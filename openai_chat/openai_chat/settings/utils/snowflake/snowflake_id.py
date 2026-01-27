from __future__ import annotations
"""
Snowflake ID 生成模块

目标：
- import 阶段零 I/O：模块加载时不触发 Redis、不分配节点、不初始化 Snowflake 实例
- 懒初始化：首次真正需要生成 ID 时，才从 Redis 获取/分配 (datacenter_id, machine_id)
- 线程安全：多线程并发下只初始化一次 Snowflake 实例；ID 生成也线程安全
- Fail-fast：初始化失败或时钟回拨等关键错误直接抛异常（禁止返回 None 造成隐性数据污染）
"""
import threading # 导入线程模块
import time # 导入时间模块
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from . import snowflake_const # Snowflake 全局常量配置

logger = get_logger("project.snowflake.register")

class Snowflake:
    """
    Snowflake 算法核心实现: 生产全局唯一 64-bit 分布式 ID
    
    ID结构(64 bit):
    - 41 bit：时间戳（毫秒，相对自定义 epoch）
    - 5  bit：datacenter_id（数据中心，0-31）
    - 5  bit：machine_id（机器编号，0-31）
    - 12 bit：sequence（序列号，同一毫秒内递增，0-4095）
    
    说明:
    - 单实例在单进程内可安全生成 ID（内部有线程锁）
    - 分布式唯一性依赖 datacenter_id + machine_id 的全局唯一分配
    """
    def __init__(self, datacenter_id: int, machine_id: int) -> None:
        # datacenter_id / machine_id 做位宽裁剪，确保落在合法范围
        self.datacenter_id = datacenter_id & snowflake_const.SNOWFLAKE_MAX_DATACENTER_ID
        self.machine_id = machine_id & snowflake_const.SNOWFLAKE_MAX_MACHINE_ID
        
        # 序列号: 同一毫秒内递增(最多4096)
        self.sequence = 0
        
        # 上一次生成 ID 的时间戳(毫秒)
        self.last_timestamp = -1
        
        # 线程锁: 保证多线程并发生成 ID 时，sequence 与 last_timestamp 的一致性
        self._lock = threading.Lock()
        
        # 自定义 epoch(毫秒), 用于缩短 timestamp 位宽
        self.epoch = snowflake_const.SNOWFLAKE_EPOCH
    
    @staticmethod
    def _timestamp_ms() -> int:
        """
        获取当前时间戳(毫秒)
        - 使用 time.time() 的秒级浮点数转换为毫秒
        """
        return int(time.time() * 1000)
    
    def _wait_next_ms(self, last_timestamp: int) -> int:
        """
        当同一毫秒内 sequence 用尽（溢出归零）时，阻塞等待下一毫秒
        :param last_timestamp: 上一次生成 ID 的毫秒时间戳
        :return: 下一毫秒时间戳
        """
        ts = self._timestamp_ms()
        while ts <= last_timestamp:
            ts = self._timestamp_ms()
        return ts
    
    def next_id(self) -> int:
        """
        生成下一个 Snowflake ID（线程安全）
        :return: 64位整数 ID
        """
        with self._lock:
            ts = self._timestamp_ms()
            
            # 1.时钟回拨检测: 当前时间戳小于上次时间戳 -> 直接失败
            if ts < self.last_timestamp:
                logger.critical(
                    f"[Snowflake] clock moved backwards: now={ts}, last={self.last_timestamp}"
                )
                raise RuntimeError("Clock moved backwards. Refusing to generate id")
            
            # 2.同一毫秒: sequence 自增；若溢出则等待下一毫秒
            if ts == self.last_timestamp:
                self.sequence = (self.sequence + 1) & snowflake_const.SNOWFLAKE_MAX_SEQUENCE
                if self.sequence == 0:
                    ts = self._wait_next_ms(self.last_timestamp)
            else:
                # 3.新的毫秒: sequence 重置为 0
                self.sequence = 0
            
            # 4.更新 last_timestamp
            self.last_timestamp = ts
            
            # 5.组装 64-bit Snowflake ID
            # 时间戳： (ts - epoch) 左移 timestamp_shift
            # datacenter：左移 datacenter_shift
            # machine：左移 machine_shift
            # sequence：低位直接 OR
            return (
                ((ts - self.epoch) << snowflake_const.SNOWFLAKE_TIMESTAMP_SHIFT)
                | (self.datacenter_id << snowflake_const.SNOWFLAKE_DATACENTER_SHIFT)
                | (self.machine_id << snowflake_const.SNOWFLAKE_MACHINE_SHIFT)
                | self.sequence
            )

# === 单例缓存 ===
_snowflake_instance: Snowflake | None = None # 进程内 Snowflake 单例
_snowflake_lock = threading.Lock() # 只保护初始化, 不保护 next_id

def get_snowflake_instance() -> Snowflake:
    """
    获取 Snowflake 单例（懒加载 + 线程安全）
    - 首次调用时触发 get_node_ids()
    """
    global _snowflake_instance
    
    # 已初始化则直接返回(无锁)
    if _snowflake_instance is not None:
        return _snowflake_instance
    
    # 慢路径: 首次初始化加锁
    with _snowflake_lock:
        # 二次检查: 防止多个线程同时通过第一次检查
        if _snowflake_instance is not None:
            return _snowflake_instance
        logger.info("[Snowflake] initializing instance...")
        
        import os, traceback
        if os.getenv("SNOWFLAKE_DEBUG_STACK", "0") == "1":
            logger.warning(
                "[Snowflake] init stack (who triggered init):\n"
                + "".join(traceback.format_stack(limit=50))
            )
        
        # 延迟导入
        # 避免 import 本模块时就导入 node_config 造成导入链膨胀
        from .node_config import get_node_ids
        
        datacenter_id, machine_id = get_node_ids()
        _snowflake_instance = Snowflake(datacenter_id, machine_id)
        
        logger.info(
            f"[Snowflake] initialized: datacenter_id={datacenter_id}, machine_id={machine_id}"
        )
        return _snowflake_instance
    
def get_snowflake_id() -> int:
    """
    对外统一入口: 获取一个全局唯一 Snowflake ID
    
    生产级行为：
    - 永远返回 int
    - 初始化失败/Redis 失败/时钟回拨等关键错误直接抛异常
    """
    return get_snowflake_instance().next_id()