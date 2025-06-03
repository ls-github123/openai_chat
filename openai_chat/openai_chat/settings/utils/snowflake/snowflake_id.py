import threading # 导入线程模块
import time # 导入时间模块
from .node_config import get_node_ids # 导入获取节点ID函数
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from . import snowflake_const # Snowflake 全局常量配置

logger = get_logger("project.snowflake.register")

_snowflake_instance = None # 全局缓存 Snowflake 实例
_snowflake_lock = threading.Lock() # 多线程并发互斥锁,确保只初始化一次

class Snowflake:
    """
    雪花算法核心实现类:用于生成全局唯一分布式ID
    ID结构(64位):
    - 41位时间戳(毫秒级, 相对于自定义epoch)
    - 5位数据中心ID(最多32个)
    - 5位机器ID(最多32个)
    - 12位序列号(每毫秒最多生成4096个ID)
    """
    def __init__(self, datacenter_id: int, machine_id: int):
        self.datacenter_id = datacenter_id & snowflake_const.SNOWFLAKE_MAX_DATACENTER_ID # 数据中心ID限制为5位(0-31)
        self.machine_id = machine_id & snowflake_const.SNOWFLAKE_MAX_MACHINE_ID # 机器ID限制为5位(0-31)
        self.sequence = 0 # 序列号初始化为0
        self.last_timestamp = -1 # 上次生成ID的时间戳初始化为-1
        self.lock = threading.Lock() # 线程锁,确保多线程下的线程安全
        self.epoch = snowflake_const.SNOWFLAKE_EPOCH # 自定义起始时间戳(2024-01-01 00:00:00)
        
    def _timestamp(self):
        """返回当前时间戳(单位:毫秒)"""
        return int(time.time() * 1000)
    
    def _wait_next_ms(self, last_timestamp: int) -> int:
        """
        等待直到下一个毫秒,避免序列号溢出
        :param last_timestamp: 上次生成ID的时间戳
        :return: 下一个毫秒的时间戳
        """
        ts = self._timestamp() # 获取当前时间戳
        while ts <= last_timestamp: # 如果当前时间戳小于等于上次生成的时间戳
            ts = self._timestamp() # 继续等待
        return ts
    
    def get_id(self):
        """
        生成下一个全局唯一ID(雪花ID),线程安全
        :return: 64位整数ID
        """
        with self.lock: # 获取线程锁,确保线程安全
            ts = self._timestamp() # 获取当前时间戳
            if ts < self.last_timestamp:
                # 如果当前时间戳小于上次生成的时间戳, 则抛出异常
                logger.critical(f"[雪花ID异常] 系统时钟回拨: now={ts}, last={self.last_timestamp}")
                raise Exception("Clock moved backwards. Refusing to generate id")
            
            # 如果当前时间戳等于上次生成的时间戳
            if ts == self.last_timestamp:
                # 序列号加1,如果超过4095则等待下一毫秒
                self.sequence = (self.sequence + 1) & snowflake_const.SNOWFLAKE_MAX_SEQUENCE # 序列号限制为12位(0-4095)
                if self.sequence == 0: # 序列号溢出,等待下一毫秒
                    ts = self._wait_next_ms(self.last_timestamp) # 等待下一毫秒
            else:
                self.sequence = 0 # 如果时间戳变化,则重置序列号为0
            self.last_timestamp = ts # 更新上次生成ID的时间戳
            # 组合返回全局唯一ID(雪花ID): 时间戳 | 数据中心ID | 机器ID | 序列号
            snowflake_id = (
                # 时间戳部分(41位)
                ((ts - self.epoch) << snowflake_const.SNOWFLAKE_TIMESTAMP_SHIFT)
                # 数据中心ID部分(5位)
                | (self.datacenter_id << snowflake_const.SNOWFLAKE_DATACENTER_SHIFT)
                # 机器ID部分(5位)
                | (self.machine_id << snowflake_const.SNOWFLAKE_MACHINE_SHIFT)
                # 序列号部分(12位)
                | self.sequence
            )
            return snowflake_id # 返回生成的64位整型ID

# === 单例工厂函数,用于全局调用 ===
def get_snowflake_id():
    """
    获取全局唯一雪花ID(延迟初始化单例)
    :return: 64位整型ID
    """
    global _snowflake_instance
    try:
        if _snowflake_instance is None:
            # 获取数据中心ID和机器ID
            datacenter_id, machine_id = get_node_ids() # 调用配置函数获取节点ID
            _snowflake_instance = Snowflake(datacenter_id, machine_id) # 创建雪花ID实例
        return _snowflake_instance.get_id() # 返回生成的全局唯一ID
    except Exception as e:
        logger.error(f"[get_snowflake_id] 获取雪花ID失败: {e}")
        return None # 如果发生异常,返回None

def get_snowflake_instance() -> Snowflake:
    """
    返回已初始化的 Snowflake 实例
    若尚未初始化则从 Redis 获取节点编号并初始化
    注: 用于非生成ID场景(如 守护线程、状态监控等)
    :return: Snowflake 实例
    """
    global _snowflake_instance # 全局唯一雪花ID实例
    if _snowflake_instance is None:
        with _snowflake_lock: # 确保线程安全
            if _snowflake_instance is None: # 再次检查是否已初始化
                logger.info("[get_snowflake_instance] 开始初始化 Snowflake 实例")
                try:
                    datacenter_id, machine_id = get_node_ids() # 获取数据中心ID和机器ID
                    _snowflake_instance = Snowflake(datacenter_id, machine_id) # 创建雪花ID实例
                    logger.info(
                        f"[get_snowflake_instance] 初始化成功: datacenter_id={datacenter_id}, machine_id={machine_id}"
                    )
                except Exception as e:
                    logger.error(f"[get_snowflake_instance] 初始化失败: {e}")
                    raise
    return _snowflake_instance # 返回已初始化的 Snowflake 实例