import threading # 导入线程模块
import time # 导入时间模块
from openai_chat.settings.utils.redis import get_redis_client # 导入Redis客户端模块
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from .snowflake_id import get_snowflake_instance # 导入获取snowflake实例函数接口
from . import snowflake_const # 导入 Snowflake 全局常量配置
from .redis_register import RedisNodeRegister # 导入 Redis 注册器

logger = get_logger("project.snowflake.guard")

_guard_instance = None # 全局单例守护进程实例,避免重复启动

class SnowflakeGuard:
    """
    snowflake 节点注册守护进程:
    - 定期刷新 Redis 注册键TTL, 确保节点注册有效
    - 避免节点ID被重复抢占
    """
    def __init__(self, redis_instance, datacenter_id: int, machine_id: int):
        self.redis = redis_instance # Redis连接实例
        self.datacenter_id = datacenter_id # 数据中心ID
        self.machine_id = machine_id # 机器ID
        self.running = False # 守护进程状态运行标志
        self.key = f"{snowflake_const.SNOWFLAKE_NODE_KEY_PREFIX}:{datacenter_id}:{machine_id}" # 注册键
        self.interval = snowflake_const.SNOWFLAKE_RENEW_INTERVAL_SECONDS # 刷新间隔(单位:秒)
        self.ttl = snowflake_const.SNOWFLAKE_REGISTER_TTL_SECONDS # 注册键有效期(单位:秒)
        self.thread = threading.Thread(target=self._guard_loop, daemon=True) # 守护线程
        
    def start(self):
        """
        启动守护线程
        """
        if not self.running: # 如果守护进程未运行
            self.running = True # 设置运行标志为True
            self.thread.start() # 启动守护线程
            logger.info(f"[SnowflakeGuard] 启动守护线程: {self.key}")
            
    def stop(self):
        """
        停止守护线程
        """
        self.running = False # 设置运行标志为False
        logger.info(f"[SnowflakeGuard] 停止守护线程: {self.key}")
        
    def _guard_loop(self):
        """
        守护线程主循环
        """
        while self.running: # 当守护进程运行时
            try:
                if self.redis.expire(self.key, self.ttl): # 尝试刷新注册键的ttl
                    logger.debug(f"[SnowflakeGuard] TTL刷新成功: {self.key}")
                else:
                    logger.warning(f"[SnowflakeGuard] TTL刷新失败, 键: {self.key}不存在")
                    RedisNodeRegister(self.redis).register() # 如果注册键不存在,尝试重新注册
            except Exception as e:
                logger.error(f"[SnowflakeGuard] Redis异常: {e}")
            time.sleep(self.interval) # 等待指定间隔后继续循环

def ensure_snowflake_guard():
    """
    启动前修复机制: 
    如果注册键丢失但绑定键存在, 自动补注册占为键
    """
    try:
        redis_instance = get_redis_client(db=snowflake_const.SNOWFLAKE_REDIS_DB)
        snowflake = get_snowflake_instance() # # 获取 Snowflake 实例
        datacenter_id = snowflake.datacenter_id
        machine_id = snowflake.machine_id
        reg_key = f"{snowflake_const.SNOWFLAKE_NODE_KEY_PREFIX}:{datacenter_id}:{machine_id}"
        if not redis_instance.exists(reg_key): # 检查注册键是否存在
            redis_instance.set(reg_key, "1", ex=snowflake_const.SNOWFLAKE_REGISTER_TTL_SECONDS) # 如果不存在, 创建注册键
            logger.warning(f"[SnowflakeRepair] 注册占位键丢失, 自动补注册:{reg_key}")
        else:
            logger.debug(f"[SnowflakeRepair] 注册占位键已存在: {reg_key}")
    except Exception as e:
        logger.error(f"[SnowflakeRepair] 修复注册键失败: {e}")
            
def start_snowflake_guard():
    """
    启动后台线程, 负责定期续约 Snowflake 节点注册
    若注册键失效, 则尝试自动注册并刷新
    """
    global _guard_instance # 使用全局单例守护进程实例
    if _guard_instance: # 如果进程守护已存在
        logger.info("[SnowflakeGuard] 守护进程已存在, 跳过启动")
    
    ensure_snowflake_guard() # 确保注册键存在,如果不存在则自动补注册
    try:
        redis_instance = get_redis_client(db=snowflake_const.SNOWFLAKE_REDIS_DB) # 获取Redis客户端实例
        snowflake = get_snowflake_instance() # 获取 Snowflake 实例
        _guard_instance = SnowflakeGuard(redis_instance, snowflake.datacenter_id, snowflake.machine_id)
        _guard_instance.start() # 启动守护进程
        logger.info(f"[SnowflakeGuard] 启动守护进程: {_guard_instance.key}")
    except Exception as e:
        logger.error(f"[SnowflakeGuard] 启动守护进程异常: {e}")
        raise RuntimeError(f"无法启动 Snowflake 节点守护进程: {e}")