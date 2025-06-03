# === Redis 单实例锁实现 封装 ===
import uuid # 导入UUID生成器
from contextlib import contextmanager # 上下文管理器装饰器
from openai_chat.settings.utils.logging import get_logger # 导入日志处理器模块封装
from .interface_lock import BaseLock # 导入锁接口定义
from redis import Redis # Redis客户端

logger = get_logger("project.redis_lock")

class RedisSingleLock(BaseLock):
    """
    Redis 单实例锁, 适用本地高性能互斥、异步任务场景
    采用 SET NX EX 实现, 加锁快但无容灾能力
    """
    def __init__(self, redis: Redis, key: str, expire: int = 10):
        """
        初始化 RedisSingleLock 实例
        :param redis: Redis 客户端实例
        :param key: 锁的唯一标识
        :param expire: 锁的过期时间(单位:秒)
        """
        self.redis = redis # Redis客户端实例
        self.key = key
        self.expire = expire
        self._acquired = False # 锁获取状态标识
        self._token = str(uuid.uuid4()) # 初始化唯一标识符
    
    def acquire(self) -> bool:
        """
        获取锁(使用NX,并设置EX过期时间)
        尝试获取锁, 成功返回 True, 失败返回 False
        """
        result = self.redis.set(self.key, "1", nx=True, ex=self.expire) # 尝试设置锁
        self._acquired = bool(result) # 设置获取状态
        logger.debug(f"[RedisSingleLock] acquire key={self.key}, success={self._acquired}")
        return self._acquired # 返回获取锁的结果
    
    def release(self):
        """
        释放锁
        通过 Lua 脚本确保只删除自己设置的锁
        """
        if self._acquired:
            try:
                # 使用 Lua 脚本原子性删除锁
                release_script = """
                if redis.call("get", KEYS[1]) == ARGV[1] then
                    return redis.call("del", KEYS[1])
                else
                    return 0
                end
                """
                self.redis.eval(release_script, 1, self.key, self._token) # 删除锁
                logger.debug(f"[RedisSingleLock] release key={self.key}")
            except Exception as e:
                logger.warning(f"[RedisSingleLock] release failed: {e}")
            finally:
                self._acquired = False # 确保释放后状态置为 False，避免重复释放
                
    @contextmanager
    def lock(self):
        """
        上下文管理器接口实现
        获取当前锁, 成功返回True, 失败返回False
        """
        acquired = self.acquire() # 尝试获取锁
        try:
            yield acquired # 返回获取锁的结果
        finally:
            if acquired: # 如果获取成功则释放锁
                self.release() # 确保释放锁
        
    def __enter__(self):
        if not self.acquire():
            raise RuntimeError(f"[RedisSingleLock] Failed to acquire lock: {self.key}")
        return self # 上下文管理器进入时返回 self，符合基类接口
        
    def __exit__(self, exc_type, exc_value, exc_tb):
        self.release() # 确保退出时释放锁