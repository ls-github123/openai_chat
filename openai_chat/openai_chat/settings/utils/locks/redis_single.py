# === Redis 单实例锁实现 封装 ===
import uuid
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
        self.key = key # 锁的唯一标识
        self.expire = expire # 锁的过期时间
        self.token = str(uuid.uuid4()) # 生成唯一的锁令牌
    
    def acquire(self) -> bool:
        """
        获取锁
        尝试获取锁, 成功返回 True, 失败返回 False
        """
        try:
            # 使用 SET NX EX 命令尝试获取锁
            # NX: 仅在键不存在时设置键值
            # EX: 设置键的过期时间
            # 注意: 该实现不支持锁重入, 每次获取锁都会生成新的令牌
            result = self.redis.set(self.key, self.token, nx=True, ex=self.expire)
            if result:
                logger.debug(f"[RedisLock] Acquired lock: {self.key}")
            return result is True # 返回 True 表示获取成功, False 表示获取失败
        except Exception as e:
            logger.error(f"[RedisLock] Exception acquiring {self.key}: {e}")
            return False
    
    def release(self):
        """
        释放锁
        仅当前锁令牌匹配时才释放锁
        如果令牌不匹配, 则不执行任何操作
        """
        try:
            # 使用 Lua 脚本确保原子性操作
            script = """
            if redis.call('get', KEYS[1]) == ARGV[1] then
                return redis.call('del', KEYS[1])
            else
                return 0
            end
            """
            # KEYS[1] 是锁的键, ARGV[1] 是锁的令牌
            self.redis.eval(script, 1, self.key, self.token) # 执行 Lua 脚本确保原子性
            logger.debug(f"[RedisLock] Released lock: {self.key}")
        except Exception as e:
            logger.error(f"[RedisLock] Exception releasing {self.key}: {e}")
    
    def lock(self):
        from contextlib import contextmanager
        
        @contextmanager
        def _lock():
            # 尝试获取锁
            try:
                if self.acquire():
                    try:
                        yield True # 成功获取锁，返回True
                    finally:
                        self.release() # 确保释放锁
                else:
                    yield False # 获取锁失败，返回False
            except Exception as e:
                logger.error(f"[RedisLock] Lock context error: {e}")
                yield False
        return _lock() # 返回上下文管理器实例