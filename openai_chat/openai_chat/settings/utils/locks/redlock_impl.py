# === RedLock 分布式锁实现 封装 ===
from openai_chat.settings.utils.logging import get_logger # 导入日志处理器模块封装
from .interface_lock import BaseLock # 导入锁接口定义
from redlock import Redlock, Lock  # Redlock分布式锁库

logger = get_logger("project.redlock") # 获取Redlock日志记录器

class RedLockWrapper(BaseLock):
    """
    RedLock分布式锁实现:
    - 适用跨节点互斥、分布式锁、高一致性场景
    - 封装 redlock-py, 提供统一的上下文调用接口。
    """
    def __init__(self, redlock: Redlock, key: str, ttl: int = 10000):
        """
        初始化 RedLockWrapper 实例
        :param redlock: Redlock 实例
        :param key: 锁的唯一标识
        :param ttl: 锁的过期时间(单位:毫秒)
        """
        self.redlock = redlock
        self.key = key
        self.ttl = ttl
        self._lock: Lock | None = None # 当前锁对象
        
    def acquire(self) -> bool:
        """
        尝试获取分布式锁
        :return: True 表示获取成功, False 表示获取失败
        """
        try:
            lock_result = self.redlock.lock(self.key, self.ttl) # 尝试获取锁
            if lock_result: # 成功获取锁
                self._lock = lock_result # 保存锁对象
                logger.info(f"[RedLock] 获取锁成功: {self.key} with TTL: {self.ttl}ms") # 记录获取锁成功
                return True
            else:
                self._lock = None # 获取锁失败
                logger.warning(f"[RedLock] 获取锁失败: {self.key} after {self.ttl}ms") # 记录获取锁失败
                return False
        except Exception as e: # 捕获异常
            logger.error(f"[RedLock] 获取锁异常: {self.key}: {e}") # 记录异常信息
            return False
    
    def release(self):
        """
        释放当前锁
        """
        try:
            if self._lock:
                self.redlock.unlock(self._lock) # 释放锁
                logger.info(f"[RedLock] 释放锁成功: {self.key}") # 记录释放锁成功
        except Exception as e: 
            logger.error(f"[RedLock] 释放锁异常: {self.key}: {e}") # 记录释放锁异常信息
        finally:
            self._lock = None # 确保锁对象被清空

    def lock(self): # 上下文管理器接口实现
        """
        获取当前锁
        """
        from contextlib import contextmanager # 上下文管理器

        @contextmanager
        def _lock_context(): # 上下文管理器封装
            try:
                if self.acquire():
                    try:
                        yield True # 返回 True 表示获取锁成功
                    finally: # 确保释放锁
                        self.release()
                else:
                    yield False # 返回 False 表示获取锁失败
            except Exception as e:
                logger.error(f"[RedLock] Lock context error: {e}") # 记录上下文管理器异常信息
                yield False
        return _lock_context() # 返回上下文管理器实例
