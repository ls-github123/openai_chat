# === RedLock 分布式锁实现 封装 ===
from openai_chat.settings.utils.logging import get_logger # 导入日志处理器模块封装
from contextlib import contextmanager # 上下文管理器装饰器
from .interface_lock import BaseLock # 导入锁接口定义
from redlock import Redlock, Lock  # Redlock分布式锁库
from typing import Optional # Optional类型提示

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
        self._lock: Optional[Lock] = None # 当前锁对象, 初始为None
        
    def acquire(self) -> bool:
        """
        尝试获取分布式锁
        :return: True 表示获取成功, False 表示获取失败
        """
        lock_result = self.redlock.lock(self.key, self.ttl) # 尝试获取锁
        self._lock = lock_result or None # 将锁对象赋值给 _lock
        acquired = self._lock is not None # 检查锁是否成功获取
        logger.debug(f"[RedLockWrapper] acquire key={self.key}, success={acquired}")
        return acquired # 返回获取锁的结果
    
    def release(self):
        """
        释放当前锁
        """
        if self._lock:
            try:
                self.redlock.unlock(self._lock) # 释放锁
                logger.debug(f"[RedLockWrapper] release key={self.key}")
            except Exception as e:
                logger.warning(f"[RedLockWrapper] release failed: {e}")
            finally:
                self._lock = None # 确保释放后锁对象置为 None，避免重复释放
    
    @contextmanager
    def lock(self): # 上下文管理器接口实现
        """
        获取当前锁
        """
        acquired = self.acquire() # 尝试获取锁
        try:
            yield acquired # 返回获取锁的结果
        finally:
            if acquired:
                self.release() # 确保释放锁
    
    def __enter__(self):
        if not self.acquire():
            raise RuntimeError(f"[RedLockWrapper] Failed to acquire lock: {self.key}")
        return self # 上下文管理器进入时返回 self，表示锁已获取
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()