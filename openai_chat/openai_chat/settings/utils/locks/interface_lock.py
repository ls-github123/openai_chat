# === interface_lock.py 锁接口定义 ===
from abc import ABC, abstractmethod # 锁接口基类
from typing import ContextManager # 上下文管理器类型提示
from openai_chat.settings.utils.logging import get_logger # 日志记录器

logger = get_logger("project.lock") 

class BaseLock(ABC):
    """
    分布式锁通用接口定义
    所有锁实现类(如 Redis单机锁、RedLock分布式锁)应当继承该类
    实现 acquire/release/lock 方法
    """
    def __enter__(self):
        acquired = self.acquire() # 尝试获取锁
        if not acquired:
            logger.error(f"[BaseLock]: 获取锁失败: {self}")
            raise RuntimeError(f"[BaseLock]: 获取锁失败: {self}")
        return self # 上下文管理器接口
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release() # 释放锁
    
    # 获取锁的唯一标识
    @abstractmethod
    def acquire(self) -> bool:
        """
        尝试获取锁
        返回 True 表示获取成功, False 表示获取失败
        """
        pass
    
    # 获取锁的超时时间
    @abstractmethod
    def release(self):
        """
        释放当前锁
        """
        pass
    
    # 上下文管理器接口
    @abstractmethod
    def lock(self) -> ContextManager[bool]:
        """
        上下文管理器封装加锁和释放流程:
        with lock.lock() as acquired:
            if acquired:
                do_something()
        """
        pass