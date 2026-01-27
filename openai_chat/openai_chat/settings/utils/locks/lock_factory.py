# === 多策略锁 工厂函数接口 ===
from __future__ import annotations
from openai_chat.settings.utils.logging import get_logger
from .interface_lock import BaseLock # 导入锁接口定义

logger = get_logger("project.lock_factory")

def build_lock(key: str, ttl: int = 10000, strategy: str = "safe") -> BaseLock:
    """
    构建锁工厂方法: 根据策略返回 RedLock 或 Redis 单节点锁实例
    - import 阶段零 I/O：不得在模块顶层创建 Redis client / RedLock 实例
    - 仅在真正调用 build_lock 时按需初始化依赖（懒加载）
    
    策略分离:
    - safe：Redlock（分布式，多节点未来可通过 settings.REDLOCK_SERVERS 扩展）
    - fast：Redis 单节点锁（更快，但为单点锁语义）
    
    参数:
    - key: 锁资源唯一标识
    - ttl: 锁过期时间(毫秒)
    - strategy: "safe" 或 "fast"
    """
    if not key or not isinstance(key, str):
        raise ValueError("key 必须为非空字符串")
    if not isinstance(ttl, int) or ttl <= 0:
        raise ValueError("ttl 必须为正整数(毫秒)")
    if strategy not in ("safe", "fast"):
        raise ValueError("strategy 必须为'safe' 或 'fast'")
    
    logger.info(f"[build_lock] 请求创建锁: key={key}, ttl={ttl}, strategy={strategy}")
    
    if strategy == "safe":
        logger.debug(f"[build_lock] 使用 RedLock 分布式锁: key={key}")
        
        # 延迟导入
        from .redlock_impl import RedLockWrapper
        from .redis_config import get_redlock_instance
        
        redlock = get_redlock_instance()
        return RedLockWrapper(redlock, key, ttl)
    
    # strategy == "fast"
    logger.debug(f"[build_lock] 使用 Redis 单节点锁: key={key}")
    
    # 延迟导入
    from .redis_single import RedisSingleLock
    from .redis_config import get_lock_redis_client
    
    client = get_lock_redis_client()
    
    expire_seconds = max(1, ttl // 1000)
    return RedisSingleLock(client, key, expire=expire_seconds)