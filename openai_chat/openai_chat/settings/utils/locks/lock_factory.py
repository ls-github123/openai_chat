# === 多策略锁 工厂函数接口 ===
from .interface_lock import BaseLock # 导入锁接口定义
from .redis_single import RedisSingleLock # 导入 Redis 单节点锁实现
from .redlock_impl import RedLockWrapper # 导入 RedLock 分布式锁实现
from .redis_config import REDIS_CLIENT, REDLOCK_INSTANCE # 导入 Redis 客户端和 RedLock 实例
from openai_chat.settings.utils.logging import get_logger # 导入日志处理器模块封装

logger = get_logger("project.lock_factory")

def build_lock(key: str, ttl: int = 10000, strategy: str = 'safe') -> BaseLock:
    """
    构建锁工厂方法:根据策略返回 RedLock 或 Redis 单节点锁实例
    :param key: 锁定资源唯一标识
    :param ttl: 锁的过期时间(单位:毫秒)
    :param strategy: 锁策略, 'safe'=RedLock分布式锁, 'fast'=Redis单节点锁
    :return: BaseLock 实例,根据策略返回不同的锁实现
    """
    logger.info(f"[build_lock] 请求创建锁: key={key}, ttl={ttl}, strategy={strategy}")
    if strategy == 'safe':
        # 返回 RedLock 分布式锁实例
        logger.debug(f"[build_lock] 使用 RedLock 分布式锁: key={key}")
        return RedLockWrapper(REDLOCK_INSTANCE, key, ttl)
    elif strategy == 'fast':
        # 返回 Redis 单节点锁实例
        logger.debug(f"[build_lock] 使用 Redis 单节点锁: key={key}")
        return RedisSingleLock(REDIS_CLIENT, key, expire=ttl // 1000)
    else:
        logger.error(f"[build_lock] 非法锁策略: {strategy}")
        raise ValueError("Invalid strategy, must be 'safe' or 'fast'")