"""
Redis 客户端连接池模块封装
- 支持多数据库分离
- 提供连接池复用机制
- 默认返回 db=0 连接池实例
- 高性能连接池管理, 避免重复创建
"""

from redis import Redis, ConnectionPool # 导入Redis和连接池类
from openai_chat.settings.base import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD # 导入Redis配置
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器

logger = get_logger("project.redis_config")

# === Redis连接池缓存 ===
# 不同db使用不同连接池,按需初始化
_REDIS_POOLS: dict[int, ConnectionPool] = {} # 存储连接池实例的字典

def get_redis_pool(db: int = 0) -> ConnectionPool:
    """
    获取指定 Redis 数据库连接池实例(支持连接池复用)
    :param db: Redis数据库编号(0-15/默认0)
    :return: Redis ConnectionPool 实例
    """
    if db not in _REDIS_POOLS: # 如果连接池不存在
        try:
            _REDIS_POOLS[db] = ConnectionPool(
                host=REDIS_HOST,
                port=int(REDIS_PORT),
                password=REDIS_PASSWORD,
                db=db,
                decode_responses=True, # 自动解码字符串
                max_connections=50, # 最大连接数
                socket_connect_timeout=5, # 连接超时时间
            )
            logger.info(f"[redis_client] Redis连接池初始化成功(db={db})")
        except Exception as e:
            logger.critical(f"[redis_client] Redis连接池初始化失败(db={db}): {e}")
            raise
    return _REDIS_POOLS[db] # 返回连接池实例

def get_redis_client(db: int = 0) -> Redis:
    """
    获取 Redis 客户端实例(使用对应连接池)
    :param db: Redis数据库编号(0-15/默认0)
    :return: Redis 客户端实例
    """
    try:
        pool = get_redis_pool(db) # 获取连接池
        client = Redis(connection_pool=pool) # 创建Redis客户端
        client.ping() # 测试连接可用性
        logger.debug(f"[redis_client] Redis客户端连接成功(db={db})")
        return client
    except Exception as e:
        logger.critical(f"[redis_client] Redis客户端连接失败(db={db}): {e}")
        raise # 连接失败抛出异常
    
# 默认 Redis 客户端实例(db=0)
REDIS_POOL = get_redis_pool(db=0) # 默认连接池实例
REDIS_CLIENT = get_redis_client(db=0) # 默认Redis客户端实例