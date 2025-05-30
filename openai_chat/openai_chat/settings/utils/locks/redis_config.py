# === Redis客户端及 Redlock初始化模块 ===
# 锁模块专属Redis实例配置,独立于Django缓存系统(CACHES)
from redis import Redis
from redlock import Redlock
from openai_chat.settings.base import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD
from openai_chat.settings.utils.logging import get_logger # 导入日志处理器模块封装

logger = get_logger("project.lock.redis_config") # 获取日志记录器

# 初始化Redis客户端(单节点)
try:
    REDIS_CLIENT = Redis(
        host=REDIS_HOST,
        port=int(REDIS_PORT),
        db=0, # 锁模块专用数据库
        password=REDIS_PASSWORD,
        decode_responses=True, # 自动字符串解码,避免字节处理
    )
    logger.info("[RedisConfig] Redis client initialized successfully.")
except Exception as e:
    logger.error(f"[RedisConfig] Failed to initialize Redis client: {e}")
    raise


# 初始化 Redlock分布式锁实例
# Redlock支持多节点部署,目前仅使用单节点Redis
try:
    REDLOCK_INSTANCE = Redlock(
        [
            { # 单节点Redis配置
                'host': REDIS_HOST,
                'port': int(REDIS_PORT),
                'db': 0, # 锁模块专用数据库
                'password': REDIS_PASSWORD,
            }
        ]
    )
    logger.info("[RedlockConfig] Redlock instance initialized successfully.")
except Exception as e:
    logger.error(f"[RedlockConfig] Failed to initialize Redlock instance: {e}")
    raise
    