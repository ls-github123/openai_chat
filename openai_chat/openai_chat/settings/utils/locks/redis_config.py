"""
Redis客户端与 Redlock分布式锁配置模块
- 使用统一封装的Redis连接池机制
- 专用于锁模块(Redis db=0)
注:锁模块专属Redis实例配置,独立于Django缓存系统(CACHES)
"""
from utils.redis import get_redis_client # 导入统一封装的Redis客户端获取函数
from redlock import Redlock # Redlock分布式锁库
from openai_chat.settings.base import REDIS_HOST, REDIS_PORT, REDIS_PASSWORD
from openai_chat.settings.utils.logging import get_logger # 导入日志处理器模块封装

logger = get_logger("project.redis_config") # 获取日志记录器

# 初始化Redis客户端(单节点)
try:
    REDIS_CLIENT = get_redis_client(db=0)
    logger.info("[Redis_lock_Config] Redis 客户端初始化成功(用于单节点锁).")
except Exception as e:
    logger.critical(f"[Redis_lock_Config] Redis 客户端初始化失败: {e}")
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
    logger.info("[Redlock_Config] Redlock 实例初始化成功")
except Exception as e:
    logger.critical(f"[Redlock_Config] Redlock 实例初始化失败: {e}")
    raise