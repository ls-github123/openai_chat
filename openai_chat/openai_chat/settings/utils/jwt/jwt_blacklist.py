# JWT 黑名单模块: 检查/加入黑名单, 基于Redis缓存机制
import time
from openai_chat.settings.utils.locks import build_lock # redlock分布式锁封装
from openai_chat.settings.utils.redis import get_redis_client
from openai_chat.settings.base import REDIS_DB_JWT_BLACKLIST # JWT黑名单模块Redis存储占用库
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("project.jwt")

# Redis key 前缀
BLACKLIST_PREFIX = "jwt:blacklist"

def get_blacklist_key(jti: str) -> str:
    """
    构建Redis中用于存储黑名单Token的key
    :param jti: JWT ID
    :return: Redis key
    """
    return f"{BLACKLIST_PREFIX}{jti}"

def is_blacklisted(jti: str) -> bool:
    """
    检查Token是否已被加入黑名单
    :param jti: Token的唯一标识(jti)
    :return: 是否在黑名单中
    """
    try:
        redis = get_redis_client(db=REDIS_DB_JWT_BLACKLIST)
        result = redis.get(get_blacklist_key(jti))
        return result is not None
    except Exception as e:
        logger.error(f"[JWT黑名单]检查异常 jti={jti}, error={str(e)}")
        return False
    
def add_to_blacklist(jti: str, exp_timestamp: int) -> bool:
    """
    添加 JWT Token 至 Redis 黑名单, 设置过期时间为exp对应的时间戳
    :param jti: JWT 唯一标识符
    :param exp_timestamp: Token过期时间戳(秒)
    :return: 是否成功加入黑名单
    """
    try:
        if not isinstance(exp_timestamp, (int, float)) or exp_timestamp <= 0:
            logger.error(f"[黑名单写入失败] 非法的 exp 时间戳: jti={jti}, exp={exp_timestamp}")
            return False
        
        ttl = max(int(exp_timestamp - time.time()), 1) # 剩余有效期(秒)
        if ttl <= 0:
            logger.warning(f"[黑名单跳过] token已过期, jti={jti}, ttl={ttl}")
            return False
        
        redis = get_redis_client(db=REDIS_DB_JWT_BLACKLIST)
        lock_key = f"lock:jwt:blacklist:{jti}"
        lock = build_lock(lock_key, ttl=3000, strategy='safe') # Redlock分布式锁
        
        with lock:
            redis_key = get_blacklist_key(jti)
            if redis.get(redis_key):
                logger.debug(f"[黑名单已存在] jti={jti}")
                return True
            
            redis.set(name=redis_key, value="1", ex=ttl, nx=True) # nx=True 保障幂等性
            logger.info(f"[黑名单写入成功] jti={jti}, ttl={ttl}s")
            return True
        
    except Exception as e:
        logger.error(f"[黑名单写入失败 jti={jti}, error={str(e)}]")
        return False