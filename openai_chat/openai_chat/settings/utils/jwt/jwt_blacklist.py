"""
JWT 黑名单模块(Redis 实现)

设计目标:
- 1.负责JWT黑名单存储与查询
- 2.不负责 JWT 验签、不负责 HTTP 返回、不抛业务层 AppException
- 3.对外暴露纯技术接口（bool 返回），由上层 service/auth 决定如何映射业务语义
"""
from __future__ import annotations
import time
from typing import Optional

from openai_chat.settings.base import REDIS_DB_JWT_BLACKLIST
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client

logger = get_logger("project.jwt.blacklist")

# Redis Key 前缀
JWT_BLACKLIST_PREFIX = "jwt:blacklist:"

# 当 token 仍有极短有效期时, 至少保留1秒, 保证撤销落库语义一致
MIN_TTL_SECONDS = 1

def _redis():
    """
    获取黑名单专用 Redis 客户端
    
    说明:
    - 通过统一封装 get_redis_client 获取连接；
    - DB 使用 REDIS_DB_JWT_BLACKLIST，避免与其他模块混用
    """
    return get_redis_client(db=REDIS_DB_JWT_BLACKLIST)

def build_blacklist_key(jti: str) -> str:
    """
    生成黑名单 Redis Key
    
    参数:
    - jti: JWT ID（唯一标识）
    
    返回:
    - 形如 jwt:blacklist:<jti> 的 key
    """
    return f"{JWT_BLACKLIST_PREFIX}{jti}"

def _normalize_jti(jti: object) -> Optional[str]:
    """
    归一化并校验 jti 输入
    """
    if not isinstance(jti, str):
        return None
    
    normalize = jti.strip()
    if not normalize:
        return None
    
    return normalize

def _ttl_from_exp(exp_timestamp: int | float, now_ts: Optional[int] = None) -> int:
    """
    根据 exp(unix 时间戳-秒)计算黑名单 TTL (秒)
    
    参数:
    - ttl = exp - now
    - ttl <= 0：表示 token 已过期
    - ttl > 0：至少返回 1 秒
    """
    now = int(now_ts if now_ts is not None else time.time())
    ttl = int(exp_timestamp) - now
    return max(ttl, 0) # 过期的 token 也加入黑名单, 但 TTL 设置为 0, 表示立即过期

def is_blacklisted(jti: str) -> bool:
    """
    查询 token 是否在黑名单中
    
    返回:
    - True: 在黑名单, 或查询异常(fail-closed)
    - False: 不在黑名单中
    
    fail-closed说明:
    - 任何查询异常都视为 token 在黑名单中, 保证安全性
    """
    normalized_jti = _normalize_jti(jti)
    if not normalized_jti:
        # 输入无效的 jti 视为黑名单, 保证安全性
        logger.warning("[JWT Blacklist] invalid jti input in is_blacklisted: %r", jti)
        return True
    
    key = build_blacklist_key(normalized_jti)
    try:
        value = _redis().get(key)
        return value is not None
    except Exception as exc:
        # fail-closed: 依赖故障时默认拒绝放行
        logger.error(
            "[JWT Blacklist] check failed (fail-closed). jti=%s key=%s err=%s",
            normalized_jti,
            key,
            exc,
        )
        return True

def add_to_blacklist(jti: str, exp_timestamp: int | float) -> bool:
    """
    讲 token (jti) 假如黑名单, TTL 跟随 token 剩余有效期
    
    参数:
    - jti: token 唯一标识
    - exp_timestamp: token 的 exp(Unix 时间戳，秒)
    
    返回：
    - True: 写入成功 / 已存在 / token 已过期(视为无需再撤销)
    - False: 输入非法或 Redis 写入异常
    
    幂等性：
    - 使用 SET key value EX ttl NX (原子)
    - 若 key 已存在，说明之前已撤销，直接返回 True
    """
    normalized_jti = _normalize_jti(jti)
    if not normalized_jti:
        logger.warning("[JWT Blacklist] add failed: invalid jti=%r", jti)
        return False
    
    if not isinstance(exp_timestamp, (int, float)):
        logger.error(
            "[JWT Blacklist] add failed: invalid exp type. jti=%s exp=%r",
            normalized_jti,
            exp_timestamp,
        )
        return False
    
    ttl = _ttl_from_exp(exp_timestamp)
    
    # token 已过期: 从业务语义看无需撤销, 按成功处理
    if ttl <= 0:
        logger.info(
            "[JWT Blacklist] skip add because token already expired. jti=%s exp=%s",
            normalized_jti,
            int(exp_timestamp),
        )
        return True
    
    ttl = max(ttl, MIN_TTL_SECONDS)
    key = build_blacklist_key(normalized_jti)
    
    try:
        # SET key value EX ttl NX:
        # - NX：仅当 key 不存在时写入（幂等）
        # - EX：自动过期，生命周期与 token 对齐
        result = _redis().set(name=key, value="1", ex=ttl, nx=True)
        
        if result:
            logger.info(
                "[JWT Blacklist] added. jti=%s key=%s ttl=%ss",
                normalized_jti,
                key,
                ttl,
            )
            return True
        
        # result=False 代表 key 已存在, 按幂等成功处理
        logger.debug(
            "[JWT Blacklist] already exists (idempotent success). jti=%s key=%s",
            normalized_jti,
            key,
        )
        return True
    
    except Exception as exc:
        logger.error(
            "[JWT Blacklist] add failed. jti=%s key=%s ttl=%s err=%s",
            normalized_jti,
            key,
            ttl,
            exc,
        )
        return False