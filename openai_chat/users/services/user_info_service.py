"""
用户信息服务类

- 根据 user_id 获取用户基础信息快照
- 优先读取 Redis 缓存
- 缓存未命中时回源 MySQL
- 回源成功后写入 Redis 正向缓存
- 用户不存在 / 被禁用 / 已删除时写入短 TTL 负缓存，降低缓存穿透风险
"""
from __future__ import annotations
import json, random
from typing import Any, Dict, Optional, cast
from django.contrib.auth import get_user_model
from redis import Redis

from openai_chat.settings.base import REDIS_DB_USERS_INFO_CACHE
from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client

logger = get_logger("users")
User = get_user_model()

class UserInfoService:
    """
    用户信息获取服务类

    设计原则:
    - 对外只返回前端需要的安全字段，不返回 password / totp_secret 等敏感字段
    - 所有 ID 字段转为 str，避免前端 JavaScript 大整数精度丢失
    - 缓存损坏时删除缓存并回源 DB
    - DB / Redis 写缓存异常要区分处理:
      - Redis 读写失败: 降级，不阻断用户信息查询
      - DB 查询失败: 属于系统错误，上抛 AppException
    """

    CACHE_PREFIX: str = "user:info"
    CACHE_TTL_SECONDS: int = 3600
    CACHE_TTL_JITTER_SECONDS: int = 300
    NEGATIVE_TTL_SECONDS: int = 60
    MAX_USER_ID_LEN: int = 64

    # 缓存中允许出现的字段，和 UserInfoResponseSerializer 保持一致。
    ALLOWED_FIELDS = {
        "id",
        "email",
        "username",
        "is_active",
        "totp_enabled",
        "organization",
    }
    
    REQUIRED_FIELDS = {
        "id",
        "email",
        "is_active",
        "totp_enabled",  
    }

    @classmethod
    def _redis(cls) -> Optional[Redis]:
        """
        获取用户信息缓存 Redis 客户端

        注意:
        - Redis 是加速层，不是事实源
        - 获取 Redis 客户端失败时返回 None，后续直接回源 DB
        """
        try:
            return cast(Redis, get_redis_client(db=REDIS_DB_USERS_INFO_CACHE))
        except Exception as exc:
            logger.error("[UserInfoService] get redis client failed err=%s", exc)
            return None

    @classmethod
    def _build_cache_key(cls, user_id: str) -> str:
        """生成用户信息缓存 key"""
        return f"{cls.CACHE_PREFIX}:{user_id}"

    @classmethod
    def _normalize_user_id(cls, user_id: Any) -> Optional[str]:
        """
        归一化 user_id

        关键防御:
        - 只接受正整数形式的用户 ID
        - 拒绝空值、超长值、非数字值
        - 防止异常 payload 污染日志或 Redis key
        """
        if user_id is None:
            return None

        uid = str(user_id).strip()
        if not uid or len(uid) > cls.MAX_USER_ID_LEN:
            return None

        if not uid.isdigit():
            return None

        if int(uid) <= 0:
            return None

        return uid

    @staticmethod
    def _safe_json_loads(raw: Any) -> Optional[Dict[str, Any]]:
        """
        安全解析 Redis 原始数据

        Redis 返回值通常是 bytes，也可能是 str
        解析失败返回 None，由调用方删除脏缓存并回源 DB
        """
        if raw is None:
            return None

        try:
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8")

            data = json.loads(str(raw))
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    @classmethod
    def _is_valid_cached_user_info(cls, data: Dict[str, Any]) -> bool:
        """
        校验缓存结构是否可信

        说明:
        - {} 是负缓存，表示用户不存在或当前不可用，允许直接返回
        - 正向缓存必须包含基础字段
        - 不允许缓存中混入 password / totp_secret 等非白名单字段
        """
        if data == {}:
            return True

        if not set(data.keys()).issubset(cls.ALLOWED_FIELDS):
            return False

        if not cls.REQUIRED_FIELDS.issubset(data.keys()):
            return False

        if not str(data.get("id", "")).strip().isdigit():
            return False

        return True

    @classmethod
    def _get_from_cache(
        cls,
        redis_client: Optional[Redis],
        cache_key: str,
    ) -> Optional[Dict[str, Any]]:
        """
        从 Redis 读取用户信息缓存

        返回:
        - dict: 缓存命中，包括 {} 负缓存
        - None: 缓存未命中、Redis异常、缓存损坏

        Redis 不可用时:
        - 直接返回 None
        - 调用方继续回源 DB
        """
        if redis_client is None:
            return None

        try:
            cached_raw = redis_client.get(cache_key)
        except Exception as exc:
            logger.error("[UserInfoService] redis get failed key=%s err=%s", cache_key, exc)
            return None

        if cached_raw is None:
            return None

        data = cls._safe_json_loads(cached_raw)
        if data is not None and cls._is_valid_cached_user_info(data):
            return data

        # 缓存内容无法解析或字段不可信时，删除后回源。
        logger.warning("[UserInfoService] cache corrupted, delete and fallback key=%s", cache_key)
        try:
            redis_client.delete(cache_key)
        except Exception as exc:
            logger.warning("[UserInfoService] delete corrupted cache failed key=%s err=%s", cache_key, exc)

        return None

    @classmethod
    def _set_to_cache(
        cls,
        redis_client: Optional[Redis],
        cache_key: str,
        user_info: Dict[str, Any],
    ) -> None:
        """
        写入正向缓存

        TTL 加随机抖动:
        - 避免大量用户缓存同一时间过期
        - 降低缓存雪崩概率
        """
        if redis_client is None:
            return

        try:
            ttl = cls.CACHE_TTL_SECONDS + random.randint(0, cls.CACHE_TTL_JITTER_SECONDS)
            redis_client.setex(
                cache_key,
                ttl,
                json.dumps(user_info, ensure_ascii=False),
            )
        except Exception as exc:
            logger.error("[UserInfoService] redis setex failed key=%s err=%s", cache_key, exc)

    @classmethod
    def _set_negative_cache(
        cls,
        redis_client: Optional[Redis],
        cache_key: str,
    ) -> None:
        """
        写入负缓存

        使用 {} 表示:
        - 用户不存在
        - 用户已禁用
        - 用户已逻辑删除

        负缓存 TTL 必须较短，避免用户状态恢复后长时间不可见。
        """
        if redis_client is None:
            return

        try:
            redis_client.setex(
                cache_key,
                cls.NEGATIVE_TTL_SECONDS,
                json.dumps({}, ensure_ascii=False),
            )
        except Exception as exc:
            logger.error("[UserInfoService] redis negative setex failed key=%s err=%s", cache_key, exc)

    @classmethod
    def _serialize_user(cls, user: Any) -> Dict[str, Any]:
        """
        将 User ORM 对象序列化为对外用户信息快照

        注意:
        - 不返回 password
        - 不返回 totp_secret
        - 不返回 is_staff / is_superuser，权限信息应由 JWT scope 或权限接口表达
        """
        organization = getattr(user, "organization", None)

        return {
            "id": str(user.id),
            "email": str(getattr(user, "email", "") or ""),
            "username": str(getattr(user, "username", "") or ""),
            "is_active": bool(getattr(user, "is_active", True)),
            "totp_enabled": bool(getattr(user, "totp_enabled", False)),
            "organization": str(organization) if organization is not None else None,
        }

    @classmethod
    def _query_user_from_db(cls, uid: str, *, enforce_db_filters: bool) -> Any:
        """
        从数据库查询用户

        enforce_db_filters=True:
        - 只返回 is_active=True 且 is_deleted=False 的用户
        - 面向前端 userinfo / 登录成功 user 快照等普通场景

        enforce_db_filters=False:
        - 仅按 id 查询
        - 预留给后台审计、管理端等需要查看禁用/删除用户快照的场景
        """
        queryset = User.objects.only(
            "id",
            "email",
            "username",
            "is_active",
            "is_deleted",
            "totp_enabled",
            "organization",
        ).filter(id=int(uid))

        if enforce_db_filters:
            queryset = queryset.filter(is_active=True, is_deleted=False)

        return queryset.first()

    @classmethod
    def get_user_info(cls, user_id: Any, *, enforce_db_filters: bool = True) -> Dict[str, Any]:
        """
        获取用户信息

        返回:
        - 用户存在且可用: 用户信息 dict
        - 用户不存在 / 被禁用 / 已删除: {}
        - DB 异常: 抛 AppException.internal_error

        缓存策略:
        - enforce_db_filters=True 时读写普通用户信息缓存
        - enforce_db_filters=False 时不读写普通缓存，避免后台查询污染前端缓存语义
        """
        uid = cls._normalize_user_id(user_id)
        if not uid:
            logger.warning("[UserInfoService] invalid user_id=%r", user_id)
            return {}

        cache_key = cls._build_cache_key(uid)
        redis_client = cls._redis() if enforce_db_filters else None

        if enforce_db_filters:
            cached = cls._get_from_cache(redis_client, cache_key)
            if cached is not None:
                logger.debug("[UserInfoService] cache hit key=%s", cache_key)
                return cached

        try:
            user = cls._query_user_from_db(uid, enforce_db_filters=enforce_db_filters)
        except Exception as exc:
            logger.error("[UserInfoService] db query failed user_id=%s err=%r", uid, exc)
            raise AppException.internal_error(
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="用户信息查询失败, 请稍后重试",
            ) from exc

        if not user:
            logger.info("[UserInfoService] user missing or unavailable user_id=%s", uid)
            if enforce_db_filters:
                cls._set_negative_cache(redis_client, cache_key)
            return {}

        user_info = cls._serialize_user(user)

        if enforce_db_filters:
            cls._set_to_cache(redis_client, cache_key, user_info)
            logger.debug("[UserInfoService] cache refreshed user_id=%s", uid)

        return user_info

    @classmethod
    def invalidate_cache(cls, user_id: Any) -> None:
        """
        删除指定用户信息缓存

        调用时机:
        - 用户资料更新后
        - TOTP 开启/解绑后
        - 用户禁用/恢复/逻辑删除后

        Redis 删除失败不阻断主流程，但必须记录日志
        """
        uid = cls._normalize_user_id(user_id)
        if not uid:
            logger.warning("[UserInfoService] skip invalidate invalid user_id=%r", user_id)
            return

        redis_client = cls._redis()
        if redis_client is None:
            return

        cache_key = cls._build_cache_key(uid)

        try:
            redis_client.delete(cache_key)
        except Exception as exc:
            logger.error("[UserInfoService] cache invalidate failed key=%s err=%s", cache_key, exc)

    @classmethod
    def refresh_cache(cls, user_id: Any) -> Dict[str, Any]:
        """
        强制刷新用户信息缓存

        流程:
        1. 删除旧缓存
        2. 回源数据库
        3. 写入新缓存
        4. 返回最新用户信息
        """
        cls.invalidate_cache(user_id)
        return cls.get_user_info(user_id, enforce_db_filters=True)


__all__ = ["UserInfoService"]