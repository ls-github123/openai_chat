# 用户信息服务类
from __future__ import annotations # 延迟类型注解解析
import json, random
from typing import Any, Dict, Optional
from django.contrib.auth import get_user_model # 获取用户模型
from openai_chat.settings.utils.redis import get_redis_client
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.base import REDIS_DB_USERS_INFO_CACHE # 用户信息缓存占用库

logger = get_logger("users")
User = get_user_model() # 获取用户模型

class UserInfoService:
    """
    用户信息获取服务类
    - 优先从Redis缓存中获取用户信息
    - 缓存未命中 / 损坏 -> 查询数据库并更新缓存
    - 返回所有 ID 字段统一为 str类型(避免前端JS精度问题)
    """
    # Redis key 前缀: user:info:{user_id}
    CACHE_PREFIX: str = "user:info"
    
    # 正向缓存TTL(秒)
    CACHE_TTL_SECONDS: int = 3600
    # TTL抖动(秒), 避免大量key同时过期导致缓存雪崩
    CACHE_TTL_JITTER_SECONDS: int = 300
    
    # 负缓存TTL(秒): 缓存"用户不存在"的空对象 {}, 防止缓存穿透
    NEGATIVE_TTL_SECONDS: int = 60
    
    # user_id 最大长度(避免日志污染/异常 payload)
    MAX_USER_ID_LEN: int = 64
    
    # 内部方法: key/缓存读写/序列化
    @staticmethod
    def _build_cache_key(user_id: str) -> str:
        """
        构建用户缓存信息redis key: user:info:{user_id}
        :param user_id: 用户ID(字符串)
        """
        return f"{UserInfoService.CACHE_PREFIX}:{user_id}"
    
    @staticmethod
    def _normalize_user_id(user_id: Any) -> Optional[str]:
        """
        将 user_id 归一化为 str, 并做基础防御校验
        - None/空 -> None
        - 超长 -> None
        - 非数字(使用整数主键) -> None
        """
        if user_id is None:
            return None
        
        uid = str(user_id).strip()
        if len(uid) > UserInfoService.MAX_USER_ID_LEN:
            return None
        
        if not uid.isdigit():
            return None
        
        return uid
    
    @staticmethod
    def _safe_json_loads(raw: Any) -> Optional[Dict[str, Any]]:
        """
        将 Redis 取出的 raw(bytes/str) 转成 dict
        失败返回 None
        """
        if raw is None:
            return None
        
        try:
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", errors="ignore")
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
            return None
        except json.JSONDecodeError:
            return None
        except Exception:
            return None
    
    
    @staticmethod
    def _get_from_cache(redis_client, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        从Redis缓存读取并反序列化
        - 命中返回dict, 未命中/失败返回 None
        - JSON 损坏: 删除 key 后返回 None(触发回源)
        """
        try:
            cached_data = redis_client.get(cache_key)
        except Exception as e:
            logger.error("[UserInfoService] redis get failed key=%s err=%s", cache_key, e)
            return None
        
        if cached_data is None:
            return None
        
        data = UserInfoService._safe_json_loads(cached_data)
        if data is not None:
            return data
        
        # JSON 损坏: 删除并回源
        logger.warning("[UserInfoService] cache json corrupted, delete and fallback key=%s", cache_key)
        try:
            redis_client.delete(cache_key)
        except Exception:
            pass
        return None
    
    @staticmethod
    def _set_to_cache(redis_client, cache_key: str, user_info: Dict[str, Any]) -> None:
        """写入正向缓存(JSON + TTL抖动)"""
        try:
            ttl = UserInfoService.CACHE_TTL_SECONDS + random.randint(
                0, UserInfoService.CACHE_TTL_JITTER_SECONDS
            ) # 添加TTL抖动
            redis_client.setex(
                cache_key,
                ttl,
                json.dumps(user_info, ensure_ascii=False),
            ) # 写入缓存 setex方法设置TTL
        except Exception as e:
            logger.error("[UserInfoService] redis setex failed key=%s err=%s", cache_key, e)
    
    @staticmethod
    def _set_negative_cache(redis_client, cache_key: str) -> None:
        """写入负缓存(空对象{} + 短TTL)"""
        try:
            redis_client.setex(
                cache_key,
                UserInfoService.NEGATIVE_TTL_SECONDS, # 负缓存TTL
                json.dumps({}, ensure_ascii=False), # 空对象
            )
        except Exception as e:
            logger.error("[UserInfoService] redis negative setex failed key=%s err=%s", cache_key, e)
    
    @staticmethod
    def _serialize_user(user) -> Dict[str, Any]:
        """
        序列化对外字段(ID字段统一转换为str类型)
        - ID 字段统一 str
        - username/organization 允许为空
        """
        return {
            "id": str(user.id),
            "email": getattr(user, "email", "") or "",
            "username": getattr(user, "username", None),
            "is_active": bool(getattr(user, "is_active", True)),
            "is_staff": bool(getattr(user, "is_staff", False)),
            "is_superuser": bool(getattr(user, "is_superuser", False)),
            "totp_enabled": bool(getattr(user, "totp_enabled", False)),
            "organization": str(getattr(user, "organization", "")) if getattr(user, "organization", None) else None,
        }
    
    # 对外方法: 获取/刷新/失效 用户信息缓存
    
    @staticmethod
    def get_user_info(user_id: Any, *, enforce_db_filters: bool = True) -> Dict[str, Any]:
        """
        获取用户信息, 优先从Redis缓存中读取
        :param user_id: 用户ID(来自 token, 允许 int/str)
        :return: 用户信息字典, 若用户不存在则返回 {}
        """
        if not user_id:
            logger.warning("[UserInfoService] user_id为空")
            return {} # 空ID直接返回空对象
        
        cache_key = UserInfoService._build_cache_key(user_id) # 构建缓存key
        redis_client = get_redis_client(db=REDIS_DB_USERS_INFO_CACHE) # 获取Redis客户端
        
        cached = UserInfoService._get_from_cache(redis_client, cache_key) # 读取缓存
        if cached is not None:
            logger.debug(f"[UserInfoService] 缓存命中 {cache_key}")
            return cached # 命中缓存(包含负缓存)
        
        try:
            user = User.objects.filter(id=user_id, is_active=True, is_deleted=False).first() # 查询数据库
            if not user:
                logger.info(f"[UserInfoService] 用户不存在或未启用 user_id={user_id}")
                UserInfoService._set_negative_cache(redis_client, cache_key) # 写入负缓存
                return {} # 用户不存在或未启用
            
            user_info = UserInfoService._serialize_user(user) # 序列化用户信息
            UserInfoService._set_to_cache(redis_client, cache_key, user_info) # 写入正向缓存
            logger.debug(f"[UserInfoService] 用户信息缓存更新成功 user_id={user_id}")
            return user_info
        
        except Exception as e:
            logger.error(f"[UserInfoService] 查询数据库失败 user_id={user_id}, err={e}")
            return {} # 查询失败返回空对象
    
    @staticmethod
    def invalidate_cache(user_id: str) -> None:
        """删除指定用户缓存(资料更新后调用)"""
        if not user_id:
            return
        key = UserInfoService._build_cache_key(user_id)
        redis_client = get_redis_client(db=REDIS_DB_USERS_INFO_CACHE)
        
        try:
            redis_client.delete(key)
        except Exception as e:
            logger.error(f"[UserInfoService] 删除用户缓存失败 key={key}, err={e}")
            
    @staticmethod
    def refresh_cache(user_id: str) -> Dict[str, Any]:
        """强制刷新缓存(删除->回源DB -> 覆盖缓存)"""
        UserInfoService.invalidate_cache(user_id)
        return UserInfoService.get_user_info(user_id)