"""
---用户状态事实源构建与同步模块---
本模块负责将用户的核心状态（是否启用 / 是否删除）同步到 Redis,
作为接口鉴权阶段的“事实源(Source of Truth)”。

使用约定：
- 写入发生在:登录成功、refresh 成功(可选)
- 读取发生在：接口鉴权 guards(Redis-only)
- 本模块不做权限判断、不抛鉴权异常，仅负责状态同步

Redis 设计：
- DB: REDIS_DB_USERS_STATE
- Key: user:state:{user_id}
- Type: Hash
"""
from __future__ import annotations # 延迟类型注解解析
import time
from dataclasses import dataclass # 简化服务类定义
from users.models import User # 用户模型
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.base import REDIS_DB_USERS_STATE # 用户状态事实源 Redis占用库
from openai_chat.settings.utils.redis import get_redis_client

logger = get_logger("users")

@dataclass(frozen=True)
class UserState:
    """用户状态数据类"""
    is_active: bool
    is_deleted: bool
    updated_at: int

class UserStateService:
    """
    用户状态事实源(Redis)
    - 写入: 登录成功后 / refresh成功后(可选)
    - 读取: 接口鉴权 guards (后续实现)
    """
    key_prefix = "user:state:"
    
    @classmethod
    def _key(cls, user_id: int) -> str:
        """生成 Redis key"""
        return f"{cls.key_prefix}{user_id}"
    
    @classmethod
    def build_state(cls, user: User) -> UserState:
        """根据 User 实例构建 UserState 对象"""
        return UserState(
            is_active=bool(getattr(user, "is_active", True)),
            is_deleted=bool(getattr(user, "is_deleted", False)),
            updated_at=int(time.time()), # 当前时间戳
        )
    
    @classmethod
    def sync_to_redis(cls, user: User) -> None:
        """
        将用户状态同步到 Redis(事实源)
        - 只写入, 不做权限判断
        """
        user_id = int(getattr(user, "id"))
        key = cls._key(user_id)
        state = cls.build_state(user)
        
        r = get_redis_client(db=REDIS_DB_USERS_STATE)
        
        payload = {
            "is_active": 1 if state.is_active else 0,
            "is_deleted": 1 if state.is_deleted else 0,
            "updated_at": state.updated_at,
        }
        
        # 写入 Redis 哈希(不设置TTL: 用户状态长期存在, 由更新操作覆盖)
        r.hset(key, mapping=payload)
        
        logger.info(
            "[UserStateService] synced user state to redis user_id=%s is_active=%s is_deleted=%s",
            user_id, payload["is_active"], payload["is_deleted"],
        )