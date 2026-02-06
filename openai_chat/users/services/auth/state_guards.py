"""
--- JWT 鉴权阶段 · 用户状态实时校验（Redis-only） ---

本模块用于 JWT 鉴权阶段的用户状态校验，作为接口访问时的
“实时事实源（Source of Truth）”。

设计要点：
- 仅使用 Redis 读取用户状态，不查询数据库（高性能、低耦合）
- Redis 中缺失状态即视为不可信，直接拒绝访问（安全优先）
- 校验字段仅限：
    - is_active  ：账户是否启用
    - is_deleted ：账户是否已注销
- 删除状态优先级高于禁用状态

使用场景：
- JWT 鉴权成功后（token 已验签）
- 在接口权限校验前调用
- 用于动态封禁、注销即时生效

Redis 约定：
- DB   : REDIS_DB_USERS_STATE
- Key  : user:state:{user_id}
- Type : Hash
- Value:
    - is_active   (0 / 1)
    - is_deleted  (0 / 1)
    - updated_at (timestamp)

注意事项：
- 本模块不负责登录、签发令牌
- 不做数据库回源、不做状态修复
- 仅负责“是否允许继续访问”的最终判定
"""
from __future__ import annotations

from typing import Any, Dict
from openai_chat.settings.base import REDIS_DB_USERS_STATE # 用户状态事实源占用库
from openai_chat.settings.utils.redis import get_redis_client
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.error_codes import ErrorCodes

logger = get_logger("users")

class UserStateGuard:
    """
    Redis-only 用户状态校验(JWT鉴权前置校验)
    - 只读 Redi user:state:{uid} 用户状态事实源
    - 不查询DB
    """
    key_prefix = "user:state:"
    
    @classmethod
    def _key(cls, user_id: int) -> str:
        return f"{cls.key_prefix}{user_id}"
    
    @staticmethod
    def _to_str(x: Any) -> str:
        # 将 Redis 返回的 bytes 类型转换为 str
        if isinstance(x, (bytes, bytearray)):
            return x.decode("utf-8")
        return str(x)
    
    @staticmethod
    def _to_bool_flag(val: str, *, default: bool = False) -> bool:
        """
        将 Redis 中的布尔标志值解析为 bool
        - 支持 1/0、 true/false True/False 等多种形式
        """
        v = (val or "").strip()
        if v in ("1", "true", "True", "TRUE"):
            return True
        if v in ("0", "false", "False", "FALSE", ""):
            return False
        return default # 无法解析时返回默认值
    
    @classmethod
    def ensure_user_state_allowed(cls, user_id: int, *, stage: str = "auth") -> Dict[str, Any]:
        """
        Redis-only 用户状态校验
        :return: 用户状态事实源字典(均为str类型), 供上层写入 request 上下文
        """
        if not user_id:
            logger.warning("[AuthStateGuard] reject: invalid user_id stage=%s", stage)
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_USER,
                message="认证失败",
            )
        
        r = get_redis_client(db=REDIS_DB_USERS_STATE)
        key = cls._key(int(user_id))
        
        raw = r.hgetall(key)
        if not raw:
            # 用户状态事实源不存在, 视为无效用户
            logger.warning("[AuthStateGuard] reject: state missing stage=%s user_id=%s", stage, user_id)
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_USER,
                message="认证失败",
            )
        
        if not isinstance(raw, dict):
            logger.error(
                "[AuthStateGuard] reject: invalid redis return type stage=%s user_id=%s type=%s",
                stage, user_id, type(raw),
            )
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_USER,
                message="认证失败",
            )
        
        # 统一转换为 str
        state: Dict[str, str] = {cls._to_str(k): cls._to_str(v) for k, v in raw.items()}
        
        is_deleted = cls._to_bool_flag(state.get("is_deleted", "0"), default=False)
        is_active = cls._to_bool_flag(state.get("is_active", "0"), default=False)
        
        # 账户注销校验优先 -> 403
        if is_deleted:
            logger.warning("[AuthStateGuard] reject: deleted stage=%s user_id=%s", stage, user_id)
            raise AppException.forbidden(
                code=ErrorCodes.ACCOUNT_DELETED,
                message="该账户已被注销",
            )
        
        # 账户禁用校验
        if not is_active:
            logger.warning("[AuthStateGuard] reject: disabled stage=%s user_id=%s", stage, user_id)
            raise AppException.forbidden(
                code=ErrorCodes.ACCOUNT_DISABLED,
                message="该账户已被禁用",
            )
        
        # 校验通过
        return state