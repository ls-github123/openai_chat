"""
JWT 鉴权阶段 - 用户状态实时校验（Redis-only）

模块目标:
1. 在鉴权链路中只依赖 Redis 用户状态事实源，不查询数据库
2. 统一校验账号状态:
   - is_active（是否启用）
   - is_deleted（是否删除/注销）
3. 支持会话版本实时校验:
   - token payload 中 sv
   - Redis 状态中的 sess_ver
   - 两者不一致时判定“登录态已失效”

安全策略:
- fail-closed：Redis 读取异常、状态缺失、字段异常时，一律拒绝访问
"""
from __future__ import annotations
from typing import Any, Dict, Mapping, cast
from redis import Redis
from openai_chat.settings.base import REDIS_DB_USERS_STATE
from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client

logger = get_logger("users.auth.state_guards")

class UserStateGuard:
   """
   Redis-only 用户状态守卫
   """
   KEY_PREFIX = "user:state:"
   
   @classmethod
   def _key(cls, user_id: int) -> str:
      """
      构造 Redis key: user:state:{user_id}
      """
      return f"{cls.KEY_PREFIX}{user_id}"
   
   @staticmethod
   def _redis_sync() -> Redis:
      """
      获取同步 Redis 客户端，并做类型收敛，避免类型污染
      """
      return cast(Redis, get_redis_client(db=REDIS_DB_USERS_STATE))
   
   @staticmethod
   def _to_str(value: Any) -> str:
      """
      将 Redis 返回值统一转换为 str 字符串
      """
      if isinstance(value, (bytes, bytearray)):
         return value.decode("utf-8", errors="ignore")
      return str(value)
   
   @staticmethod
   def _to_bool_flag(value: str, *, default: bool = False) -> bool:
      """
      解析 Redis 中布尔标记字符串为 bool
      """
      v = (value or "").strip()
      if v in {"1", "true", "True", "TRUE"}:
         return True
      if v in {"0", "false", "False", "FALSE", ""}:
         return False
      return default
   
   @staticmethod
   def _parse_positive_int(raw: Any, *, field_name: str) -> int:
      """
      将任意输入解析为正整数（>=1），用于 sess_ver/sv 等字段校验
      """
      if raw is None:
         raise ValueError(f"{field_name} is None")
      if isinstance(raw, bool):
         raise ValueError(f"{field_name} is bool")
      value = int(str(raw).strip())
      if value < 1:
         raise ValueError(f"{field_name} < 1")
      return value
   
   @classmethod
   def _load_user_state(cls, user_id: int, *, stage: str) -> Dict[str, str]:
      """
      从 Redis 加载并标准化用户状态
      
      失败策略：
      - 状态缺失/读取异常/结构异常 -> 直接抛 AppException.unauthorized（fail-closed）
      """
      if not isinstance(user_id, int) or user_id <= 0:
         logger.warning("[UserStateGuard] invalid user_id stage=%s user_id=%r", stage, user_id)
         raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_USER,
            message="认证失败",
         )
      
      key = cls._key(user_id)
      
      try:
         raw = cls._redis_sync().hgetall(key)
      except Exception as exc:
         logger.error(
            "[UserStateGuard] redis read failed stage=%s user_id=%s key=%s err=%r",
               stage,
               user_id,
               key,
               exc,
         )
         raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_USER,
            message="认证失败",
         ) from exc
         
      if not raw or not isinstance(raw, Mapping):
         logger.warning(
               "[UserStateGuard] state missing stage=%s user_id=%s key=%s",
               stage,
               user_id,
               key,
         )
         raise AppException.unauthorized(
               code=ErrorCodes.AUTH_INVALID_USER,
               message="认证失败",
         )
      
      state = {cls._to_str(k): cls._to_str(v) for k, v in raw.items()}
      return state
   
   @classmethod
   def _ensure_account_state_allowed(cls, *, user_id: int, state: Mapping[str, str], stage: str) -> None:
      """
      校验账号状态字段：
      - is_deleted 优先级高于 is_active
      """
      is_deleted = cls._to_bool_flag(state.get("is_deleted", "0"), default=False)
      is_active = cls._to_bool_flag(state.get("is_active", "0"), default=False)
      
      if is_deleted:
         logger.warning("[UserStateGuard] reject deleted stage=%s user_id=%s", stage, user_id)
         raise AppException.forbidden(
            code=ErrorCodes.ACCOUNT_DELETED,
            message="该账号已被注销",
         )
      
      if not is_active:
         logger.warning("[UserStateGuard] reject disabled stage=%s user_id=%s", stage, user_id)
         raise AppException.forbidden(
            code=ErrorCodes.ACCOUNT_DISABLED,
            message="该账号已被禁用",
         )
   
   @classmethod
   def ensure_user_state_allowed(cls, user_id: int, *, stage: str = "auth") -> Dict[str, str]:
      """
      仅校验账号状态(is_active / is_deleted)
      
      返回:
      - 标准化后的 Redis 状态字典(string -> string)
      """
      state = cls._load_user_state(user_id=user_id, stage=stage)
      cls._ensure_account_state_allowed(user_id=user_id, state=state, stage=stage)
      return state
   
   @classmethod
   def ensure_user_state_and_sv_allowed(
      cls,
      *,
      user_id: int,
      token_sv: int,
      stage: str = "auth",
   ) -> Dict[str, str]:
      """
      校验账号状态 + 会话版本一致性(sv == sess_ver)
      
      典型场景:
      - jwt_auth(access token 鉴权)
      - token_refresh_service(refresh token 刷新)
      """
      state = cls.ensure_user_state_allowed(user_id=user_id, stage=stage)
      
      try:
         state_sv = cls._parse_positive_int(state.get("sess_ver"), field_name="sess_ver")
      except Exception as exc:
         logger.warning(
            "[UserStateGuard] invalid sess_ver stage=%s user_id=%s sess_ver=%r",
            stage,
            user_id,
            state.get("sess_ver"),
         )
         raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
            message="登录状态已失效，请重新登录",
         ) from exc
      
      try:
         parsed_token_sv = cls._parse_positive_int(token_sv, field_name="token_sv")
      except Exception as exc:
         logger.warning(
            "[UserStateGuard] invalid token sv stage=%s user_id=%s token_sv=%r",
            stage,
            user_id,
            token_sv,
         )
         raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
            message="登录状态已失效，请重新登录",
         ) from exc
      
      if parsed_token_sv != state_sv:
         logger.info(
            "[UserStateGuard] sv mismatch stage=%s user_id=%s token_sv=%s state_sv=%s",
            stage,
            user_id,
            parsed_token_sv,
            state_sv,
         )
         raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
             message="登录状态已失效，请重新登录",
         )
      
      return state