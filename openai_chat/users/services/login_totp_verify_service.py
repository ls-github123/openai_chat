"""
用户登录服务类(二阶段TOTP验证)
"""
from __future__ import annotations
import json
from typing import Any, Dict, Optional, cast
from users.models import User

from openai_chat.settings.base import REDIS_DB_USERS_LOGIN_PENDING
from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.jwt.jwt_token_service import TokenIssuerService
from openai_chat.settings.utils.locks import build_lock
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client

from users.services.auth.guards import ensure_user_can_login
from users.services.user_info_service import UserInfoService
from users.services.user_state_service import UserStateService
from users.totp import verify_login_totp
from .login_service import LOGIN_PENDING_PREFIX

logger = get_logger("users")

# 二阶段登录验证锁 TTL
LOGIN_TOTP_VERIFY_LOCK_TTL_MS = 5000

class LoginTOTPVerifyService:
    """
    用户登录服务类(二阶段)
    
    - pending 登录态只能被消费一次
    - challenge_id 不能被并发重复使用
    - TOTP 验证通过后，必须先成功删除 pending，再签发 JWT
    - 二阶段请求尽量绑定一阶段记录的 IP / UA，降低 challenge 泄露后的复用风险
    """
    def __init__(
        self,
        challenge_id: str,
        totp_code: str,
        *,
        ip: str = "",
        user_agent: str = "",
    ):
        """
        :param challenge_id: 登录阶段一返回的 challenge_id
        :param totp_code: 用户提交的 6 位 TOTP 验证码
        :param ip: 当前二阶段请求 IP，用于和 pending 中的一阶段 IP 比对
        :param user_agent: 当前二阶段请求 UA，用于和 pending 中的一阶段 UA 比对
        """
        self.challenge_id = str(challenge_id or "").strip()
        self.totp_code = str(totp_code or "").strip()
        self.remote_ip = str(ip or "").strip()
        self.user_agent = str(user_agent or "")[:512]
        self.redis = get_redis_client(db=REDIS_DB_USERS_LOGIN_PENDING)
    
    def verify_and_issue_token(self) -> Dict[str, Any]:
        """
        核心流程:
        
        1. 校验 challenge_id 基础格式
        2. 对 challenge_id 加锁, 保证同一个 pending 登录态串行消费
        3. 读取并解析 pending
        4. 校验 pending 中 uid / ip / ua
        5. 查询用户并校验 TOTP
        6. 再次校验用户状态
        7. 签发前删除 pending，删除失败则拒绝签发
        8. 签发 JWT 并返回用户快照
        """
        if not self.challenge_id:
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message="登录状态无效, 请重新登录",
            )
        
        cache_key = f"{LOGIN_PENDING_PREFIX}:{self.challenge_id}"
        lock_key = f"lock:{LOGIN_PENDING_PREFIX}:{self.challenge_id}"
        
        # 只锁当前 challenge_id，不锁整个用户
        # 避免同一个 challenge 被并发消费
        with build_lock(lock_key, ttl=LOGIN_TOTP_VERIFY_LOCK_TTL_MS, strategy="safe"):
            return self._verify_and_issue_token_locked(cache_key)
        
    
    def _verify_and_issue_token_locked(self, cache_key: str) -> Dict[str, Any]:
        """
        必须在 challenge_id 锁内调用
        
        - 不要在锁外读取 pending，否则并发请求可能同时读到同一份 pending
        - 删除 pending 失败时停止继续签发 JWT
        """
        pending = self._load_pending(cache_key)
        
        uid = str(pending.get("uid", "")).strip()
        if not uid:
            logger.error(
                "[TOTPVerify] pending invalid: missing uid challenge_id=%s",
                self.challenge_id,
            )
            self._delete_broken_pending(cache_key)
            raise AppException.internal_error(
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="系统内部错误, 请重新登录",
            )
        
        self._ensure_pending_context_allowed(pending)
        
        try:
            user = cast(User, User.objects.get(id=uid))
        except User.DoesNotExist as exc:
            logger.warning(
                "[TOTPVerify] user missing uid=%s challenge_id=%s",
                uid,
                self.challenge_id,
            )
            self._delete_broken_pending(cache_key)
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_USER,
                message="用户不存在或登录状态已失效",
            ) from exc
        
        # TOTP 校验内部处理
        # - 是否启用 TOTP
        # - secret 是否存在
        # - 验证码格式
        # - 失败计数
        # - 超限拒绝
        if not verify_login_totp(user, self.totp_code):
            logger.warning(
                "[TOTPVerify] rejected: bad totp uid=%s challenge_id=%s",
                user.id,
                self.challenge_id,
            )
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_TOTP_INVALID,
                message="TOTP验证码错误或已超出最大尝试次数",
            )
        
        # 二阶段和一阶段之间可能存在时间间隔
        # 用户可能在间隔内被禁用/注销或状态变更, 签发前需再次校验
        ensure_user_can_login(user, stage="totp")
        
        # 同步用户状态事实源, 确保 JWT 后续校验依赖的 Redis 状态保持实时性
        UserStateService.sync_to_redis(user)
        
        # 签发JWT之前删除pending
        # 如删除失败, 则无法保证 challenge_id 只消费一次, fail-closed 拒绝签发
        deleted = self.redis.delete(cache_key)
        if int(str(deleted) or 0) != 1:
            logger.warning(
                "[TOTPVerify] rejected: pending consume failed challenge_id=%s deleted=%s",
                self.challenge_id,
                deleted,
            )
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_TOTP_INVALID,
                message="登录状态已过期, 请重新登录",
            )
        
        logger.info(
            "[TOTPVerify] ok uid=%s email=%s -> issue jwt",
            user.id,
            user.email,
        )
        
        token_service = TokenIssuerService(user)
        tokens = token_service.issue_tokens() # 签发 access + refresh token
        
        user_info = UserInfoService.get_user_info(str(user.id))
        
        return {
            **tokens,
            "user": user_info,
        }
    
    def _load_pending(self, cache_key: str) -> Dict[str, Any]:
        """
        从 redis 读取并解析 pending
        
        损坏数据处理策略:
        - 记录日志
        - 删除损坏 pending
        - 对外返回系统错误, 要求用户重新登录
        """
        cache_raw = self.redis.get(cache_key)
        
        if not cache_raw:
            logger.warning(
                "[TOTPVerify] rejected: pending missing challenge_id=%s",
                self.challenge_id,
            )
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_TOTP_INVALID,
                message="登录状态已过期, 请重新登录",
            )
        
        try:
            if isinstance(cache_raw, (bytes, bytearray)):
                cache_text = cache_raw.decode("utf-8")
            elif isinstance(cache_raw, str):
                cache_text = cache_raw
            else:
                raise TypeError(f"缓存数据类型异常: {type(cache_raw)}")
            
            pending = json.loads(cache_text)
            if not isinstance(pending, dict):
                raise TypeError(f"pending 类型异常: {type(pending)}")
            
            return cast(Dict[str, Any], pending)
        
        except Exception as exc:
            logger.error(
                "[TOTPVerify] pending parse failed challenge_id=%s err=%s",
                self.challenge_id,
                exc,
            )
            self._delete_broken_pending(cache_key)
            raise AppException.internal_error(
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="系统内部错误, 请重新登录",
            ) from exc
    
    def _ensure_pending_context_allowed(self, pending: Dict[str, Any]) -> None:
        """
        校验二阶段请求是否和一阶段 pending 上下文一致
        
        说明:
        - LoginService._cache_pending_login() 已写入 ip / ua
        - 这里进行弱绑定，降低 challenge_id 被截获后跨客户端复用的风险
        - 如果你的生产环境经过反向代理，必须确保 view 层取到的是可信真实 IP
        """
        pending_ip = str(pending.get("ip", "") or "").strip()
        pending_ua = str(pending.get("ua", "") or "")[:512]
        
        if pending_ip and self.remote_ip and pending_ip != self.remote_ip:
            logger.warning(
                "[TOTPVerify] rejected: ip mismatch challenge_id=%s pending_ip=%s request_ip=%s",
                self.challenge_id,
                pending_ip,
                self.remote_ip,
            )
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_TOTP_INVALID,
                message="登录状态已失效, 请重新登录",
            )
        
        if pending_ua and self.user_agent and pending_ua != self.user_agent:
            logger.warning(
                "[TOTPVerify] rejected: ua mismatch challenge_id=%s uid=%s",
                self.challenge_id,
                pending.get("uid"),
            )
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_TOTP_INVALID,
                message="登录状态已失效, 请重新登录",
            )
    
    def _delete_broken_pending(self, cache_key: str) -> None:
        """
        删除损坏或无效 pending
        - 签发 JWT 前检查 delete 返回值
        """
        try:
            self.redis.delete(cache_key)
        except Exception as exc:
            logger.error(
                "[TOTPVerify] pending delete failed challenge_id=%s err=%s",
                self.challenge_id,
                exc,
            )