from __future__ import annotations
import json, time, secrets
from datetime import timedelta # 兼容 JWT_ACCESS_TOKEN_LIFETIME 为 timedelta 的场景
from typing import Any, Dict, Optional, cast

# === 项目内导入 ===
from users.models import User # 用户模型
from users.serializers.auth_login_serializer import LoginSerializer # 登录输入校验序列化器
from users.services.auth.guards import ensure_user_can_login # 登录前置状态校验(禁用/注销等)
from users.services.user_state_service import UserStateService # 用户状态事实源同步
from openai_chat.settings.utils.jwt.jwt_token_service import TokenIssuerService # JWT令牌签发服务类
from openai_chat.settings.utils.redis import get_redis_client

from openai_chat.settings.base import REDIS_DB_USERS_LOGIN_PENDING # 用户登录预登录缓存占用库
from openai_chat.settings.base import JWT_ACCESS_TOKEN_LIFETIME # Access Token默认有效期
from openai_chat.settings.utils.logging import get_logger

from openai_chat.settings.utils.exceptions import AppException # 业务异常：统一抛出（DRF异常处理器负责输出）
from openai_chat.settings.utils.error_codes import ErrorCodes # 错误码常量表

logger = get_logger("users")

# Redis Key
LOGIN_PENDING_PREFIX = "login:pending" # pending key 前缀
LOGIN_TTL_SECONDS = 300 # pending 生存时间(秒)

# 输入防御 - 长度限制
MAX_EMAIL_LEN = 254
MAX_PASSWORD_LEN = 1024

class LoginService:
    """
    用户登录服务类(阶段一: 密码校验 + guards + 状态事实源同步 + TOTP分流)
    - 对外错误信息收敛，避免枚举（统一“邮箱或密码错误”）
    - 若启用 TOTP：写入 pending，并返回 challenge_id（不返回 user_id）
    - 若未启用 TOTP：直接签发 JWT
    """
    def __init__(self, *, data: Any, ip: str, user_agent: str = ""):
        """
        :param data: 前端提交登录数据（email/password）
        :param ip: 请求来源 IP（用于审计与 pending 绑定）
        :param user_agent: UA（可选，用于审计与风控；不影响业务）
        """
        self.data = data
        self.remote_ip = ip
        self.user_agent = user_agent
        
        # DRF serializer: 仅做字段格式校验
        self.serializer = LoginSerializer(data=data)
        
        # 登录成功后的用户实例(阶段内缓存)
        self.user: Optional[User] = None
        
        # pending 专用 Redis
        self.redis_pending = get_redis_client(db=REDIS_DB_USERS_LOGIN_PENDING)
        
    def execute(self) -> Dict[str, Any]:
        """
        登录入口(阶段一)
        :return: dict(require_totp / challenge_id / tokens)
        """
        # 参数格式校验
        self.serializer.is_valid(raise_exception=True)
        data = cast(Dict[str, Any], self.serializer.validated_data)
        
        email_raw = str(data.get("email", "")).strip()
        password = str(data.get("password", "")).strip()
        
        # 防御式校验: 空值/长度(对外统一错误)
        if not email_raw or not password:
            logger.warning("[Login] rejected: empty email/password ip=%s", self.remote_ip)
            raise AppException.bad_request(
                code=ErrorCodes.AUTH_INVALID_CREDENTIALS,
                message="邮箱或密码错误",
            )
        
        if len(email_raw) > MAX_EMAIL_LEN or len(password) > MAX_PASSWORD_LEN:
            logger.warning("[Login] rejected: too long input ip=%s", self.remote_ip)
            raise AppException.bad_request(
                code=ErrorCodes.AUTH_INVALID_CREDENTIALS,
                message="邮箱或密码错误",
            )
        
        # 查询用户
        user = self._get_user_by_email(email_raw)
        if not user:
            logger.warning("[Login] rejected: user not found email=%s ip=%s", email_raw, self.remote_ip)
            raise AppException.bad_request(
                code=ErrorCodes.AUTH_INVALID_CREDENTIALS,
                message="邮箱或密码错误",
            )
        
        # 校验密码(统一错误信息: 避免枚举)
        if not user.check_password(password):
            logger.warning(
                "[Login] rejected: bad password user_id=%s email=%s ip=%s",
                user.id, email_raw, self.remote_ip,
            )
            raise AppException.bad_request(
                code=ErrorCodes.AUTH_INVALID_CREDENTIALS,
                message="邮箱或密码错误",
            )
        
        self.user = user
        
        # 登录前置校验: 禁用/注销等
        ensure_user_can_login(user, stage="login")
        
        # 同步用户状态事实源(redis db=8)
        UserStateService.sync_to_redis(user)
        
        logger.info(
            "[Login] password ok user_id=%s email=%s totp_enabled=%s ip=%s",
            user.id, user.email, user.totp_enabled, self.remote_ip,
        )
        
        # TOTP 分流: 如启用则进入二次验证
        if user.totp_enabled:
            challenge_id = self._cache_pending_login()
            return {
                "require_totp": True,
                "challenge_id": challenge_id,
            }
        
        # 未启用 TOTP: 直接签发 JWT
        tokens = self._issue_tokens(user)
        return {
            "require_totp": False,
            **tokens,
            "token_type": "Bearer",
            "expires_in": self._get_expires_in_seconds(JWT_ACCESS_TOKEN_LIFETIME),
        }
            
    
    # === 内部方法 ===
    @staticmethod
    def _get_expires_in_seconds(value: Any) -> int:
        """
        将 token lifetime 转换为秒(int)
        - timedelta -> total_seconds
        - int/float/str -> int()
        """
        if isinstance(value, timedelta):
            return int(value.total_seconds())
        try:
            return int(value)
        except Exception:
            logger.error("[Login] invalid JWT_ACCESS_TOKEN_LIFETIME=%r", value)
            return 900 # 兜底
    
    @staticmethod
    def _get_user_by_email(email: str) -> Optional[User]:
        """
        根据邮箱查询用户:
        - email__iexact：不区分大小写
        - first()：不存在则返回 None，避免 .get() 抛异常导致 500
        """
        email_norm = email.strip()
        if not email_norm:
            return None
        return User.objects.filter(email__iexact=email_norm).first()
    
    def _cache_pending_login(self) -> str:
        """
        写入 pending(用于 TOTP 二次验证)
        - key: login:pending:{challenge_id}
        - value: JSON(uid/ip/ua/ts)
        - TTL: setex(明确 TTL，避免无 TTL key)
        """
        if not self.user:
            raise AppException.internal_error(
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="系统内部错误, 请稍后再试",
            )
        
        challenge_id = secrets.token_urlsafe(32)
        cache_key = f"{LOGIN_PENDING_PREFIX}:{challenge_id}"
        payload = {
            "uid": str(self.user.id),
            "ip": self.remote_ip,
            "ua": self.user_agent[:512], # 防御: 截断 UA, 避免日志污染
            "ts": int(time.time()),
        }
        
        try:
            self.redis_pending.setex(
                cache_key,
                LOGIN_TTL_SECONDS,
                json.dumps(payload, ensure_ascii=False),
            )
            logger.debug("[Login] pending cache ok key=%s uid=%s", cache_key, self.user.id)
            return challenge_id
        except Exception as e:
            logger.error("[Login] pending cache failed key=%s uid=%s err=%s", cache_key, self.user.id, e)
            raise AppException.internal_error(
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="系统内部错误, 请稍后再试",
            )
    
    @staticmethod
    def _issue_tokens(user: User) -> Dict[str, Any]:
        """
        签发 JWT(复用 TokenIssuerService)
        """
        token_service = TokenIssuerService(user)
        return cast(Dict[str, Any], token_service.issue_tokens())