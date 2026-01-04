# 用户登录服务类
from __future__ import annotations # 延迟类型注解解析
import time, json
import secrets # 用于生成随机challenge_id
from typing import Dict, Any, Optional, cast
from users.models import User # 用户模型
from users.serializers.auth_login_serializer import LoginSerializer
from openai_chat.settings.utils.jwt.jwt_token_service import TokenIssuerService # JWT签发服务类
from openai_chat.settings.utils.redis import get_redis_client

# from openai_chat.settings.utils.cloudflare_turnstile import verify_turnstile_token_async # Turnstile人机验证
from openai_chat.settings.base import REDIS_DB_USERS_LOGIN_PENDING
from openai_chat.settings.utils.logging import get_logger
from users.services.user_info_service import UserInfoService # 用户信息服务类(携带JWT查询用户信息)
from users.services.auth.guards import ensure_user_can_login # 登录前置用户状态校验
from users.services.user_state_service import UserStateService # 用户状态事实源同步服务类

logger = get_logger("users")

LOGIN_PENDING_PREFIX = "login:pending" # 预登录缓存Redis key
LOGIN_TTL_SECONDS = 300 # 预登录缓存有效期(秒)

class LoginService:
    """
    用户登录服务类(阶段一 手动校验密码 + guards)
    - 校验人机验证(Turnstile) / 可选
    - 校验请求参数
    - 按邮箱查询用户(不直接使用 authenticate, 避免 is_active 导致的提前拦截)
    - 使用 check_password 校验密码
    - ensure_user_can_login 校验用户状态(禁用/注销等)
    - 同步用户状态事实源(Redis db=8)
    - 判断TOTP状态:
        - 若启用TOTP, 写入pending缓存, 返回 challenge_id 并进入二次验证流程
        - 若未启用TOTP, 直接签发 JWT, 并返回 access/refresh token + user_info
    """
    def __init__(self, data: Dict[str, Any], ip: str, cf_token: str):
        """
        初始化服务类
        :param data: 前端提交的登录数据
        :param ip: 请求来源的 IP 地址
        :param cf_token: Cloudflare Turnstile 返回的Token
        """
        self.data = data
        self.remote_ip = ip
        self.cf_token = cf_token
        self.serializer = LoginSerializer(data=data) # DRF序列化器
        self.user: Optional[User] = None # 登录成功后的用户实例
        self.redis_pending = get_redis_client(db=REDIS_DB_USERS_LOGIN_PENDING) # 预登录缓存 pending
    
    def validate_credentials(self) -> dict:
        """
        登录入口(阶段一):
        :return: dict(包含require_totp / tokens/ user_info等)
        """
        # # 人机验证(防止爆破登录)
        # if not verify_turnstile_token_async(self.cf_token, settings.TURNSTILE_USERS_SECRET_KEY, self.remote_ip):
        #     logger.warning(f"[Login] 人机验证失败, IP={self.remote_ip}")
        #     raise ValueError("人机验证未通过, 请刷新页面后重试")
        
        # 1. 参数校验
        self.serializer.is_valid(raise_exception=True) # 自动抛出 ValidationError
        # 类型断言, 避免IDE报错, validated_data 实际上为 dict-like 对象
        data = cast(Dict[str, Any], self.serializer.validated_data)
        
        email_raw = str(data.get("email", "")).strip()
        password = str(data.get("password", "")).strip()
        
        # 防御式校验:避免空值穿透
        if not email_raw or not password:
            logger.warning("[Login] rejected: empty email/password ip=%s", self.remote_ip)
            raise ValueError("邮箱或密码错误")
        
        # 2. 查询用户(对外统一错误信息, 避免枚举攻击)
        user = self._get_user_by_email(email_raw)
        if not user:
            logger.warning("[Login] rejected: user not found email=%s ip=%s", email_raw, self.remote_ip)
            raise ValueError("邮箱或密码错误")
        
        # 3. 校验密码(使用 check_password 方法)
        if not user.check_password(password):
            logger.warning(
                "[Login] rejected: bad password user_id=%s email=%s ip=%s",
                user.id, email_raw, self.remote_ip,
            )
            raise ValueError("邮箱或密码错误")
        
        self.user = user # 记录登录成功的用户实例
        
        # 4. 登录前置校验(ORM: 注销/禁用 时抛出业务异常)
        ensure_user_can_login(user, stage="login")
        
        # 5. 同步用户状态事实源(Redis db=8)
        UserStateService.sync_to_redis(user)
        
        logger.info(
            "[Login] password ok user_id=%s email=%s totp_enabled=%s ip=%s",
            user.id, user.email, user.totp_enabled, self.remote_ip,
        )
        
        # 若启用了TOTP, 进入二次验证阶段(返回challenge_id)
        if user.totp_enabled:
            challenge_id = self._cache_pending_login() # 缓存进入TOTP阶段的用户信息
            return {
                "require_totp": True, # 用户启用TOTP, 进入TOTP验证码输入界面
                "challenge_id": str(challenge_id), # 返回预登录缓存标识(不返回user_id,避免枚举爆破风险)
            }
        
        # 若未启用TOTP, 直接签发 JWT
        token_service = TokenIssuerService(user)
        tokens = token_service.issue_tokens()
        
        # 返回用户快照(缓存命中则不查询DB, 未命中则回源并缓存)
        user_info = UserInfoService.get_user_info(str(user.id))
        return {
            "require_totp": False,
            **tokens, # 展开 access 和 refresh字段
            "user": user_info
        }
    
    @staticmethod
    def _get_user_by_email(email: str) -> Optional[User]:
        """
        根据邮箱查询用户(支持大小写/空格处理)
        - 采用 iexact: 不区分大小写查询
        - 采用 first: 找不到时返回 None, 避免.get()抛出异常导致500
        """
        email_norm = email.strip()
        if not email_norm:
            return None
        return User.objects.filter(email__iexact=email_norm).first()
    
    def _cache_pending_login(self) -> str:
        """
        缓存用户预登录信息, 用于TOTP二次验证阶段
        - 每次登录都强制覆盖 Redis 登录缓存(不再判断是否已存在)
        """
        if not self.user:
            raise RuntimeError("user 未初始化, 无法写入 pending 缓存")
        
        # 生成随机 challenge_id 作为Redis key
        challenge_id = secrets.token_urlsafe(32) # 32位长度的随机字符串
        
        cache_key = f"{LOGIN_PENDING_PREFIX}:{challenge_id}"
        cache_value = {
            "uid": str(self.user.id),
            "email": self.user.email,
            "ip": self.remote_ip,
            "ts": int(time.time()), # 缓存时间戳
        }
        
        try:
            # 每次登录，强制覆盖对应账户缓存(setex 明确TTL-秒)
            self.redis_pending.setex(
                cache_key,
                LOGIN_TTL_SECONDS,
                json.dumps(cache_value, ensure_ascii=False),
            )
            logger.debug(f"[Login] 用户预登录信息缓存成功: key={cache_key}")
            return challenge_id # 返回 challenge_id 供前端使用
        except Exception as e:
            logger.error("[Login] pending cache failed key=%s uid=%s err=%s", cache_key, self.user.id, e)
            raise RuntimeError("系统内部错误, 请稍后再试")