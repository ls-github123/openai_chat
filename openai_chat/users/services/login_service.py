# 用户登录服务类
import time, json
from typing import Dict, Any, Union, cast
from django.contrib.auth import authenticate
from users.models import User
from users.serializers.auth_login_serializer import LoginSerializer
from openai_chat.settings.utils.jwt.jwt_token_service import TokenService
from openai_chat.settings.utils.redis import get_redis_client
from django.conf import settings
# from openai_chat.settings.utils.cloudflare_turnstile import verify_turnstile_token_async # Turnstile人机验证
from openai_chat.settings.base import REDIS_DB_JWT_CACHE
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("users")

LOGIN_CACHE_PREFIX = "login:pending" # 预登录缓存Redis key
LOGIN_TTL_SECONDS = 300 # 预登录缓存有效期(秒)

class LoginService:
    """
    用户登录服务类(阶段一)
    - 校验人机验证(Turnstile)
    - 校验用户邮箱和密码
    - 若未启用TOTP, 直接签发 JWT
    - 若启用TOTP, 缓存用户登录信息并进入二次验证流程
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
        self.user: Union[User, None] = None
        self.redis = get_redis_client(db=REDIS_DB_JWT_CACHE)
        
    def validate_credentials(self) -> dict:
        """
        校验 Cloudflare Turnstile 人机验证
        校验邮箱 + 密码, 判断是否启用TOTP
        若启用TOTP -> 缓存登录信息 -> 返回 require_totp=True
        若未启用TOTP -> 直接签发JWT
        :return: 返回 JWT 或 require_totp 状态
        """
        # # 人机验证(防止爆破登录)
        # if not verify_turnstile_token_async(self.cf_token, settings.TURNSTILE_USERS_SECRET_KEY, self.remote_ip):
        #     logger.warning(f"[Login] 人机验证失败, IP={self.remote_ip}")
        #     raise ValueError("人机验证未通过, 请刷新页面后重试")
        
        self.serializer.is_valid(raise_exception=True) # 自动抛出 ValidationError
        # 类型断言, 避免IDE报错, validated_data 实际上为 dict-like 对象
        data = cast(Dict[str, Any], self.serializer.validated_data)
        email = data["email"]
        password = data["password"]
        
        user = authenticate(email=email, password=password)
        if not user:
            logger.warning(f"[Login] 登录失败: 邮箱或密码错误 -> {email}")
            raise ValueError("用户不存在或密码错误")
        
        assert isinstance(user, User) # Pylance类型断定
        
        self.user = user
        logger.info(f"[Login] 用户登录成功: {user.email}, TOTP状态={user.totp_enabled}")
        
        # 若启用了TOTP, 进入二次验证阶段
        if user.totp_enabled:
            self._cache_pending_login() # 缓存进入TOTP阶段的用户信息
            return {
                "require_totp": True, # 用户启用TOTP, 进入TOTP验证码输入界面
                "user_id": str(user.id)
            }
            
        # 若未启用TOTP, 直接签发 JWT
        token_service = TokenService(user)
        tokens = token_service.issue_tokens()
        return {
            "require_totp": False,
            **tokens # 展开 access 和 refresh字段
        }
    
    def _cache_pending_login(self) -> None:
        """
        缓存用户预登录信息, 用于TOTP验证阶段
        - 每次登录都强制覆盖 Redis 登录缓存(不再判断是否已存在)
        """
        if not self.user:
            raise RuntimeError("user 未初始化, 无法写入Redis缓存")
        
        cache_key = f"{LOGIN_CACHE_PREFIX}:{self.user.id}"
        cache_value = {
            "uid": str(self.user.id),
            "email": self.user.email,
            "ip": self.remote_ip,
            "ts": int(time.time()),
        }
        
        try:
            # 每次登录，强制覆盖对应账户缓存
            self.redis.set(
                name=cache_key,
                value=json.dumps(cache_value),
                ex=LOGIN_TTL_SECONDS # 预登录缓存有效期(秒)
            )
            logger.debug(f"[Login] 用户预登录信息缓存成功: {cache_key}")
        except Exception as e:
            logger.error(f"[Login] 写入 Redis 登录缓存失败: {e}")
            raise RuntimeError("系统内部错误, 请稍后再试")