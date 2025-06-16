from typing import cast
from users.models import User # 自定义用户模型
from openai_chat.settings.utils.jwt.jwt_token_service import TokenService
from openai_chat.settings.utils.redis import get_redis_client
from openai_chat.settings.base import REDIS_DB_JWT_CACHE
from users.totp import verify_login_totp
from openai_chat.settings.utils.logging import get_logger
from login_service import LOGIN_CACHE_PREFIX # 预登录缓存Redis key

logger = get_logger("users")

class LoginTOTPVerifyService:
    """
    用户登录服务类(二阶段)
    - TOTP验证码校验 + 签发JWT
    """
    def __init__(self, user_id: str, totp_code: str):
        """
        初始化服务类
        :param user_id: 用户ID(查询用户预登录缓存记录)
        :param totp_code: 用户提交的6位TOTP验证码
        """
        self.user_id = user_id
        self.totp_code = totp_code
        self.redis = get_redis_client(db=REDIS_DB_JWT_CACHE)
        
    def verify_and_issue_token(self) -> dict:
        """
        核心逻辑:
        - 读取用户预登录缓存
        - 校验TOTP 6位验证码
        - 校验成功则签发 JWT
        - 清除缓存
        """
        cache_key = f"{LOGIN_CACHE_PREFIX}:{self.user_id}"
        cache_raw = self.redis.get(cache_key)
        
        if not cache_raw:
            logger.warning(f"[TOTP登录校验] Redis 缓存不存在, 用户ID={self.user_id}")
            raise ValueError("登录状态已过期, 请重新登录")
        
        try:
            user = cast(User, User.objects.get(id=self.user_id))
        except User.DoesNotExist:
            logger.warning(f"[TOTP登录校验] 用户不存在: {self.user_id}")
            self.redis.delete(cache_key)
            raise ValueError("用户不存在")
        
        # 开始进行TOTP校验
        if not verify_login_totp(user, self.totp_code):
            raise ValueError("TOTP验证码错误或已超出最大尝试次数")
        
        # 清除 Redis 用户预登录缓存
        self.redis.delete(cache_key)
        
        logger.info(f"[TOTP登录校验] 用户: {user.email} TOTP二次验证通过, 开始签发JWT")
        # 签发 access + refresh Token
        token_service = TokenService(user)
        return token_service.issue_tokens()