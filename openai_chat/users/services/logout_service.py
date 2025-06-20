from openai_chat.settings.utils.jwt.jwt_blacklist import add_to_blacklist # 令牌黑名单函数
from openai_chat.settings.utils.jwt.jwt_verifier import AzureRS256Verifier
from openai_chat.settings.utils.logging import get_logger
from typing import Optional

logger = get_logger("users")

class LogoutService:
    """
    用户退出登录服务类
    - 接收 access_token 或 refresh_token
    - 将 token 加入 Redis 黑名单
    """
    def __init__(self, token: str, token_type: Optional[str] = "access"):
        self.token = token
        self.token_type = token_type or "access"
    
    def execute(self) -> None:
        try:
            # 获取 AzureRS256Verifier 的全局单例实例（懒加载），用于验证 JWT Token 签名
            verifier = AzureRS256Verifier.get_instance()
            # 验证并解析 JWT Token(校验token是否过期、时间戳是否合法等)
            payload = verifier.verify(self.token)
            
            jti = payload.get("jti") # 从pyload中提取唯一标识jti字段
            exp = payload.get("exp") # 从payload中提取 exp 字段
            
            if not jti or not exp:
                raise RuntimeError("Token缺少 jti 或 exp 字段, 无法安全退出登录")
            
            add_to_blacklist(self.token, exp)
            logger.info(f"[LogoutService] 成功将 {self.token_type} 令牌加入黑名单, jti={jti}")
        except Exception as e:
            logger.error(f"[LogoutService] token 加入黑名单失败: {e}")
            raise RuntimeError("安全退出登录失败, 请稍后重试")