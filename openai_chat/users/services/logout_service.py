from openai_chat.settings.utils.jwt.jwt_blacklist import add_to_blacklist # 令牌黑名单函数
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
            add_to_blacklist(self.token, int(self.token_type))
            logger.info(f"[LogoutService]成功拉黑 {self.token_type} 令牌")
        except Exception as e:
            logger.error(f"[LogoutService] 拉黑 token 失败: {e}")
            raise RuntimeError("退出登录失败, 请稍后重试")