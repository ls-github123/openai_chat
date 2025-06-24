from openai_chat.settings.utils.jwt.jwt_token_service import TokenRevoker # JWT Token拉黑器
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
            user_id = payload.get("sub") # 从 payload 中获取 sub 字段
            
            if not all([jti, exp, user_id]):
                raise RuntimeError("Token缺少必要字段 jti/exp/sub")
            
            if not isinstance(exp, int):
                raise RuntimeError("Token exp 字段类型非法")
            
            # 使用统一封装类拉黑接口
            revoker = TokenRevoker(jti=str(jti), exp=exp, user_id=user_id, token_type=self.token_type)
            if revoker.revoke_token():
                logger.info(f"[LogoutService] 用户 {user_id} 成功注销 {self.token_type} 令牌, jti={jti}")
            else:
                raise RuntimeError("拉黑失败, 请重试")
        except Exception as e:
            logger.error(f"[LogoutService] {self.token_type}令牌加入黑名单失败: {e}")
            raise RuntimeError("安全退出登录失败, 请稍后重试")