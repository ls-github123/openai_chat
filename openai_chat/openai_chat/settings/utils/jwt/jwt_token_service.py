"""
JWT Token 服务模块
- 统一封装 access/refresh 签发、刷新、拉黑逻辑
- 提供视图调用接口
- 依赖 RS256 Azure Key Vault 签名器
- 支持 refresh token 延长机制
"""
import traceback # 打印详细异常信息
from typing import Dict, Literal
from django.conf import settings
from users.models import User # 自定义用户模型
from .jwt_payload import build_jwt_payload # 构造 Payload
from .jwt_signer import AzureRS256Signer # RS256签名器
from .jwt_blacklist import add_to_blacklist # 黑名单机制
from openai_chat.settings.utils.logging import get_logger # 日志记录器

logger = get_logger("jwt")

class TokenService:
    """
    JWT 令牌服务类
    - 签发 access & refresh token
    - 刷新 access token
    - 拉黑 token
    """
    HEADER = {"alg": "RS256", "typ": "JWT"}
    
    def __init__(self, user: User):
        self.user = user
        self.signer = AzureRS256Signer.get_instance()
    
    def issue_tokens(self) -> Dict[Literal["access", "refresh"], str]:
        """
        签发 access + refresh token
        :return: {'access': xxx, 'refresh': yyy}
        """
        user_id = str(self.user.id)
        
        try:
            # 构造 Access Token 载荷
            access_payload = build_jwt_payload(
                user_id=user_id,
                scope=getattr(self.user, "scope", settings.JWT_SCOPE_DEFAULT),
                lifetime=settings.JWT_ACCESS_TOKEN_LIFETIME,
                token_type='access',
            )
            
            # 构造 Refresh Token 载荷
            refresh_payload = build_jwt_payload(
                user_id=user_id,
                scope='refresh', # 固定标记 refresh 类型作用域
                lifetime=settings.JWT_REFRESH_TOKEN_LIFETIME,
                token_type='refresh',
            )
            
            # 执行 Azure Key Vault 执行签名
            access_token = self.signer.sign(self.HEADER, access_payload)
            refresh_token = self.signer.sign(self.HEADER, refresh_payload)
            
            return {
                "access": access_token,
                "refresh": refresh_token
            }
            
        except Exception as e:
            logger.error(f"[TokenService] 令牌签发失败: {traceback.format_exc()}")
            raise RuntimeError("令牌签发失败, 请稍后重试")
       
    def refresh_access_token(self, refresh_payload: Dict) -> str:
        """
        根据已验证的 refresh_token payload 刷新新的 access_token
        :param refresh_payload: 解码后的payload, 必须包含 typ=refresh 和 sub 字段
        :return: 新的 access_token 字符串
        """
        logger.debug(f"[TokenService] 尝试刷新 access token, payload: {refresh_payload}")
        if refresh_payload.get("typ") != "refresh":
            raise ValueError("提供的Token并非Refresh类型")
        
        user_id = refresh_payload.get("sub")
        if not user_id:
            raise ValueError("RefreshToken缺少 sub 字段")
        
        # 构造新的 access token 载荷
        access_payload = build_jwt_payload(
            user_id=user_id,
            scope=settings.JWT_SCOPE_DEFAULT,
            lifetime=settings.JWT_ACCESS_TOKEN_LIFETIME,
            token_type="access",
        )
        
        header = {"alg": "RS256", "typ": "JWT"}
        return self.signer.sign(header, access_payload)
    
    def revoke_token(self, jti: str, exp: int) -> bool:
        """
        拉黑 token (如退出登录/被强制退出)
        :param jti: Token 唯一标识
        :param exp: Token 过期时间戳(秒)
        :return: 是否成功
        """
        logger.info(f"[TokenService] 拉黑令牌 jti={jti}, exp={exp}")
        return add_to_blacklist(jti, exp)