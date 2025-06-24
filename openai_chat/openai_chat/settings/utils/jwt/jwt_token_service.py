"""
JWT Token 服务模块
- 统一封装 access/refresh 签发、刷新、拉黑逻辑
- 提供视图调用接口
- 依赖 RS256 Azure Key Vault 签名器
- 支持 refresh token 延长机制
"""
import traceback # 打印详细异常信息
from typing import Dict, Literal, Optional
from django.conf import settings
from users.models import User # 自定义用户模型
from .jwt_payload import build_jwt_payload # 构造 Payload
from .jwt_signer import AzureRS256Signer # RS256签名器
from .jwt_verifier import AzureRS256Verifier # 封装的RS256验证器
from .jwt_blacklist import add_to_blacklist # 黑名单机制
from openai_chat.settings.utils.logging import get_logger # 日志记录器

logger = get_logger("jwt")

class TokenService:
    """
    JWT 令牌服务类
    - 签发 access & refresh token
    - 刷新 access token
    """
    HEADER = {"alg": "RS256", "typ": "JWT"}
    
    def __init__(self, user: User):
        self.user = user
        self.signer = AzureRS256Signer.get_instance()
    
    def _get_scope_for_user(self) -> str:
        """
        根据用户权限动态确定 access_token 的 scope 值
        """
        if self.user.is_superuser:
            return "super"
        elif self.user.is_staff:
            return "admin"
        return "user"
    
    def issue_tokens(self) -> Dict[Literal["access", "refresh"], str]:
        """
        签发 access + refresh token
        :return: {'access': xxx, 'refresh': yyy}
        """
        user_id = str(self.user.id)
        
        try:
            # 获取 access token 的权限范围
            access_scope = self._get_scope_for_user()
            
            # 构造 Access Token 载荷
            access_payload = build_jwt_payload(
                user_id=user_id,
                scope=access_scope,
                lifetime=settings.JWT_ACCESS_TOKEN_LIFETIME,
                token_type='access',
            )
            
            # 构造 Refresh Token 载荷(固定 scope 为 refresh)
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
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """
        根据已验证的 refresh_token payload 刷新新的 access_token
        :param refresh_payload: 解码后的payload, 必须包含 typ=refresh 和 sub 字段
        :return: 新的 access_token 字符串
        """
        logger.debug(f"[TokenService] 尝试刷新 access token, 传入refresh_token: {refresh_token}")
        
        # 令牌完整签名 + 黑名单 + 字段校验
        verifier = AzureRS256Verifier.get_instance()
        payload = verifier.verify(refresh_token)
        
        # 再次校验 typ 字段,确保传入的令牌类型只能为 refresh_token
        if payload.get("typ") != "refresh":
            raise ValueError("提供的Token并非Refresh类型")
        
        user_id = payload.get("sub")
        if not user_id:
            raise ValueError("RefreshToken缺少 sub 字段")
        
        try:
            self.user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise ValueError("对应用户不存在")
        
        # 动态获取用户权限
        scope = self._get_scope_for_user()
        
        # 构造新的 access token 载荷
        access_payload = build_jwt_payload(
            user_id=user_id,
            scope=scope,
            lifetime=settings.JWT_ACCESS_TOKEN_LIFETIME,
            token_type="access",
        )
        
        header = {"alg": "RS256", "typ": "JWT"}
        return self.signer.sign(header, access_payload)
    
class TokenRevoker:
    """
    JWT Token拉黑器
    - 统一处理 access/refresh token的注销拉黑
    - 支持日志记录 user_id 来源
    """
    def __init__(self, jti: str, exp: int, user_id: Optional[str] = None, token_type: str = "access"):
        """
        :param user_id: 用户ID(来自 token sub字段)
        :param jti: Token 唯一标识
        :param exp: Token 过期时间戳(秒)
        """
        self.user_id = user_id or "unknow"
        self.jti = jti
        self.exp = exp
        self.token_type = token_type
    
    def revoke_token(self) -> bool:
        """
        拉黑 token (如退出登录/被强制退出)
        :return: 是否成功加入黑名单
        """
        logger.info(f"[TokenRevoker] 用户 {self.user_id} 请求拉黑 {self.token_type} 令牌: jti={self.jti}, exp={self.exp}")
        return add_to_blacklist(self.jti, self.exp)