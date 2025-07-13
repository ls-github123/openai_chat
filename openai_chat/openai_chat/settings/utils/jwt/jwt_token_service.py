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
from openai_chat.settings.utils.token_helpers import get_scope_for_user # 动态获取用户权限范围

logger = get_logger("jwt")
HEADER = {"alg": "RS256", "typ": "JWT"}

class TokenIssuerService:
    """
    JWT 令牌签发服务类
    - 首次签发 access & refresh token
    - 动态获取用户权限 scope
    """
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
            # 获取 access token 的权限范围
            access_scope = get_scope_for_user(self.user)
            
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
            access_token = self.signer.sign(HEADER, access_payload)
            refresh_token = self.signer.sign(HEADER, refresh_payload)
            
            return {
                "access": access_token,
                "refresh": refresh_token
            }
            
        except Exception as e:
            logger.error(f"[TokenService] 令牌签发失败: {traceback.format_exc()}")
            raise RuntimeError("令牌签发失败, 请稍后重试")
    
class TokenRefreshService:
    """
    JWT令牌刷新服务类
    - 根据已验证的 refresh_token 刷新新的 access_token
    - 支持滑动更新 refresh token
    """
    def __init__(self, refresh_token: str):
        """
        初始化JWT令牌刷新服务
        """
        self.refresh_token = refresh_token
        self.signer = AzureRS256Signer.get_instance()
        self.verifier = AzureRS256Verifier.get_instance()
    
    def _get_user(self, user_id: str) -> User:
        """
        根据用户ID获取用户对象
        """
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            logger.error(f"[TokenRefreshService] 用户{user_id}不存在, 无法刷新令牌")
            raise ValueError("用户不存在, 无法刷新令牌")
    
    def refresh_access_token(self) -> Dict[str, str]:
        """
        根据已验证的 refresh_token payload 刷新新的 access_token
        :param refresh_payload: 解码后的payload, 必须包含 typ=refresh 和 sub 字段
        :return: 新的 access_token 字符串, 新的 refresh token 字符串
        """
        try:
            # 令牌完整签名 + 黑名单 + 字段校验
            payload = self.verifier.verify(self.refresh_token)
        except Exception:
            logger.warning(f"[TokenRefreshService] Refresh Token 验证失败: {traceback.format_exc()}")
            raise ValueError("Refresh Token 无效或已过期")
        
        # 再次校验 typ 字段,确保传入的令牌类型只能为 refresh_token
        token_type = payload.get("typ")
        if token_type != "refresh":
            logger.critical(f"[TokenRefreshService] 非法Token类型: {token_type}, 期望 refresh")
            raise ValueError("提供的Token非Refresh类型")
        
        user_id = payload.get("sub")
        jti = payload.get("jti")
        exp = payload.get("exp")
        if not user_id or not jti or not exp:
            raise ValueError("RefreshToken缺少关键字段(sub/jti/exp)")
        
        # 确认用户是否存在
        self.user = self._get_user(user_id)
        
        # 确认用户存在后, 将原来的 token 加入黑名单
        revoker = TokenRevoker(jti=jti, exp=exp, user_id=user_id, token_type="refresh")
        if not revoker.revoke_token():
            logger.error(
                f"[TokenRefreshService] 原Refresh Token加入黑名单失败: jti={jti}, user_id={user_id}"
            )
            raise RuntimeError("Refresh Token注销失败, 请稍后重试")
        
        # 动态获取用户权限
        scope = get_scope_for_user(self.user)
        
        # 构造新的 access token 载荷
        new_access_payload = build_jwt_payload(
            user_id=user_id,
            scope=scope,
            lifetime=settings.JWT_ACCESS_TOKEN_LIFETIME,
            token_type="access",
        )
        new_access_token = self.signer.sign(HEADER, new_access_payload)
        
        # 构造新的 refresh token 载荷(滑动更新)
        new_refresh_payload = build_jwt_payload(
            user_id=user_id,
            scope="refresh", # 固定标记 refresh 类型作用域
            lifetime=settings.JWT_REFRESH_TOKEN_LIFETIME,
            token_type="refresh",
        )
        new_refresh_token = self.signer.sign(HEADER, new_refresh_payload)
        
        return {
            "access": new_access_token,
            "refresh": new_refresh_token
        }

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
        self.user_id = user_id or "unknown"
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