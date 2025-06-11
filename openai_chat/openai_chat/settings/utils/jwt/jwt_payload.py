"""
JWT Payload 构造模块
- 提供统一函数用于构造标准化 JWT Payload
- 包括签发时间、过期时间、签发者、受众、权限范围等字段
- 后续签名模块可直接调用该方法生成 payload
"""
import time
import uuid
from typing import Dict, Optional
from django.conf import settings

def build_jwt_payload(user_id: str, scope: Optional[str] = None, lifetime: Optional[int] = None, token_type: str = "access") -> Dict:
    """
    构造 JWT 标准载荷 Payload
    :param user_id: 用户唯一标识(用户ID)
    :param scope: 权限范围(如: 'user', 'admin', 'superuser')
    :param lifetime: 有效期(秒)默认读取 settings.JWT_ACEES_TOKEN_LIFETIME
    :param token_type: JWT类型(如"access"或"refresh"),影响有效期与权限
    :return: dict 格式 JWT Payload
    """
    now = int(time.time()) # 当前时间戳(单位:秒)
    
    # 动态获取有效期(若未显式)
    if lifetime is None:
        if token_type == "access":
            lifetime = getattr(settings, "JWT_ACCESS_TOKEN_LIFETIME", 300) # 默认300秒
        elif token_type == "refresh":
            lifetime = getattr(settings, "JWT_REFRESH_TOKEN_LIFETIME", 86400) # 默认24小时
        else:
            raise ValueError("token_type 必须是 'access'或 'refresh'")
    
    # 显式断言, 确保 lifetime 一定为 int 类型(避免类型检查器报错)
    assert isinstance(lifetime, int), "lifetime 必须为 int 类型"
    
    return {
        "sub": str(user_id), # 用户身份标识(subject),
        "iat": now, # 签发时间(issued at), 用于标记令牌生成的时间点
        "exp": now + lifetime, # 过期时间(当前时间 + 生命周期)
        "iss": getattr(settings, "JWT_ISSUER", "openai_chat"), # 签发者标识
        "aud": getattr(settings, "JWT_AUDIENCE", "openai_chat_users"), # 接收方标识
        "scope": scope or getattr(settings, "JWT_SCOPE_DEFAULT", "user"), # 权限范围(默认user)
        "jti": str(uuid.uuid4()), # JWT 唯一ID(防止重放)
        "typ": token_type, # 令牌类型(access/refresh)
    }