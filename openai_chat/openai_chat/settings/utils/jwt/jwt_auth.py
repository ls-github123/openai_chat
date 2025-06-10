"""
JWT 鉴权认证模块: 自定义DRF认证器
- 使用 Azure Key Vault 公钥进行 RS256 Token 验证
- Token 从请求 Header 中提取: Authorization: Bearer <token>
- 验证签名、有效期、sub字段映射用户对象
"""
import re
from typing import Tuple, Optional
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import AbstractBaseUser
from .verifier import AzureRS256Verifier # 封装的RS256验证器
from users.models import User # 用户数据库模型

class JWTAuthentication(BaseAuthentication):
    """
    自定义 JWT 认证类: 用于 REST Framework 接口
    - 从请求中提取 JWT Token 并验证
    - 验证通过后返回 (用户实例, token字符串)
    """
    def authenticate(self, request) -> Optional[Tuple[AbstractBaseUser, str]]:
        """
        DRF认证入口方法
        :param request: 当前请求对象
        :return: Tuple(用户实例, token字符串) 或 None
        """
        # 从请求头中提取 Authorization 字段
        auth_header = request.headers.get("Authorization", "")
        match = re.match(r"^Bearer\s+(.+)$",auth_header)
        
        if not match:
            return None # 没有提供有效 token 则跳过认证, 交其他认证器处理
        
        token = match.group(1)
        
        try:
            # 获取单例 verifier 实例, 执行 token 验证
            verifier = AzureRS256Verifier.get_instance()
            payload = verifier.verify(token)
            
            # 从 payload 中提取 sub (用户ID)
            user_id = payload.get("sub")
            
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise AuthenticationFailed("用户不存在")
            
            return user, token # DRF 认证机制要求的返回格式
        
        except Exception as e:
            raise AuthenticationFailed(str(e)) # 返回 401 Unauthorized