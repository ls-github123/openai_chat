from __future__ import annotations
"""
用户退出登录序列化器
- 接收 access_token / refresh_token
- 至少要求传入一个 token
- 仅做基础参数校验, 不校验JWT
- 具体业务逻辑由 LogoutService 处理
"""
from typing import Any
from rest_framework import serializers
from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException

class LogoutSerializer(serializers.Serializer):
    """
    用户退出登录序列化器
    
    字段说明:
    - access_token: 当前访问令牌(可选)
    - refresh_token: 当前刷新令牌(可选)
    """
    access_token = serializers.CharField(
        required=False,
        allow_blank=True,
        trim_whitespace=True,
        write_only=True,
        help_text="访问令牌",
    )
    
    refresh_token = serializers.CharField(
        required=False,
        allow_blank=True,
        trim_whitespace=True,
        write_only=True,
        help_text="刷新令牌",
    )
    
    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """
        全局校验:
        - access_token / refresh_token 至少传入一个
        - 将空字符串统一清洗为 None, 便于后续 service 层直接使用
        """
        access_token = (attrs.get("access_token") or "").strip()
        refresh_token = (attrs.get("refresh_token") or "").strip()
        
        # 至少需要一个 token
        if not access_token and not refresh_token:
            raise AppException.bad_request(
                code=ErrorCodes.AUTH_TOKEN_MISSING,
                message="access_token 与 refresh_token 不能同时为空",
            )
        
        # 统一清洗, 避免 service 层重复处理空白字符串
        attrs["access_token"] = access_token or None
        attrs["refresh_token"] = refresh_token or None
        
        return attrs