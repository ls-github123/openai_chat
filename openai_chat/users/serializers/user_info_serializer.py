"""
用户信息获取 - 响应序列化器
- GET /userinfo/
- 不接收任何请求参数
- 用户身份仅来源于 access token
"""
from __future__ import annotations
from typing import Any, Dict, cast
from rest_framework import serializers

class UserInfoResponseSerializer(serializers.Serializer):
    """
    用户信息响应序列化器(只读)
    
    设计原则:
    - 只做输出，不做输入校验
    - 作为 service -> View 的唯一数据出口
    """
    # 基础身份字段
    id = serializers.CharField()
    email = serializers.EmailField()
    
    # 展示字段
    username = serializers.CharField(
        allow_blank=True,
        allow_null=True,
    )
    
    # 状态字段(前端据此决定UI展示)
    is_active = serializers.BooleanField()
    totp_enabled = serializers.BooleanField()
    
    # 可选业务字段
    organization = serializers.CharField(
        allow_null=True,
        allow_blank=True,
    )
    
    @classmethod
    def from_service(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        serializer = cls(data=data)
        serializer.is_valid(raise_exception=True)
        return cast(Dict[str, Any], serializer.validated_data)