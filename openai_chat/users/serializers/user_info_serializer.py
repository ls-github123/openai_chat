"""
用户信息获取 - 响应序列化器
- GET /userinfo/
- 不接收用户提交的业务参数
- 用户身份仅来源于 access token
"""
from __future__ import annotations
from typing import Any, Dict, Mapping, cast
from rest_framework import serializers

class UserInfoResponseSerializer(serializers.Serializer):
    """
    用户信息响应序列化器(只读)
    
    设计原则:
    - 只做输出响应整型，不做输入校验
    - 不输出 password / totp_secret / is_staff / is_superuser 等敏感或权限实现细节
    - 作为 service -> View 的唯一数据出口
    - 所有 ID 类字段使用字符串，避免前端 JavaScript 大整数精度丢失
    """
    # 基础身份字段
    id = serializers.CharField(
        required=True,
        allow_blank=False,
        help_text="用户ID, 字符串格式",
    )
    
    email = serializers.EmailField(
        required=True,
        allow_blank=False,
        help_text="用户邮箱",
    )
    
    # 展示字段
    username = serializers.CharField(
        required=True,
        allow_blank=True,
        allow_null=False,
        help_text="用户名，可为空字符串",
    )
    
    # 状态字段(前端据此决定UI展示)
    is_active = serializers.BooleanField(
        required=True,
        help_text="账户是否启用",
    )
    
    totp_enabled = serializers.BooleanField(
        required=True,
        help_text="是否已启用TOTP二次验证",
    )
    
    # 可选业务字段
    organization = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        help_text="组织ID，字符串格式；无组织时为null",
    )
    
    @classmethod
    def allowed_fields(cls) -> set[str]:
        """
        返回允许输出的字段集合
        - UserInfoService 的缓存白名单应保持一致
        """
        return {
            "id",
            "email",
            "username",
            "is_active",
            "totp_enabled",
            "organization",
        }
    
    @classmethod
    def normalize_service_data(cls, data: Mapping[str, Any]) -> Dict[str, Any]:
        """
        将 service 返回值规整为 serializer 可校验的结构

        关键点:
        - 只保留白名单字段，避免 service/cache 中混入敏感字段后被透传
        - organization 缺失时补 None，保持响应结构稳定
        """
        normalized = {
            key: data[key]
            for key in cls.allowed_fields()
            if key in data
        }

        normalized.setdefault("organization", None)
        return normalized
    
    @classmethod
    def from_service(cls, data: Mapping[str, Any] | None) -> Dict[str, Any]:
        """
        从 UserInfoService 输出构造最终响应数据

        返回:
        - service 返回空对象 / None: {}
        - service 返回用户信息: 经过字段白名单过滤和 DRF 校验后的 dict

        注意:
        - serializer 校验失败会抛 serializers.ValidationError
        - 项目全局异常处理器会统一转换为五段式响应
        """
        if not data:
            return {}

        normalized = cls.normalize_service_data(data)
        serializer = cls(data=normalized)
        serializer.is_valid(raise_exception=True)
        return cast(Dict[str, Any], serializer.validated_data)