from __future__ import annotations
from rest_framework import serializers # DRF序列化器基类

class LoginSerializer(serializers.Serializer):
    """
    用户登录序列化器
    - email: 标准 EmailField 格式 + 最大长度限制
    - password: 不做 trim，限制最大长度，最小长度不强行约束
    """
    email = serializers.EmailField(
        required=True,
        allow_blank=False, # 禁止空字符串
        max_length=254,
        help_text="用户邮箱地址",
    )
    
    password = serializers.CharField(
        required=True,
        allow_blank=False, # 明确禁止空字符串
        write_only=True, # 避免序列化输出泄露
        max_length=1024,
        trim_whitespace=False, # 密码不做 strip/trim
        style={"input_type": "password"},  # DRF Browsable API 展示用(不影响接口)
        help_text="用户密码",
    )
    
    def validate_email(self, value: str) -> str:
        """
        规范化 email:
        - strip：去除首尾空格，防止“同一邮箱多形态”
        - lower：避免大小写造成的重复形态
        """
        email = (value or "").strip()
        if not email:
            raise serializers.ValidationError("email required")
        if len(email) > 254:
            raise serializers.ValidationError("email too long")
        return email.lower()
    
    def validate_password(self, value: str) -> str:
        """
        密码校验原则:
        - 不做 strip(trim_whitespace=False 已保证)
        - 不强制 min_length
        - 仅做空值与最大长度防御
        """
        if value is None:
            raise serializers.ValidationError("password required")
        
        if value == "":
            raise serializers.ValidationError("password required")
        
        if len(value) > 1024:
            raise serializers.ValidationError("password too long")
        
        return value