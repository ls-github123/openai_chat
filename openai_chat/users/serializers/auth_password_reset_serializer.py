from __future__ import annotations
import re
from typing import Any, Dict
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

User = get_user_model()

class PasswordResetRequestSerializer(serializers.Serializer):
    """
    密码重置申请 Serializer
    
    - 只校验入参格式
    - 不检查邮箱是否存在, 避免账号枚举
    - 业务逻辑交由 PasswordResetRequestService
    """
    email = serializers.EmailField(required=True)
    
    # Turnstile token 预留字段
    cf_token = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=4096,
    )
    
    def validate_email(self, value: str) -> str:
        """
        统一规范化邮箱:
        - 去除首尾空格
        - 转小写
        - 保证 Redis key / DB 查询 / 邮件发送使用同一份邮箱值
        """
        email = str(value or "").strip().lower()
        if not email:
            raise serializers.ValidationError("邮箱不能为空")
        return email
    
class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    密码重置确认 Serializer
    
    - 校验 email / verify_code / new_password / confirm_password
    - 使用 Django AUTH_PASSWORD_VALIDATORS 校验新密码强度
    - 不做验证码校验, 验证码校验交给 Service 层处理
    """
    email = serializers.EmailField(required=True)
    
    verify_code = serializers.CharField(
        required=True,
        min_length=6,
        max_length=6,
        trim_whitespace=True,
    )
    
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        max_length=128,
    )
    
    confirm_password = serializers.CharField(
        required=True,
        write_only=True,
        max_length=128,
    )
    
    def validate_email(self, value: str) -> str:
        """统一邮箱格式, 保持与申请阶段 Redis key 一致"""
        email = str(value or "").strip().lower()
        if not email:
            raise serializers.ValidationError("邮箱不能为空")
        return email
    
    def validate_verify_code(self, value: str) -> str:
        """
        验证码格式校验:
        - 只允许 6 位数字
        - 不在 Serializer 中判断正确性, 避免混入业务状态逻辑
        """
        code = str(value or "").strip()
        if not re.fullmatch(r"\d{6}", code):
            raise serializers.ValidationError("验证码格式错误")
        return code

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        new_password = str(attrs.get("new_password", ""))
        confirm_password = str(attrs.get("confirm_password", ""))
        email = str(attrs.get("email", ""))

        if new_password != confirm_password:
            raise serializers.ValidationError({
                "confirm_password": "两次输入的密码不一致"
            })

        # 关键位置:
        # 构造临时 user 传给 validate_password, 让 UserAttributeSimilarityValidator
        # 基于 email 等用户属性判断密码是否过于相似
        tmp_user = User(email=email)

        try:
            validate_password(password=new_password, user=tmp_user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({
                "new_password": exc.messages
            })
        
        return attrs