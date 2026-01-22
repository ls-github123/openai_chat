from __future__ import annotations
from typing import Any, Dict
from rest_framework import serializers # serializer 定义入参字段, 校验规则与错误信息组织方式

# === Django 导入: 复用 AUTH_PASSWORD_VALIDATORS 的官方校验入口 ===
from django.contrib.auth import get_user_model # 获取当前User模型(用于构造临时 user 实例供密码校验器使用)
# validate_password：按 settings.AUTH_PASSWORD_VALIDATORS 执行所有密码校验器
from django.contrib.auth.password_validation import validate_password
# Django 的 ValidationError：validate_password 抛出的异常类型
from django.core.exceptions import ValidationError as DjangoValidationError

User = get_user_model() # 当前项目的User模型

class RegisterPreSerializer(serializers.Serializer):
    """
    用户预注册 Serializer
    - 只做输入校验(字段类型/长度/格式/密码强度等)
    - 不负责业务流程/逻辑
    - 校验失败抛出 serializers.ValidationError
      - DRF 统一捕获并交由 custom_exception_handler
      - 输出统一五段式错误结构
    """
    # 邮箱字段:
    # -EmailField: 内置邮箱格式校验(包含@\域名合法性等)
    # - required=True 必须提供
    email = serializers.EmailField(required=True)
    
    # 密码字段
    # - CharField：字符串字段
    # - write_only=True：序列化输出时不回传该字段（避免泄露）
    # - max_length：限制最大长度，防止超大 payload（接口安全）
    password = serializers.CharField(
        required=True,
        write_only=True,
        max_length=128,
    )
    
    # 手机号字段(可选):
    # - 不做格式强校验
    phone_number = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=32,
    )
    
    # Turnstile token(预留字段)
    # - 测试阶段不启用校验
    cf_token = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=4096,
    )
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        对象级校验
        - 执行密码强度校验
        """
        password = attrs.get("password", "")
        email = attrs.get("email", "")
        phone_number = attrs.get("phone_number", "")
        
        # 构造临时 user 对象
        # 目的：让 UserAttributeSimilarityValidator 能拿到 email/phone_number 做相似度判断
        tmp_user = User(email=email)
        
        # 兼容: 若User模型没有 phone_number字段, 这里不会报错
        setattr(tmp_user, "phone_number", phone_number)
        
        try:
            # validate_password 读取 settings.AUTH_PASSWORD_VALIDATORS 并逐个执行
            validate_password(password=password, user=tmp_user)
        except DjangoValidationError as e:
            # 将密码错误挂到 password 字段中, 便于前端精准展示
            raise serializers.ValidationError({"password": e.messages})
        
        return attrs