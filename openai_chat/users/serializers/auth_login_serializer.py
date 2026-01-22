from rest_framework import serializers # DRF序列化器基类

class LoginSerializer(serializers.Serializer):
    """
    用户登录序列化器:
    - 仅做基础格式校验(登录阶段避免过度约束)
    """
    email = serializers.EmailField(
        required=True,
        help_text="用户邮箱地址",
        max_length=254
    )
    
    password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        max_length=1024, # 与 Service 层 MAX_PASSWORD_LEN 对齐
        trim_whitespace=False, # 密码不做 strip/trim
        help_text="用户密码"
    )