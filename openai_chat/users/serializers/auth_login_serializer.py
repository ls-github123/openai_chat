from rest_framework import serializers # DRF序列化器基类

class LoginSerializer(serializers.Serializer):
    """
    用户登录序列化器:
    - 校验邮箱与密码格式
    """
    email = serializers.EmailField(
        required=True,
        help_text="用户邮箱地址",
        max_length=64
    )
    
    password = serializers.CharField(
        required=True,
        write_only=True,
        min_length=8,
        max_length=128,
        help_text="用户密码(8-128位)"
    )
    
    def validate(self, attrs):
        """
        统一校验方法:
        - 验证邮箱与密码是否都填写
        """
        email = attrs.get("email")
        password = attrs.get("password")
        if not email or not password:
            raise serializers.ValidationError("邮箱和密码均为必填项")
        return attrs