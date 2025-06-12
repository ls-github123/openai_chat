from rest_framework import serializers # DRF序列化器基类
from users.models import User # 导入自定义用户模型
from django.contrib.auth.password_validation import validate_password # 密码强度验证器
from django.core.validators import RegexValidator # 导入正则验证器
from typing import Dict, Any
class RegisterSerializer(serializers.ModelSerializer):
    """
    用户注册序列化器:
    - email: 唯一登录凭证(必填)
    - phone_number: 用户手机号(选填)
    - password: 用户密码(必填)
    - password_confirm: 确认密码一致性(必填)
    """
    # 密码确认字段, 用于校验是否一致(不保存)
    password_confirm = serializers.CharField(
        write_only=True, 
        min_length=8, 
        max_length=64, 
        label="确认密码"
    )
    
    # 密码字段(写入时验证强度但不返回)
    password = serializers.CharField(
        write_only = True,
        min_length=8,
        max_length=64,
        validators=[validate_password], # 自动应用Django密码强度验证器
        label="密码"
    )
    
    # 手机号字段校验
    phone_number = serializers.CharField(
        required=False, # 可为空
        allow_blank=True, # 可传空字符串
        validators=[ # 正则校验规则
            RegexValidator(
                regex=r"^1[3-9]\d{9}$",
                message="手机号格式不正确, 应为长度11位的纯数字字符串(数字1开头)"
            )
        ],
        label = "手机号"
    )
    
    # 使用 EmailField 自动校验邮箱格式
    email = serializers.EmailField(
        required=True, # 不可为空
        allow_blank=False, # 不可传空字符串
        label="邮箱"
    )
    
    class Meta:
        model = User # 指定模型类
        fields = ['email', 'password', 'password_confirm', 'phone_number'] # 序列化字段
        
    def validate(self, attrs):
        """
        校验密码一致性
        - (password == password_confirm)
        """
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("两次输入的密码不一致")
        return attrs
    
    def get_cleaned_data(self) -> Dict[str, Any]:
        """
        清洗后数据返回 Service 层调用(密码不加密)
        """
        validated = getattr(self, "validated_data", None)
        if not isinstance(validated, dict):
            return {}
        
        # 显式转换 key 为 str，防止 Pylance 类型冲突
        data = {str(k): v for k, v in validated.items()}
        data.pop("password_confirm", None)
        return data