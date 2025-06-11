# === TOTP 序列化器模块 ===
# 封装启用和验证动态口令逻辑
from rest_framework import serializers # DRF 序列化器基类
from django.contrib.auth import get_user_model # 获取当前用户模型
from django.utils.translation import gettext_lazy as _ # 国际化支持(错误信息可翻译)
from users.totp.totp_utils import verify_totp_token # 导入totp验证函数

User = get_user_model() # 获取自定义用户模型类

# === 启用TOTP 接口序列化器(只返回二维码, 无字段校验) ===
class TOTPEnableSerializer(serializers.Serializer):
    """
    启用阶段序列化器(校验请求合法性, 无字段输入校验)
    扩展: 校验请求来源、请求时间、签名等
    """
    pass

# === 校验用户输入验证码, 启用TOTP功能 ===
class TOTPVerifySerializer(serializers.Serializer):
    token = serializers.CharField(
        max_length=6, 
        required=True, 
        help_text=_("用户输入的6位验证码"),
        label=_("验证码")
    )
    
    def validate_token(self, value):
        """ 格式校验, 必须为6位数字 """
        if not value.isdigit():
            raise serializers.ValidationError(_("验证码必须为纯数字"))
        if len(value) != 6:
            raise serializers.ValidationError(_("验证码长度必须等于6位"))
        return value
    
    def validate(self, attrs):
        user = self.context['request'].user # # 获取当前登录用户对象(从 DRF 的上下文中提取 request)
        token = attrs.get("token") # 获取用户提交的验证码字段(已通过字段级别校验)
        
        # 校验用户是否已经生成 secret
        if not user.totp_secret:
            raise serializers.ValidationError(_("当前用户尚未生成 TOTP 密钥"))
        
        # 校验验证码是否正确
        if not verify_totp_token(user.totp_secret, token):
            raise serializers.ValidationError(_("验证码错误或已过期"))
        
        return attrs