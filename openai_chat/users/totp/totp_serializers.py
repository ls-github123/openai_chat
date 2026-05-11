# === TOTP 序列化器模块 ===
"""
TOTP serializer 只负责 请求字段格式校验

边界:
- 不在 serializer 中校验 TOTP secret 是否存在
- 不在 serializer 中校验 TOTP 动态码是否正确
- 不在 serializer 中校验 TOTP 动态码是否正确
"""
from __future__ import annotations
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _

class TOTPEnableSerializer(serializers.Serializer):
    """
    启用 TOTP 初始化接口 serializer
    
    当前接口不需要请求体字段
    - 用户身份来自 access token
    - service 层根据当前用户生成预绑定二维码
    
    保留该 serializer 目的:
    - 使 view 层保持统一结构
    - 后续如需加入 password_confirm、device_name、csrf nonce 等字段时可直接扩展
    """
    pass

class TOTPVerifySerializer(serializers.Serializer):
    """
    TOTP 绑定确认 / 解绑接口 serializer
    
    只校验 token 格式:
    - 必填
    - 去除首尾空白
    - 必须是 6 位纯数字
    """
    token = serializers.CharField(
        max_length=6,
        min_length=6,
        required=True,
        allow_blank=False,
        trim_whitespace=True,
        help_text=_("6位动态验证码"),
        label=_("验证码"),
    )
    
    def validate_token(self, value: str) -> str:
        """
        字段级格式校验
        """
        token = str(value or "").strip()
        
        if not token.isdigit():
            raise serializers.ValidationError(_("验证码必须为纯数字"))
        
        if len(token) != 6:
            raise serializers.ValidationError(_("验证码必须为6位"))
        
        return token
    
class TOTPLoginVerifySerializer(serializers.Serializer):
    """
    登录阶段二 TOTP serializer
    
    字段:
    - challenge_id:
      登录阶段一返回的预登录挑战 ID
    - totp_code:
      用户提交的 6 位动态验证码
    
    边界:
    - 这里只校验字段格式
    - challenge_id 是否存在、是否过期、是否匹配用户, 由 LoginTOTPVerifyService 校验
    - totp_code 是否正确, 由 verify_login_totp() 校验
    """
    challenge_id = serializers.CharField(
        required=True,
        allow_blank=False,
        trim_whitespace=True,
        max_length=128,
        help_text=_("登录阶段一返回的challenge_id"),
        label=_("登录挑战ID"),
    )
    
    totp_code = serializers.CharField(
        max_length=6,
        min_length=6,
        required=True,
        allow_blank=False,
        trim_whitespace=True,
        help_text=_("6位动态验证码"),
        label=_("验证码"),
    )
    
    def validate_challenge_id(self, value: str) -> str:
        """
        challenge_id 基础格式校验
        
        注:
        - 不在 serializer 里查 Redis pending
        - 只做最基础的空值和长度收敛
        """
        challenge_id = str(value or "").strip()
        
        if not challenge_id:
            raise serializers.ValidationError(_("登录挑战ID不能为空"))
        
        if len(challenge_id) > 128:
            raise serializers.ValidationError(_("登陆挑战ID长度非法"))
        
        return challenge_id
    
    def validate_totp_code(self, value: str) -> str:
        """
        TOTP 登录验证码格式校验
        """
        code = str(value or "").strip()
        
        if not code.isdigit():
            raise serializers.ValidationError(_("验证码必须为纯数字"))
        
        if len(code) != 6:
            raise serializers.ValidationError(_("验证码必须为6位"))
        
        return code