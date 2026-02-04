"""
用户注册确认序列化器
- 校验并规范化 email/verify_code
- 生成稳定的 validated_data, 供 service / view 使用
"""
from typing import Any, Dict
from rest_framework import serializers # DRF 序列化器基类

class RegisterConfirmSerializer(serializers.Serializer):
    """
    用户注册确认入参序列化器
    校验参数:
    - email: 用户邮箱(必填, EmailField校验)
    - verify_code: 邮箱验证码(必填)
    """
    email = serializers.EmailField(required=True, allow_blank=False)
    verify_code = serializers.CharField(required=True, allow_blank=False, max_length=32)
    
    def validate_email(self, value: str) -> str:
        """
        标准化 email:
        - 去空格
        - 转小写
        """
        email = value.strip().lower()
        if not email:
            raise serializers.ValidationError("邮箱不能为空")
        return email
    
    def validate_verify_code(self, value: str) -> str:
        """
        标准化 verify_code:
        - 去空格
        - 可选: 限制只允许数字
        """
        code = value.strip()
        
        if not code:
            raise serializers.ValidationError("验证码不能为空")
        
        if not code.isdigit():
            raise serializers.ValidationError("验证码格式错误")
        
        if len(code) != 6: # 验证码长度必须为6位
            raise serializers.ValidationError("验证码长度错误")
        
        return code
    
    def to_internal_value(self, data: Any) -> Dict[str, Any]:
        """
        保持 DRF 默认行为, 显式保留入口, 便于后续扩展
        """
        return super().to_internal_value(data)