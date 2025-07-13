from rest_framework import serializers

class TokenRefreshSerializer(serializers.Serializer):
    """
    令牌刷新序列化器
    - 接收 refresh token
    - 仅进行基本格式校验
    - 实际刷新逻辑由服务类 TokenRefreshService 处理
    """
    refresh = serializers.CharField(
        required=True, # 必须提供 refresh 字段
        help_text="原 refresh token", # 用于DRF自动文档
        error_messages={ # 自定义错误提示信息
            "blank": "refresh token 不能为空",
            "required": "请提供 refresh token"
        }
    )
    
    def validate_refresh(self, value: str) -> str:
        """
        校验 refresh token 合法性
        - 类型为字符串
        - 非空
        - 实际签名/黑名单/过期判断由服务类完成
        """
        value = value.strip() # 去除首尾空格
        if not value or not isinstance(value, str):
            raise serializers.ValidationError("Refresh token 不合法")
        return value