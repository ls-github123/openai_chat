from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from users.serializers.token_refresh_serializer import TokenRefreshSerializer
from openai_chat.settings.utils.jwt.jwt_token_service import TokenRefreshService
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response # 标准统一响应封装
from typing import cast, Any

logger = get_logger("users")

class TokenRefreshView(APIView):
    """
    用户令牌刷新视图
    - 接收 refresh token 字符串
    - 调用 TokenRefreshService 完成校验、黑名单加入及新令牌签发
    - 返回新 access_token 与 refresh_token
    """
    permission_classes = [AllowAny] # 允许未认证用户调用(无需 access token)
    
    def post(self, request):
        # 1.参数验证
        serializer = TokenRefreshSerializer(data=request.data)
        if not serializer.is_valid():
            errors: Any = serializer.errors
            logger.error(f"[TokenRefreshView] 请求参数验证失败: {errors}")
            return json_response(code=400, msg="参数格式有误", data={"errors": errors})
        
        # 2. 获取 refresh token 字符串
        validated_data = cast(dict[str, Any], serializer.validated_data)
        refresh_token: str = validated_data["refresh"]
        
        try:
            # 3.调用服务类刷新令牌
            service = TokenRefreshService(refresh_token)
            tokens: dict[str, str] = service.refresh_access_token()
            return json_response(code=200, msg="令牌刷新成功", data=tokens)
        
        except ValueError as ve:
            logger.warning(f"[TokenRefreshView] 校验失败: {ve}")
            return json_response(code=401, msg=str(ve))
        
        except Exception as e:
            logger.error(f"[TokenRefreshView] 令牌刷新失败: {e}")
            return json_response(code=500, msg="服务器内部错误, 请稍后重试")