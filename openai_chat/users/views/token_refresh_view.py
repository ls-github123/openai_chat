from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework import status
from users.serializers.token_refresh_serializer import TokenRefreshSerializer
from openai_chat.settings.utils.jwt.jwt_token_service import TokenRefreshService
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response # 标准统一响应封装
from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException
from typing import cast, Any

logger = get_logger("users")

class TokenRefreshView(APIView):
    """
    用户令牌刷新视图
    - 接收 refresh token 字符串
    - 调用 TokenRefreshService 完成校验并签发新的 access token
    - refresh token 保持不变，不随刷新接口返回
    """
    authentication_classes: list[Any] = []
    permission_classes = [AllowAny] # 允许未认证用户调用(无需 access token)
    
    def post(self, request):
        # 1.参数验证
        serializer = TokenRefreshSerializer(data=request.data)
        if not serializer.is_valid():
            errors: Any = serializer.errors
            logger.error(f"[TokenRefreshView] 请求参数验证失败: {errors}")
            return json_response(
                success=False,
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message="参数格式有误",
                data={"errors": errors},
                http_status=status.HTTP_400_BAD_REQUEST,
            )
        
        # 2. 获取 refresh token 字符串
        validated_data = cast(dict[str, Any], serializer.validated_data)
        refresh_token: str = validated_data["refresh"]
        
        try:
            # 3.调用服务类刷新令牌
            service = TokenRefreshService(refresh_token)
            tokens: dict[str, str] = service.refresh_access_token()
            return json_response(
                success=True,
                code=ErrorCodes.SUCCESS,
                message="令牌刷新成功",
                data=tokens,
                http_status=status.HTTP_200_OK,
            )
        
        except AppException as exc:
            logger.warning("[TokenRefreshView] 校验失败: code=%s message=%s", exc.code, exc.message)
            return json_response(
                success=False,
                code=exc.code,
                message=exc.message,
                data=exc.data,
                http_status=exc.http_status,
            )
        
        except Exception as e:
            logger.error(f"[TokenRefreshView] 令牌刷新失败: {e}")
            return json_response(
                success=False,
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="服务器内部错误, 请稍后重试",
                data=None,
                http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
