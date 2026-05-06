from __future__ import annotations
"""
用户退出登录视图

职责:
- 接收前端提交的 access_token / refresh_token
- 使用 LogoutSerializer 做基础参数校验
- 调用 LogoutService 执行退出逻辑（拉黑 access + refresh）
- 最终统一返回 json_response

说明:
- 当前实现要求用户已登录（IsAuthenticated）
- 当前实现要求前端显式传入 access_token 与/或 refresh_token
- 视图层不直接处理 JWT 业务细节，仅负责调用序列化器与服务类
"""
from typing import Any, Dict, cast
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from openai_chat.settings.utils.response_wrapper import json_response
from openai_chat.settings.utils.exceptions import AppException # 统一业务异常
from openai_chat.settings.utils.error_codes import ErrorCodes # 统一错误码

from users.serializers.logout_serializer import LogoutSerializer # 退出登录序列化器
from users.services.logout_service import LogoutService, LogoutCommand # 退出登录服务类/命令对象
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("users")

class LogoutView(APIView):
    """
    用户退出登录视图:
    说明：
    - 要求用户已通过认证（IsAuthenticated）
    - 当前实现仍要求前端显式传入 access_token / refresh_token
    - 视图层不直接处理 JWT 业务，仅负责参数接收、调用 service、返回响应
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """
        处理用户退出登录请求
        """
        try:
            # 入参校验
            serializer = LogoutSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            validated: Dict[str, Any] = cast(Dict[str, Any], serializer.validated_data)
            
            access_token: str | None = validated.get("access_token")
            refresh_token: str | None = validated.get("refresh_token")
            
            # 构造命令对象, 由 service 层处理业务逻辑
            cmd = LogoutCommand(
                access_token=access_token,
                refresh_token=refresh_token,
            )
            
            # 调用 service
            service = LogoutService(cmd=cmd)
            service.execute()
            
            # 成功响应
            return json_response(
                success=True,
                code=ErrorCodes.SUCCESS,
                message="安全退出成功",
                data=None,
                http_status=status.HTTP_200_OK,
            )
        
        except AppException as e:
            logger.warning(
                "[LogoutView] logout failed by app exception: code=%s, message=%s",
                e.code,
                e.message,
            )
            return json_response(
                success=False,
                code=e.code,
                message=e.message,
                data=getattr(e, "data", None),
                http_status=getattr(e, "http_status", status.HTTP_400_BAD_REQUEST),
            )
        
        except Exception as e:
            logger.error("[LogoutView] logout failed by unexpected exception: err=%r", e)
            return json_response(
                success=False,
                code=ErrorCodes.COMMON_ERROR,
                message="安全退出登录失败, 请稍后重试",
                data=None,
                http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )