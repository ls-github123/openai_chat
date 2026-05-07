from __future__ import annotations
"""
用户退出登录视图

职责:
- 接收前端提交的 access_token / refresh_token
- 若请求头携带 Authorization: Bearer <access_token>，可自动补充 access_token
- 使用 LogoutSerializer 做基础参数校验
- 调用 LogoutService 执行退出逻辑（拉黑 access + refresh）
- 最终统一返回 json_response

说明:
- 退出接口不依赖 IsAuthenticated，避免 access 已过期/已拉黑时无法撤销 refresh
- 当前实现要求前端显式传入 refresh_token，access_token 可来自请求体或 Authorization 头
- 视图层不直接处理 JWT 业务细节，仅负责调用序列化器与服务类
"""
import re
from collections.abc import Mapping
from typing import Any, Dict, cast
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from openai_chat.settings.utils.response_wrapper import json_response
from openai_chat.settings.utils.error_codes import ErrorCodes # 统一错误码

from users.serializers.logout_serializer import LogoutSerializer # 退出登录序列化器
from users.services.logout_service import LogoutService, LogoutCommand # 退出登录服务类/命令对象
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("users")

class LogoutView(APIView):
    """
    用户退出登录视图:
    说明：
    - 不走默认 JWTAuthentication，避免已过期 access 阻断退出流程
    - 当前实现仍要求前端显式传入 refresh_token；access_token 可通过 Authorization 头传入
    - 视图层不直接处理 JWT 业务，仅负责参数接收、调用 service、返回响应
    """
    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    _bearer_re = re.compile(r"^Bearer\s+(.+)$", re.IGNORECASE)

    def post(self, request: Request) -> Response:
        """
        处理用户退出登录请求
        """
        data = self._request_data_with_header_access(request)

        # 入参校验
        serializer = LogoutSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        validated: Dict[str, Any] = cast(Dict[str, Any], serializer.validated_data)

        access_token: str | None = validated.get("access_token")
        refresh_token: str | None = validated.get("refresh_token")
        logger.info(
            "[LogoutView] token inputs has_access=%s has_refresh=%s",
            bool(access_token),
            bool(refresh_token),
        )

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
            data={},
            http_status=status.HTTP_200_OK,
        )

    @classmethod
    def _extract_bearer_token(cls, request: Request) -> str | None:
        auth_header = str(request.headers.get("Authorization", ""))
        meta = getattr(request, "META", {})
        if not auth_header:
            auth_header = str(meta.get("HTTP_AUTHORIZATION", ""))
        if not auth_header:
            auth_header = str(meta.get("REDIRECT_HTTP_AUTHORIZATION", ""))

        match = cls._bearer_re.match(auth_header)
        if not match:
            return None

        token = match.group(1).strip()
        return token or None

    @classmethod
    def _request_data_with_header_access(cls, request: Request) -> Dict[str, Any]:
        raw_data = cast(Any, request.data)
        data: Dict[str, Any] = dict(raw_data.items()) if isinstance(raw_data, Mapping) else {}
        if not data.get("access_token"):
            header_access = cls._extract_bearer_token(request)
            if header_access:
                data["access_token"] = header_access
        return data
