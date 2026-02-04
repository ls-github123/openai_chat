from typing import Any, Dict, cast
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.request import Request

from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response
from openai_chat.settings.utils.error_codes import ErrorCodes

from users.serializers.auth_register_confirm_serializer import RegisterConfirmSerializer
from users.services.register_confirm_service import ConfirmRegisterService

logger = get_logger("users")

class RegisterConfirmView(APIView):
    """
    用户注册确认视图:
    - serializer 校验 email / verify_code
    - 读取请求头 Idempotency-Key
    - 调用 ConfirmRegisterService.execute_confirm()
    """
    permission_classes = [AllowAny]
    
    def post(self, request: Request):
        # 入参校验
        serializer = RegisterConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated: Dict[str, Any] = cast(Dict[str, Any], serializer.validated_data)
        
        email: str = validated["email"]
        verify_code: str = validated["verify_code"]
        
        # 幂等 key 校验(强制要求)
        idem_key = request.headers.get("Idempotency-Key", "").strip()
        if not idem_key:
            return json_response(
                success=False,
                code=ErrorCodes.IDEMPOTENCY_KEY_MISSING,
                message="缺少 Idempotency-Key",
                http_status=status.HTTP_400_BAD_REQUEST,
            )
        
        # 调用 service
        service = ConfirmRegisterService(email=email, verify_code=verify_code)
        result = service.execute_confirm(idem_key=idem_key, ttl_seconds=900)
        
        # 成功响应
        return json_response(
            success=True,
            code=ErrorCodes.SUCCESS,
            message="账户注册成功",
            data=result,
            http_status=status.HTTP_200_OK,
        )