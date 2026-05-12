from __future__ import annotations
from typing import Any, Dict, cast
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.response_wrapper import json_response
from users.serializers.auth_password_reset_serializer import (
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
)
from users.services.password_reset_service import (
    PasswordResetConfirmService,
    PasswordResetRequestService,
)

class PasswordResetRequestView(APIView):
    """
    密码重置申请接口
    
    POST /password-reset/request/
    - 校验邮箱格式
    - 调用 Service 发送验证码
    - 不暴露账号是否存在, 防止账号枚举
    """
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        validated_data = cast(Dict[str, Any], serializer.validated_data)
        
        service = PasswordResetRequestService(
            validated_data=validated_data,
            cf_token=str(validated_data.get("cf_token", "")),
            remote_ip=str(request.META.get("REMOTE_ADDR", "")),
        )
        result = service.process()
        
        return json_response(
            success=True,
            code=ErrorCodes.SUCCESS,
            message="如该邮箱已注册, 验证码邮件将发送至该邮箱",
            data=result,
            http_status=status.HTTP_200_OK,
        )
        
class PasswordResetConfirmView(APIView):
    """
    密码重置确认接口
    
    POST /password-reset/confirm/
    Header:
    - Idempotency-Key: 必填, 用于防止重复提交

    职责:
    - 校验邮箱、验证码、新密码格式
    - 调用 Service 完成验证码校验和密码更新
    - 密码重置成功后旧 JWT 会通过 sess_ver 失效
    """
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        validate_data = cast(Dict[str, Any], serializer.validated_data)
        
        idem_key = str(request.headers.get("Idempotency-Key", "")).strip()
        
        service = PasswordResetConfirmService(
            email=str(validate_data["email"]),
            verify_code=str(validate_data["verify_code"]),
            new_password=str(validate_data["new_password"]),
        )
        
        result = service.execute_confirm(idem_key=idem_key)
        
        return json_response(
            success=True,
            code=ErrorCodes.SUCCESS,
            message="密码重置成功, 请重新登录",
            data=result,
            http_status=status.HTTP_200_OK,
        )