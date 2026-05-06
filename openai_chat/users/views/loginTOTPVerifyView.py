from typing import Dict, Any, cast
from rest_framework.views import APIView
from rest_framework import status
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response
from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException
from users.services.login_totp_verify_service import LoginTOTPVerifyService # 用户登录服务类(二阶段)
from users.totp.totp_serializers import TOTPLoginVerifySerializer # 登录账户二次验证TOTP序列化器

logger = get_logger("users")

class LoginTOTPVerifyView(APIView):
    """
    用户登录视图(阶段二-TOTP二次验证)
    - 校验用户提交的TOTP动态验证码
    - 若验证码正确, 签发JWT
    """
    authentication_classes = [] # 不需要DRF认证
    permission_classes = [] # 不需要DRF权限
    
    def post(self, request):
        """
        接收参数:
        - challenge_id: 登录阶段一返回的挑战ID
        - totp_code: TOTP验证码
        """
        serializer = TOTPLoginVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = cast(Dict[str, Any], serializer.validated_data)
        
        # 基础安全校验: 确保 challenge_id 存在
        challenge_id = validated_data.get("challenge_id")
        if not challenge_id:
            logger.error("[LoginTOTPVerify] 缺少 challenge_id 参数")
            return json_response(
                success=False,
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message="非法请求: 登录挑战ID缺失",
                http_status=status.HTTP_400_BAD_REQUEST,
            )
        
        # 获取客户端 IP 地址
        remote_ip = (
            request.META.get("HTTP_X_FORWARDED_FOR") or
            request.META.get("REMOTE_ADDR", "")
        )
                
        try:
            service = LoginTOTPVerifyService(**validated_data)
            tokens = service.verify_and_issue_token()
            logger.info("[LoginTOTPVerify] challenge_id=%s 登录成功, IP=%s", challenge_id, remote_ip)
            return json_response(
                success=True,
                code=ErrorCodes.SUCCESS,
                message="登录成功",
                data=tokens,
                http_status=status.HTTP_200_OK,
            )
        except ValueError as ve:
            logger.warning(f"[LoginTOTPVerify] 验证失败: {ve}")
            return json_response(
                success=False,
                code=ErrorCodes.AUTH_TOTP_INVALID,
                message=str(ve),
                http_status=status.HTTP_401_UNAUTHORIZED,
            )
        except AppException as exc:
            logger.warning("[LoginTOTPVerify] 业务拒绝: code=%s message=%s", exc.code, exc.message)
            return json_response(
                success=False,
                code=exc.code,
                message=exc.message,
                data=exc.data,
                http_status=exc.http_status,
            )
        except Exception as e:
            logger.exception(f"[LoginTOTPVerify] 系统异常: {e}")
            return json_response(
                success=False,
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="系统错误",
                data=None,
                http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
