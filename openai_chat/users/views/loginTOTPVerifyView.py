from __future__ import annotations
from typing import Any, Dict, cast
from rest_framework import status
from rest_framework.request import Request
from rest_framework.views import APIView

from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.request_utils import get_client_ip
from openai_chat.settings.utils.response_wrapper import json_response

from users.services.login_totp_verify_service import LoginTOTPVerifyService
from users.totp.totp_serializers import TOTPLoginVerifySerializer

logger = get_logger("users")

def _mask_challenge_id(challenge_id: str) -> str:
    """
    日志脱敏 challenge_id
    """
    value = str(challenge_id or "").strip()
    if len(value) <= 12:
        return "***"
    return f"{value[:6]}...{value[-6:]}"

class LoginTOTPVerifyView(APIView):
    """
    用户登录视图(阶段二 - TOTP 二次验证)
    
    边界:
    - View 层只负责 HTTP 入参校验, 请求上下文提取、成功响应输出
    - Service 层负责 pending 校验、TOTP 校验、防重放、用户状态校验、JWT 签发
    - 业务异常统一抛 AppException，由全局 DRF 异常处理器输出五段式响应
    """
    authentication_classes = [] # 登录二阶段尚未持有 access token，不走 DRF 认证
    permission_classes = [] # 登录二阶段允许匿名访问，但必须持有有效 challenge_id + TOTP
    
    def post(self, request: Request):
        """
        入参:
        - challenge_id: 登录阶段一返回的 挑战ID
        - totp_code: 用户提交的 6 位 TOTP验证码
        
        出参:
        - access + refresh token
        - user
        """
        serializer = TOTPLoginVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        validated_data = cast(Dict[str, Any], serializer.validated_data)
        challenge_id = str(validated_data["challenge_id"]).strip()
        totp_code = str(validated_data["totp_code"]).strip()
        
        # 必须与 LoginPreView使用同一个 IP 提取逻辑
        # 否则一阶段 pending 里保存的 ip 和二阶段传入 service 的IP可能不一致
        remote_ip = get_client_ip(request)
        
        # UA 用于和一阶段 pending 中的 ua 做弱绑定
        # request.headers 为 DRF 推荐入口，内部兼容 Django META
        user_agent = request.headers.get("User-Agent", "")
        
        tokens = LoginTOTPVerifyService(
            challenge_id=challenge_id,
            totp_code=totp_code,
            ip=remote_ip,
            user_agent=user_agent,
        ).verify_and_issue_token()
        
        logger.info(
            "[LoginTOTPVerify] login ok challenge_id=%s ip=%s",
            _mask_challenge_id(challenge_id),
            remote_ip,
        )
        
        return json_response(
            success=True,
            code=ErrorCodes.SUCCESS,
            message="登录成功",
            data=tokens,
            http_status=status.HTTP_200_OK,
        )