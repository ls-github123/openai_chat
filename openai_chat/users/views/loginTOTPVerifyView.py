from typing import Dict, Any, cast
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response
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
        - user_id: 用户ID
        - totp_code: TOTP验证码
        """
        serializer = TOTPLoginVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = cast(Dict[str, Any], serializer.validated_data)
        
        # 基础安全校验: 确保 user_id 存在
        user_id = validated_data.get("user_id")
        if not user_id:
            logger.error("[LoginTOTPVerify] 缺少 user_id 参数")
            return json_response(code=400, msg="非法请求: 用户ID缺失")
        
        # 获取客户端 IP 地址
        remote_ip = (
            request.META.get("HTTP_X_FORWARDED_FOR") or
            request.META.get("REMOTE_ADDR", "")
        )
                
        try:
            service = LoginTOTPVerifyService(**validated_data)
            tokens = service.verify_and_issue_token()
            logger.info(f"[LoginTOTPVerify] 用户 {user_id} 登录成功, IP={remote_ip}")
            return json_response(
                code=200,
                msg="登录成功",
                data=tokens
            )
        except ValueError as ve:
            logger.warning(f"[LoginTOTPVerify] 验证失败: {ve}")
            return json_response(
                code=401,
                msg=str(ve)
            )
        except Exception as e:
            logger.exception(f"[LoginTOTPVerify] 系统异常: {e}")
            return json_response(
                code=500,
                msg="系统错误",
                data={"detail": str(e)}
            )