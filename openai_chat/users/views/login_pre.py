from typing import cast, Dict, Any
from rest_framework.views import APIView # DRF基础视图类
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response # 标准统一JSON响应封装
from users.serializers.auth_login_serializer import LoginSerializer # 登录序列化器
from users.services.login_service import LoginService # 用户登录服务类(一阶段)

logger = get_logger("users")

class LoginPreView(APIView):
    """
    用户登录视图(阶段一):
    - 校验 cloudflare Turnstil 人机验证
    - 校验邮箱和密码
    - 若启用 TOTP: 返回 require_totp = True + user_id
    - 若未启用 TOTP: 返回 require_totp = False + access_token + refresh_token
    """
    authentication_classes = [] # 不需要验证
    permission_classes = [] # 不需要权限
    
    def post(self, request):
        """
        登录接口入口:
        - 参数: email, password, cf_turnstile_token
        """
        remote_ip = (
            request.META.get("HTTP_X_FORWARDED_FOR") or
            request.META.get("REMOTE_ADDR", "")
        )
        cf_token = request.data.get("cf_turnstile_token", "") # Cloudflare Turnstile Token
        
        # 参数结构校验
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True) # DRF自动抛出参数校验异常
        validated_data = cast(Dict[str, Any], serializer.validated_data)
        
        try:
            # 执行登录逻辑(密码校验 + TOTP判断 + 人机验证)
            service = LoginService(
                data=validated_data,
                ip=remote_ip,
                cf_token=cf_token
            )
            result = service.validate_credentials()
            
            return json_response(
                code=200,
                msg="登录成功" if not result.get("require_totp") else "进入TOTP验证流程",
                data=result
            )
        
        except ValueError as ve:
            logger.warning(f"[LoginPreView] 登录失败: {ve}")
            return json_response(code=401, msg=str(ve))
        
        except Exception as e:
            logger.exception(f"[LoginPreView] 系统异常: {e}")
            return json_response(
                code=500,
                msg="系统错误, 请稍后重试",
                data={"detail": str(e)}
            )