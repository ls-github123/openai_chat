from __future__ import annotations # 延迟类型注解解析
from typing import Dict, Any
from rest_framework.views import APIView # DRF基础视图类
from rest_framework.request import Request # DRF Request 类型
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response # 标准统一JSON响应封装
from users.services.login_service import LoginService # 用户登录服务类(一阶段)

logger = get_logger("users")

class LoginPreView(APIView):
    """
    用户登录视图(阶段一):
    - 校验 cloudflare Turnstil 人机验证
    - 返回:
        - require_totp=True -> challenge_id
        - require_totp=False -> access_token + refresh_token + token_type + expires_in
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
        
        try:
            # 传入原始数据, 由 service 负责唯一一次的 serializer 校验
            service = LoginService(
                data=dict(request.data),
                ip=remote_ip,
                cf_token=cf_token,
            )
            result: Dict[str, Any] = service.validate_credentials()
            
            return json_response(
                code=200,
                msg="进入TOTP验证流程" if result.get("require_totp") else "登录成功",
                data=result,
            )
        
        except ValueError as ve:
            # 业务拒绝: 邮箱/密码错误、guard拦截、参数问题等
            logger.warning("[LoginPreView] reject ip=%s err=%s", remote_ip, ve)
            return json_response(code=401, msg=str(ve), data={})
        
        except Exception as e:
            # 系统异常: 不向客户端暴露内部细节
            logger.exception("[LoginPrevice] system error ip=%s err=%s", remote_ip, e)
            return json_response(
                code=500,
                msg="系统错误, 请稍后重试",
                data={},
            )