from __future__ import annotations
from typing import Dict, Any
from rest_framework.views import APIView # DRF 基础视图类
from rest_framework.request import Request # DRF Request 类型
from rest_framework import status

from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response # 统一五段式响应封装
from openai_chat.settings.utils.error_codes import ErrorCodes # 错误码常量表

from users.services.login_service import LoginService # 登录服务类(阶段一)

logger = get_logger("users")

class LoginPreView(APIView):
    """
    用户登录视图(阶段一)
    - view 层负责 HTTP 输入/输出与上下文
    - Service 层负责：serializer 校验、密码校验、guards、状态同步、TOTP 分流、JWT 签发
    - 业务异常统一走 AppException -> 全局 DRF 异常处理器输出五段式
    - View 不再捕获 ValueError/Exception 做自定义响应（避免破坏统一错误出口）
    """
    authentication_classes = [] # 不需要认证
    permission_classes = [] # 不需要权限
    
    def post(self, request: Request):
        """
        入参:
        - email
        - password
        - (Turnstile token 后续由装饰器引入，不进入 service)
        
        出参:
        - require_totp=True  -> challenge_id
        - require_totp=False -> access/refresh/token_type/expires_in
        """
        result: Dict[str, Any] = LoginService(
            data=request.data,
            ip="",
            user_agent=request.headers.get("User-Agent", ""),
        ).execute()
        
        return json_response(
            success=True,
            code=ErrorCodes.SUCCESS,
            message="进入TOTP验证流程" if result.get("require_totp") else "登录成功",
            data=result,
            http_status=status.HTTP_200_OK,
        )