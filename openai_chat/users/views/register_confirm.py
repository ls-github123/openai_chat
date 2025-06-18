from typing import cast, Dict, Any
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.request import Request
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response
from users.services.confirm_register_service import ConfirmRegisterService

logger = get_logger("users")

class RegisterConfirmView(APIView):
    """
    用户注册确认视图:
    - 验证邮箱验证码
    - 完成用户数据落库
    - 清理注册缓存
    """
    permission_classes = [AllowAny]
    
    def post(self, request: Request):
        # 1.获取传入参数并进行类型安全校验
        data: Dict[str, Any] = cast(Dict[str, Any], request.data)
        email = data.get("email", "").strip().lower()
        verify_code = data.get("verify_code", "").strip()
        
        if not email or not verify_code:
            logger.warning(f"[用户注册确认] 缺少必要参数: email={email}, code={verify_code}")
            return json_response(400, "邮箱或验证码参数不能为空", status_code=status.HTTP_400_BAD_REQUEST)
        
        # 2.初始化注册确认服务类
        service = ConfirmRegisterService(email=email, verify_code=verify_code)
        
        # 3.验证码校验
        is_valid, msg, cached_info = service.validate_code()
        if not is_valid:
            return json_response(403, msg, status_code=status.HTTP_403_FORBIDDEN)
        
        # 4.写入数据库 + 并发锁
        success, db_msg = service.create_user(cached_info)
        if not success:
            return json_response(409, db_msg, status_code=status.HTTP_409_CONFLICT)
        
        # 5.清理注册信息缓存
        service.clear_cache()
        
        # 6.返回成功响应
        return json_response(200, "账户注册成功", status_code=status.HTTP_200_OK)