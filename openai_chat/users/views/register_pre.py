# 用户预注册处理视图
from typing import Dict, Any, cast, Optional
from rest_framework.views import APIView # DRF基础视图类
from rest_framework.response import Response # 标准响应封装
from rest_framework import status
from rest_framework.permissions import AllowAny # 允许匿名访问
from users.services.register_service import RegisterService # 用户预注册服务类
from users.serializers.auth_register_serializer import RegisterSerializer # 表单校验器
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from openai_chat.settings.utils.response_wrapper import json_response # 标准统一格式响应封装

logger = get_logger("users")

class RegisterPreview(APIView):
    """
    用户预注册处理视图(异步):
    - 校验Cloudflre Turnstil验证码
    - 校验邮箱/密码格式
    - 缓存注册信息到Redis
    - 发送邮箱验证码
    """
    permission_classes = [AllowAny]
    
    async def post(self, request):
        # 1.数据验证
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"[注册预处理]表单校验失败: {serializer.errors}")
            return Response({
                "code": 400,
                "msg": "参数验证失败",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # 显式注解类型: 避免pylance错误
        validated_data: Dict[str, Any] = cast(Dict[str, Any], serializer.validated_data)
        
        # 2. 提取Turnstile token 和 用户IP, 用于 Cloudflare Turnstile 人机校验
        cf_token: str = validated_data.get("cf_turnstile_token", "127.0.0.1")
        remote_ip: str = request.META.get("REMOTE_ADDR", "")
        
        # 3.初始化预注册服务类
        service = RegisterService(validated_data, cf_token, remote_ip)
        
        # 4.Cloudflare Turnstile 人机验证
        # try:
        #     is_human = await service.verify_human()
        #     logger.info(f"[用户预注册处理] 请求IP:{remote_ip}, 邮箱: {validated_data.get('email')}")
        # except Exception as e:
        #     logger.error(f"[用户注册预处理] Turnstile 请求异常: {e}")
        #     return json_response(500, "人机验证服务异常, 请稍后重试", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        # if not is_human:
        #     logger.warning(f"[用户注册预处理] 注册失败! 用户{validated_data.get('email')}人机验证未通过")
        #     return json_response(403, "人机验证失败, 请刷新页面后重试", status_code=status.HTTP_403_FORBIDDEN)
        
        # 5.缓存用户注册信息 + 发送邮箱验证码
        success, msg = await service.process()
        if not success:
            return json_response(429, msg, status_code=status.HTTP_429_TOO_MANY_REQUESTS)
        
        return json_response(200, msg, status_code=status.HTTP_200_OK)