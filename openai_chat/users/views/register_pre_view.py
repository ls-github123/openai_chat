# 用户预注册处理视图
from __future__ import annotations
from typing import Any, Dict, cast
from rest_framework.views import APIView # DRF 基础视图
from rest_framework.permissions import AllowAny # 允许匿名访问
from openai_chat.settings.utils.response_wrapper import json_response # 统一响应封装
from openai_chat.settings.utils.error_codes import ErrorCodes # 错误码常量表

from users.serializers.auth_register_pre_serializer import RegisterPreSerializer # 预注册序列化器
from users.services.register_pre_service import RegisterPreService # 预注册服务类

class RegisterPreView(APIView):
    """
    用户预注册接口
    - 接收请求
    - 执行 serializer 校验
    - 调用 service 执行业务
    - 成功返回统一五段式响应
    - 所有异常交由 DRF + custom_exception_handler 处理
    """
    # 注册接口允许匿名访问
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        # 1.输入校验
        serializer = RegisterPreSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        validated_data: Dict[str, Any] = cast(Dict[str, Any], serializer.validated_data)
        
        # 2.调用业务服务
        service = RegisterPreService(
            validated_data=validated_data,
            cf_token=validated_data.get("cf_token", ""),
            remote_ip=request.META.get("REMOTE_ADDR", ""),
        )
        
        result = service.process()
        
        # 3.成功响应(统一结构)
        return json_response(
            success=True,
            code=ErrorCodes.OK,
            message="验证码邮件已发送, 请注意查收",
            data=result,
            http_status=200,
            request=request,
        )