"""
DRF 统一异常处理器

目标：
- 统一所有失败响应为五段式：success / code / message / data / request_id
- service 层只需 raise AppException(...)，由此处收口转换为五段式
- DRF 内置异常（ValidationError/NotAuthenticated/...）也统一映射为业务错误码
- 未捕获异常：记录堆栈 + request_id，对外返回统一 500（不泄露内部细节）
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from django.http import Http404 #Django 原生404异常(非 DRF NotFound)
from rest_framework import status # DRF HTTP 状态码枚举
from rest_framework.views import exception_handler # DRF 默认异常处理器
from rest_framework.exceptions import (
    ValidationError,
    AuthenticationFailed,
    NotAuthenticated,
    PermissionDenied,
    Throttled,
    MethodNotAllowed,
    NotFound,
) # DRF 常见异常类型
from rest_framework.response import Response # DRF 标准响应
from openai_chat.settings.utils.exceptions import AppException # 业务异常
from openai_chat.settings.utils.response_wrapper import json_response # 统一五段式响应封装
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("project.api") # 统一异常日志归口

def _get_request_id(context: Dict[str, Any]) -> Optional[str]:
    """
    从 DRF 的 context 中提取 request_id
    - request_id 通常由中间件注入：request.request_id
    """
    request = context.get("request")
    return getattr(request, "request_id", None)

def custom_exception_handler(exc: Exception, context: Dict[str, Any]) -> Response:
    """
    DRF 统一异常处理器
    
    输出结构固定五段式:
    - success / code / message / data / request_id
    
    设计要点:
    1) 业务异常 AppException 优先处理（service 层抛出，携带业务错误码）
    2) Django 原生 Http404 提前处理，避免被误归类为 500
    3) DRF 默认异常先处理，再将其映射为统一错误码
    4) DRF 无法处理的异常（response is None）：
       - 记录 logger.exception（堆栈 + request_id）
       - 对外统一 500，不泄露内部细节
    """
    request = context.get("request")
    request_id = _get_request_id(context)
    
    # 业务异常(service 层抛出) 优先处理
    if isinstance(exc, AppException):
        return json_response(
            success=False,
            code=exc.code,
            message=exc.message,
            data=exc.data or {},
            http_status=exc.http_status,
            request=request,
            request_id=request_id,
        )
    
    # Django 原生404
    # 提前统一(避免 DRF exception_handler 返回 None 走 500)
    if isinstance(exc, Http404):
        return json_response(
            success=False,
            code="COMMON.NOT_FOUND",
            message="资源不存在",
            data={},
            http_status=status.HTTP_404_NOT_FOUND,
            request=request,
            request_id=request_id,
        )
    
    # DRF默认异常处理器
    response = exception_handler(exc, context)
    
    # DRF 无法处理的异常(代码bug / 运行错误)
    if response is None:
        logger.exception(
            "Unhandled exception",
            extra={
                "request_id": request_id,
                "exc_type": exc.__class__.__name__    
            },
        )
        
        return json_response(
            success=False,
            code="SYSTEM.INTERNAL_ERROR",
            message="系统繁忙, 请稍后再试",
            data={},
            http_status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            request=request,
            request_id=request_id,
        )
        
    # DRF 已处理的异常: 映射为业务错误码 + 统一提示信息 + 统一 data 结构
    code = "COMMON.ERROR"
    message = "请求失败"
    data: Dict[str, Any] = {}
    
    # 参数校验失败
    if isinstance(exc, ValidationError):
        code = "COMMON.INVALID_PARAMS"
        message = "参数不合法"
        
        # 防御: 少数情况下 response.data 可能不是 dict（例如 list/str），统一包成 dict
        if isinstance(response.data, dict):
            data = {"fields": response.data}
        else:
            data = {"fields": {"non_field_errors": response.data}}
    
    # 未认证/认证失败: 统一为 AUTH.UNAUTHORIZED（HTTP 状态码沿用 DRF 的 response.status_code）
    elif isinstance(exc, (NotAuthenticated, AuthenticationFailed)):
        code = "AUTH.UNAUTHORIZED"
        message = "未登录或登录已失效"
    
    # 已认证但无权限
    elif isinstance(exc, PermissionDenied):
        code = "AUTH.FORBIDDEN"
        message = "无权限访问"
    
    # 限流
    elif isinstance(exc, Throttled):
        code = "RATE_LIMIT.TOO_MANY_REQUESTS"
        message = "请求过于频繁, 请稍后再试"
        data = {"wait": getattr(exc, "wait", None)}
    
    # 资源不存在(DRF 404)
    elif isinstance(exc, NotFound):
        code = "COMMON.NOT_FOUND"
        message = "资源不存在"
    
    # 方法不允许(405)
    elif isinstance(exc, MethodNotAllowed):
        code = "COMMON.METHOD_NOT_ALLOWED"
        message = "不支持的请求方法"
    
    return json_response(
        success=False,
        code=code,
        message=message,
        data=data,
        http_status=response.status_code,
        request=request,
        request_id=request_id,
    )