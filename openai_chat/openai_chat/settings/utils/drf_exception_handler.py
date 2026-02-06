"""
DRF 统一异常处理器
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from django.http import Http404
from rest_framework.views import exception_handler as drf_default_exception_handler
from rest_framework.exceptions import (
    ValidationError,
    AuthenticationFailed,
    NotAuthenticated,
    PermissionDenied,
    Throttled,
    MethodNotAllowed,
    NotFound,
)

from rest_framework import status
from rest_framework.response import Response
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.response_wrapper import json_response

logger = get_logger("project.drf")

def _get_request_id(context: Dict[str, Any]) -> Optional[str]:
    request = context.get("request")
    return getattr(request, "request_id", None)

def _emit(exc: AppException, *, context: Dict[str, Any]) -> Response:
    """
    唯一响应出口: AppException -> 五段式输出
    """
    request_id = _get_request_id(context)
    
    # 日志分级：业务拒绝(4xx)=warning，系统异常(5xx)=error
    if exc.http_status >= 500:
        logger.error(
            "[AppException] code=%s status=%s message=%s request_id=%s",
            exc.code, exc.http_status, exc.message, request_id,
        )
    else:
        logger.warning(
            "[AppException] code=%s status=%s message=%s request_id=%s",
            exc.code, exc.http_status, exc.message, request_id,
        )
    
    return json_response(
        success=False,
        code=exc.code,
        message=exc.message,
        data=exc.data or {},
        http_status=exc.http_status,
        request_id=request_id,
    )

def custom_exception_handler(exc: Exception, context: Dict[str, Any]) -> Response:
    request_id = _get_request_id(context)

    # 1) 业务异常：按业务语义输出
    if isinstance(exc, AppException):
        return _emit(exc, context=context)
    
    # 2) Django 原生 404
    if isinstance(exc, Http404):
        return _emit(
            AppException.not_found(code="COMMON.NOT_FOUND", message="资源不存在"),
            context=context,
        )
    
    # 3) DRF 默认异常处理（status_code + detail）
    response = drf_default_exception_handler(exc, context)
    
    # 4) DRF 无法处理：未知异常 -> 500
    if response is None:
        logger.exception("Unhandled exception", extra={"request_id": request_id})
        return _emit(AppException.internal_error(), context=context)
    
    # 5) DRF 内置异常: 最小映射 -> AppException
    if isinstance(exc, ValidationError):
        fields = response.data if isinstance(response.data, dict) else {"non_field_errors": response.data}
        return _emit(
            AppException.bad_request(
                code="COMMON.INVALID_PARAMS",
                message="参数不合法",
                data={"fields": fields},
            ),
            context=context,
        )

    if isinstance(exc, (NotAuthenticated, AuthenticationFailed)):
        return _emit(
            AppException.unauthorized(code="AUTH.UNAUTHORIZED", message="未登录或登录已失效"),
            context=context,
        )

    if isinstance(exc, PermissionDenied):
        return _emit(
            AppException.forbidden(code="AUTH.FORBIDDEN", message="无权限访问"),
            context=context,
        )

    if isinstance(exc, Throttled):
        return _emit(
            AppException.too_many_requests(
                code="RATE_LIMIT.TOO_MANY_REQUESTS",
                message="请求过于频繁, 请稍后再试",
                data={"wait": getattr(exc, "wait", None)},
            ),
            context=context,
        )

    if isinstance(exc, NotFound):
        return _emit(
            AppException.not_found(code="COMMON.NOT_FOUND", message="资源不存在"),
            context=context,
        )

    if isinstance(exc, MethodNotAllowed):
        return _emit(
            AppException.bad_request(code="COMMON.METHOD_NOT_ALLOWED", message="不支持的请求方法"),
            context=context,
        )

    # 6) 其他 DRF 异常：保留其 status_code，但统一错误码
    return _emit(
        AppException(
            code="COMMON.ERROR",
            message="请求失败",
            http_status=getattr(response, "status_code", status.HTTP_400_BAD_REQUEST),
            data={},
        ),
        context=context,
    )