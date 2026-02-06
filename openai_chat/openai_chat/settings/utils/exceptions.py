"""
业务异常: AppException

设计目标:
1) 让 service 层只需要 `raise AppException.xxx(...)` 即可表达业务失败原因
2) 结构稳定：code/message/http_status/data 四要素清晰、可序列化
3) 对外展示信息可控：message 给前端可读；data 不允许放敏感信息
4) 与 DRF 统一异常处理器协作：handler 捕获 AppException -> 五段式 json_response

设计原则:
- AppException 只负责“承载业务失败信息”，不负责“构造 Response”
- data 允许为空；但建议在 __post_init__ 中做强约束，避免出现 list/str 造成 handler 不稳定
- 工厂方法统一 HTTP 状态码，service 层避免手写数字
"""
from __future__ import annotations
from typing import Any, Mapping, Dict
from rest_framework import status

def _normalize_data(data: Any) -> Dict[str, Any]:
    """
    强制把 data 规整为 dict, 避免 handler/json_response 在序列化阶段不稳定
    """
    if data is None:
        return {}
    if isinstance(data, Mapping):
        return dict(data)
    return {"detail": data}


class AppException(Exception):
    """
    业务异常(业务层唯一允许抛出的异常类型):
    目标：
    - service/guard/jwt_auth 只需 raise AppException.xxx(...)
    - DRF 全局异常处理器捕获 AppException -> 五段式响应
    - 结构稳定：code/message/http_status/data
    
    参数:
    - code: 业务错误码(稳定)
    - message: 用户可读提示(前端提示信息)
    - http_status: HTTP状态码
    - data: 附加信息(不含敏感字段/JSON序列化)
    """
    __slots__ = ("code", "message", "http_status", "data")
    
    def __init__(
        self,
        *,
        code: str,
        message: str,
        http_status: int = status.HTTP_400_BAD_REQUEST,
        data: Any = None,
    ) -> None:
        # Exception 的标准行为：str(exc) 显示 message
        super().__init__(message)
        self.code = str(code)
        self.message = str(message)
        self.http_status = int(http_status)
        self.data = _normalize_data(data)
    
    # 工厂方法: 标准化 HTTP 状态码
    @classmethod
    def bad_request(cls, *, code: str, message: str, data: Any = None) -> "AppException":
        return cls(code=code, message=message, http_status=status.HTTP_400_BAD_REQUEST, data=data)
    
    @classmethod
    def unauthorized(cls, *, code: str, message: str = "未登录或登录已失效", data: Any = None) -> "AppException":
        return cls(code=code, message=message, http_status=status.HTTP_401_UNAUTHORIZED, data=data)

    @classmethod
    def forbidden(cls, *, code: str, message: str = "无权限访问", data: Any = None) -> "AppException":
        return cls(code=code, message=message, http_status=status.HTTP_403_FORBIDDEN, data=data)

    @classmethod
    def not_found(cls, *, code: str, message: str = "资源不存在", data: Any = None) -> "AppException":
        return cls(code=code, message=message, http_status=status.HTTP_404_NOT_FOUND, data=data)
    
    @classmethod
    def too_many_requests(cls, *, code: str, message: str = "请求过于频繁", data: Any = None) -> "AppException":
        return cls(code=code, message=message, http_status=status.HTTP_429_TOO_MANY_REQUESTS, data=data)
    
    @classmethod
    def internal_error(cls, *, code: str = "SYSTEM.INTERNAL_ERROR", message: str = "系统繁忙, 请稍后再试", data: Any = None) -> "AppException":
        return cls(code=code, message=message, http_status=status.HTTP_500_INTERNAL_SERVER_ERROR, data=data)