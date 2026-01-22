from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional

@dataclass
class AppException(Exception):
    """
    业务异常:
    - code: 业务错误码(稳定)
    - message: 用户可读提示
    - http_status: HTTP状态码
    - data: 附加信息(不含敏感字段)
    """
    code: str
    message: str
    http_status: int = 400
    data: Optional[Dict[str, Any]] = None
    
    def __post_init__(self) -> None:
        # 确保 Exception 的标准行为一致：str(exc) 与日志输出可直接显示 message
        super().__init__(self.message)
    
    # 工厂方法: 减少 service 层重复写 status 数字
    @classmethod
    def bad_request(
        cls, *, code: str, message: str, data: Optional[Dict[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=400, data=data)
    
    @classmethod
    def unauthorized(
        cls, *, code: str, message: str = "未登录或登录已失效", data: Optional[Dict[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=401, data=data)
    
    @classmethod
    def forbidden(
        cls, *, code: str, message: str = "无权限访问", data: Optional[Dict[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=403, data=data)
    
    @classmethod
    def not_found(
        cls, *, code: str, message: str = "资源不存在", data: Optional[Dict[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=404, data=data)
    
    @classmethod
    def conflict(
        cls, *, code: str, message: str, data: Optional[Dict[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=409, data=data)