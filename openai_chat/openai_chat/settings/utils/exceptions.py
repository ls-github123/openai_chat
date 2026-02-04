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
from dataclasses import dataclass, field
from typing import Any, Optional, Mapping

# - frozen=True：异常对象不可变，防止被后续代码意外修改造成日志与响应不一致
# - slots=True：减少内存占用，提高属性访问效率（大量异常时更稳）
@dataclass(frozen=True, slots=True)
class AppException(Exception):
    """
    业务异常(用于service层, 交 DRF 全局异常处理器转为五段式响应):
    - code: 业务错误码(稳定)
    - message: 用户可读提示(前端提示信息)
    - http_status: HTTP状态码
    - data: 附加信息(不含敏感字段/JSON序列化)
    """
    code: str
    message: str
    http_status: int = 400
    data: Optional[Mapping[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        # 确保 Exception 的标准行为一致：str(exc) 与日志输出可直接显示 message
        super().__init__(self.message)
        
        raw = self.data
        if raw is None:
            object.__setattr__(self, "data", {})
            return
        
        # Mapping(如 dict OrderedDict) -> dict 拷贝
        if isinstance(raw, Mapping):
            object.__setattr__(self, "data", dict(raw))
            return
        
        # 其他类型: 兜底封装, 避免 DRF Response JSON 渲染失败
        object.__setattr__(self, "data", {"detail": raw})
    
    # 工厂方法: 标准化 HTTP 状态码
    @classmethod
    def bad_request(
        cls, *, code: str, message: str, data: Optional[Mapping[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=400, data=data)
    
    @classmethod
    def unauthorized(
        cls, *, code: str, message: str = "未登录或登录已失效", data: Optional[Mapping[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=401, data=data)
    
    @classmethod
    def forbidden(
        cls, *, code: str, message: str = "无权限访问", data: Optional[Mapping[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=403, data=data)
    
    @classmethod
    def not_found(
        cls, *, code: str, message: str = "资源不存在", data: Optional[Mapping[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=404, data=data)
    
    @classmethod
    def conflict(
        cls, *, code: str, message: str, data: Optional[Mapping[str, Any]] = None
    ) -> "AppException":
        return cls(code=code, message=message, http_status=409, data=data)
    
    @classmethod
    def too_many_requests(
        cls,
        *,
        code: str,
        message: str = "请求过于频繁, 请稍后再试",
        data: Optional[Mapping[str, Any]] = None,
    ) -> "AppException":
        """
        429 Too Many Requests: 自定义业务限流(非 DRF Throttled)
        """
        return cls(code=code, message=message, http_status=429, data=data)
    
    @classmethod
    def internal_error(
        cls,
        *,
        code: str = "SYSTEM.INTERNAL_ERROR",
        message: str = "系统繁忙, 请稍后再试",
        data: Optional[Mapping[str, Any]] = None,
    ) -> "AppException":
        """
        500 Internal Server Error：业务层需要“主动兜底”时可用（一般更推荐让未知异常交给 handler 处理）
        """
        return cls(code=code, message=message, http_status=500, data=data)