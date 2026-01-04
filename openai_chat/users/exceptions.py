# 异常类型
from __future__ import annotations # 延迟类型注解解析

class AuthGuardError(Exception):
    """登录/签发前置校验失败的基类异常(业务异常)"""
    code: str = "AUTH_GUARD_FAILED" # 默认错误码
    
    def __init__(self, message: str, *, code: str | None = None):
        super().__init__(message)
        if code:
            self.code = code

class AccountDeletedError(AuthGuardError):
    """账户已被删除异常"""
    code = "ACCOUNT_DELETED"

class AccountDisabledError(AuthGuardError):
    """账户被禁用异常"""
    code = "ACCOUNT_DISABLED"

class InvalidUserError(AuthGuardError):
    """无效用户异常"""
    code = "INVALID_USER"