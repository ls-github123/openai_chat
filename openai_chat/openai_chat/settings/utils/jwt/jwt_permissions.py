from __future__ import annotations
from typing import Any, ClassVar
from rest_framework.permissions import BasePermission
from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException

class MinJWTScope(BasePermission):
    """
    JWT scope 最小等级权限校验
    
    scope 等级:
    - user: 普通用户
    - admin: staff 管理员
    - super: 超级管理员
    """
    required_scope: ClassVar[str] = "user"
    scope_rank: ClassVar[dict[str, int]] = {
        "user": 1,
        "admin": 2,
        "super": 3,
    }
    
    def has_permission(self, request: Any, view: Any):
        payload = getattr(request, "jwt_payload", None)
        if not isinstance(payload, dict):
            raise AppException.forbidden(
                code=ErrorCodes.AUTH_FORBIDDEN,
                message="无权限访问",
            )
        
        current_scope = str(payload.get("scope", "")).strip().lower()
        required_scope = str(self.required_scope).strip().lower()
        
        current_rank = self.scope_rank.get(current_scope, 0)
        required_rank = self.scope_rank.get(required_scope, 0)
        
        if current_rank < required_rank:
            raise AppException.forbidden(
                code=ErrorCodes.AUTH_FORBIDDEN,
                message="无权限访问",
            )
        
        return True
    
class IsAdminScope(MinJWTScope):
    required_scope = "admin"

class IsSuperScope(MinJWTScope):
    required_scope = "super"