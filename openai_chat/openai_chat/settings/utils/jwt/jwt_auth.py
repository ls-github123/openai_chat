"""
JWT 鉴权认证模块: 自定义 DRF 认证器（Redis-only 状态校验）

职责：
- 从 Authorization Header 中解析 Bearer Token
- 使用 Azure Key Vault RS256 公钥验签
- 校验 access token 基本 claims（typ / jti / sub）
- 基于 Redis 用户状态事实源进行实时校验
- 不查询数据库（高性能、低耦合）
- 校验通过后向 request 注入认证上下文

=== 关键设计原则 ===
- JWT 认证阶段不访问数据库
- 用户是否“允许访问”完全由 Redis 事实源决定
- Redis 状态缺失视为不可信，直接拒绝（安全优先）
- 业务异常统一使用 AppException
- 本模块仅做“认证适配”，不承载业务语义

=== request 上下文约定 ===
认证成功后注入：
- request.user_id     : int
- request.user_state  : dict
- request.jwt_payload : dict
- request.jwt_token   : str

注：
- request.user 为 AuthenticatedUser（轻量对象，不查 DB）
- 业务/权限判断应基于 request.user_id / request.user_state
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional, Tuple, Any, Dict, cast

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.error_codes import ErrorCodes

from .jwt_verifier import AzureRS256Verifier
from users.services.auth.state_guards import UserStateGuard
# Redis-only 用户状态校验:
# - 校验 is_active / is_deleted
# - Redis 缺失即拒绝
# - 不回源 DB

logger = get_logger("project.jwt")

@dataclass
class AuthenticatedUser:
    """
    轻量"已认证用户"对象(Redis-only 场景专用)
    - 不查询DB
    """
    id: int
    @property
    def is_authenticated(self) -> bool:
        return True

class JWTAuthentication(BaseAuthentication):
    """
    自定义 JWT 认证器(DRF适配)
    - access token 验签 + payload 校验
    - Redis-only 用户状态事实源校验
    - 不查询数据库DB
    """
    _bearer_re = re.compile(r"^Bearer\s+(.+)$", re.IGNORECASE)
    
    def authenticate(self, request) -> Optional[Tuple[Any, str]]:
        """
        DRF 认证入口:
        - Header 无 Bearer token: 返回 None
        - Bearer token 存在: 验签 + 校验 + 写入 request 上下文
        """
        auth_header = request.headers.get("Authorization", "")
        match = self._bearer_re.match(auth_header)
        if not match:
            return None
        
        token = match.group(1).strip()
        if not token:
            return None
        
        try:
            # 1.验签并获取 payload(AzureRS256Verifier 内部已处理签名/过期黑名单等)
            verifier = AzureRS256Verifier.get_instance()
            payload = cast(Dict[str, Any], verifier.verify(token))
            
            # 2.强制校验 token 类型: 仅允许 access
            if payload.get("typ") != "access":
                raise AppException.unauthorized(
                    code=ErrorCodes.AUTH_INVALID_TOKEN,
                    message="认证失败",
                )
            
            # 3.校验 jti: 要求存在(黑名单逻辑通常在 verifier 内做, 这里仅做字段完整性检查)
            jti = payload.get("jti")
            # 4.从 payload 提取 sub(用户ID)
            sub = payload.get("sub")
            if not jti or sub is None:
                raise AppException.unauthorized(
                    code=ErrorCodes.AUTH_INVALID_TOKEN,
                    message="认证失败",
                )
            
            # 5.sub类型校验(必须为 int 可解析)
            try:
                uid = int(sub)
            except Exception:
                raise AppException.unauthorized(
                    code=ErrorCodes.AUTH_INVALID_TOKEN,
                    message="认证失败",
                )
            
            # 6.Redis-only 用户状态校验(缺失/禁用/注销: 直接拒绝访问)
            user_state = UserStateGuard.ensure_user_state_allowed(uid, stage="jwt_auth")
            
            # 7.写入 request 上下文(供后续权限/业务层使用)
            request.user_id = uid # 当前请求的用户ID
            request.user_state = user_state # Redis 用户状态事实源
            request.jwt_payload = payload # JWT原始载荷
            request.jwt_token = token # access token原文
            
            # 8. 返回轻量已认证用户
            return AuthenticatedUser(uid), token
        
        except AppException as e:
            # 统一日志出口
            logger.warning(
                "[JWTAuth] reject code=%s message=%s",
                getattr(e, "code", None),
                getattr(e, "message", None),
            )
            
            # 协议层转换
            self._raise_drf_auth_exception(e)
            
            raise AuthenticationFailed(
                detail={
                    "code": ErrorCodes.AUTH_FAILED,
                    "message": "认证失败"
                }
            )
        
        except Exception:
            logger.exception("[JWTAuth] unexpected system error")
            raise AuthenticationFailed(
                detail={
                    "code": ErrorCodes.AUTH_FAILED,
                    "message": "认证失败",
                }
            )
    
    
    @staticmethod
    def _raise_drf_auth_exception(e: AppException) -> None:
        """
        将 AppException 转换为 DRF 可识别的认证异常
        """
        code = getattr(e, "code", ErrorCodes.AUTH_FAILED)
        message = getattr(e, "message", "认证失败")
        
        # 账户状态类错误 -> 403
        if code in {
            ErrorCodes.ACCOUNT_DISABLED,
            ErrorCodes.ACCOUNT_DELETED,
            ErrorCodes.AUTH_FORBIDDEN,
        }:
            raise PermissionDenied(detail={"code": code, "message": message})
        
        # 其余一律视为认证失败 -> 401
        raise AuthenticationFailed(detail={"code": code, "message": "认证失败"})