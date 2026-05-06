"""
JWT 鉴权认证模块(DRF Authentication)

模块定位：
1. 解析 Authorization Header 中的 Bearer Token
2. 调用 ES256 verifier 做 JWT 技术校验（签名、标准 claims、黑名单等）
3. 基于 Redis 用户状态事实源做实时鉴权校验（不查 DB）：
   - is_active / is_deleted
   - payload.sv 与 redis.sess_ver 一致性
4. 校验通过后向 request 注入上下文，供后续业务层直接使用

设计原则：
- 高性能：认证主链路 Redis-only
- 安全优先：状态缺失/异常即拒绝（fail-closed）
- 边界清晰：业务错误统一使用 AppException，再映射为 DRF 协议异常
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any, Dict, NoReturn, Optional, Tuple, cast
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.logging import get_logger
from users.services.auth.state_guards import UserStateGuard
from .jwt_verifier import AzureES256Verifier, JWTValidationError

logger = get_logger("project.jwt.auth")

@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """
    轻量认证用户对象(不查DB)
    
    说明:
    - 仅保存 user_id，满足 DRF 对 request.user.is_authenticated 的语义需求
    - 业务层若需要完整用户信息，应在业务流程中按需查询，而非在认证阶段查询
    """
    id: int
    
    @property
    def is_authenticated(self) -> bool:
        return True

class JWTAuthentication(BaseAuthentication):
    """
    自定义 JWT 认证器(DRF 适配层)
    
    返回约定:
    - 无 Bearer Token：返回 None (让 DRF 继续其他认证器或进入匿名权限判断)
    - 有 Bearer Token 且认证成功：返回 (AuthenticatedUser, token)
    - 认证失败：抛 AuthenticationFailed / PermissionDenied
    """
    _bearer_re = re.compile(r"^Bearer\s+(.+)$", re.IGNORECASE)
    
    def authenticate(self, request: Any) -> Optional[Tuple[Any, str]]:
        """
        DRF 认证入口
        """
        token = self._extract_bearer_token(request)
        if token is None:
            return None
        
        try:
            # 1. JWT技术校验(验签、exp/iat/nbf、黑名单等)
            verifier = AzureES256Verifier.get_instance()
            payload = cast(Dict[str, Any], verifier.verify(token))
            
            # 2. access token 基本字段校验(typ/jti/sub/sv)
            uid, token_sv = self._validate_access_payload(payload)
            
            # 3. Redis-only 用户状态 + 会话版本实时校验
            user_state = UserStateGuard.ensure_user_state_and_sv_allowed(
                user_id=uid,
                token_sv=token_sv,
                stage="jwt_auth",
            )
            
            # 4. 注入 request 上下文(供后续权限与业务层复用)
            self._inject_request_context(
                request=request,
                uid=uid,
                payload=payload,
                token=token,
                user_state=user_state,
            )
            
            return AuthenticatedUser(id=uid), token
        
        except AppException as exc:
            # 业务异常统一映射到 DRF 401/403
            logger.warning(
                "[JWTAuth] reject by AppException code=%s message=%s",
                getattr(exc, "code", None),
                getattr(exc, "message", None),
            )
            self._raise_drf_auth_exception(exc)
        
        except JWTValidationError as exc:
            # verifier 的技术异常：统一按认证失败处理
            logger.warning("[JWTAuth] reject by JWTValidationError err=%s", exc)
            raise AuthenticationFailed(
                detail={
                    "code": ErrorCodes.AUTH_INVALID_TOKEN,
                    "message": "认证失败",
                }
            )
        
        except Exception:
            # 防止内部异常细节泄露
            logger.exception("[JWTAuth] unexpected system error")
            raise AuthenticationFailed(
                detail={
                    "code": ErrorCodes.AUTH_FAILED,
                    "message": "认证失败",
                }
            )
    
    def _extract_bearer_token(self, request: Any) -> Optional[str]:
        """
        从请求头提取 Bearer Token
        
        兼容行为:
        - Header 缺失、格式不符、token 为空字符串 -> 返回 None
        """
        auth_header = str(request.headers.get("Authorization", ""))
        match = self._bearer_re.match(auth_header)
        if not match:
            return None
        
        token = match.group(1).strip()
        return token or None
    
    @staticmethod
    def _parse_positive_int(raw: Any, *, field_name: str) -> int:
        """
        将输入解析为正整数(>=1)
        
        该方法显式处理 None/bool，避免静态类型检查器对 int(None) 报错
        同时保证 sub/sv 等字段在认证层严格收敛
        """
        if raw is None:
            raise ValueError(f"{field_name} is None")
        if isinstance(raw, bool):
            raise ValueError(f"{field_name} is bool")
        
        value = int(raw)
        if value < 1:
            raise ValueError(f"{field_name} < 1")
        return value
    
    def _validate_access_payload(self, payload: Dict[str, Any]) -> Tuple[int, int]:
        """
        校验 access token 关键字段, 并返回 (uid, token_sv)
        
        必要字段:
        - typ == "access"
        - jti 非空字符串
        - sub 可解析为 >=1 的 int
        - sv 可解析为 >=1 的 int
        """
        typ = str(payload.get("typ", "")).strip().lower()
        if typ != "access":
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_TOKEN,
                message="认证失败",
            )
        
        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti.strip():
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_TOKEN,
                message="认证失败",
            )
        
        try:
            uid = self._parse_positive_int(payload.get("sub"), field_name="sub")
        except Exception:
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_TOKEN,
                message="认证失败",
            )
        
        try:
            token_sv = self._parse_positive_int(payload.get("sv"), field_name="sv")
        except Exception:
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_TOKEN,
                message="登录状态已失效，请重新登录",
            )
        
        return uid, token_sv
    
    @staticmethod
    def _inject_request_context(
        *,
        request: Any,
        uid: int,
        payload: Dict[str, Any],
        token: str,
        user_state: Dict[str, Any],
    ) -> None:
        """
        向 request 注入认证上下文，避免后续重复解析 token
        """
        request.user_id = uid
        request.user_state = user_state
        request.jwt_payload = payload
        request.jwt_token = token
    
    @staticmethod
    def _raise_drf_auth_exception(exc: AppException) -> NoReturn:
        """
        将 AppException 映射到 DRF 层异常

        规则：
        - 账号状态类错误 -> 403
        - 其他认证类错误 -> 401
        """
        code = getattr(exc, "code", ErrorCodes.AUTH_FAILED)
        message = getattr(exc, "message", "认证失败")
        
        if code in {
            ErrorCodes.ACCOUNT_DISABLED,
            ErrorCodes.ACCOUNT_DELETED,
            ErrorCodes.AUTH_FORBIDDEN,
        }:
            raise PermissionDenied(detail={"code": code, "message": message})
        
        raise AuthenticationFailed(detail={"code": code, "message": message})