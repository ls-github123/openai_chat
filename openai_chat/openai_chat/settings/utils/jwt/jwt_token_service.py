"""
JWT Token 服务模块（ES256）

模块职责：
1. TokenIssuerService
   - 负责签发 access + refresh
   - 将 sess_ver 写入 payload.sv（用于全局会话失效）
2. TokenRefreshService
   - 负责 refresh token 校验
   - 校验用户状态事实源（Redis）与 sv 一致性
   - refresh token 保持不变，仅签发新 access
3. TokenRevoker
   - 统一封装 token 拉黑逻辑（按 jti + exp）

设计原则：
- 技术校验与业务映射分离：
  - 签名/claims 校验由 verifier 完成
  - 业务错误对外统一为 AppException
- 鉴权安全优先：
  - refresh 路径显式校验 Redis 用户状态（is_active/is_deleted）
  - refresh 路径显式校验 payload.sv == redis.sess_ver
- 向后兼容：
  - 保留 refresh_access_token() 方法名，兼容现有调用方
"""

from __future__ import annotations

from typing import Any, Dict, Literal, Mapping, Optional, cast

from django.conf import settings
from users.models import User

from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.jwt.jwt_blacklist import add_to_blacklist
from openai_chat.settings.utils.jwt.jwt_payload import build_jwt_payload
from openai_chat.settings.utils.jwt.jwt_signer import AzureES256Signer
from openai_chat.settings.utils.jwt.jwt_verifier import AzureES256Verifier, JWTValidationError
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.token_helpers import get_scope_for_user
from users.services.auth.state_guards import UserStateGuard
from users.services.user_state_service import UserStateService

logger = get_logger("project.jwt")

# JWT 头固定：ES256 + JWT
HEADER: Dict[str, str] = {"alg": "ES256", "typ": "JWT"}

TokenType = Literal["access", "refresh"]


def _cfg_int(name: str, default: int) -> int:
    """
    读取整型配置并兜底，防止配置缺失导致签发链路中断。
    """
    try:
        return int(getattr(settings, name, default))
    except Exception:
        return int(default)


def _normalize_sub_to_uid(payload: Mapping[str, Any]) -> int:
    """
    从 payload 提取并校验 sub，返回 uid(int >= 1)。

    修正点：
    - 直接在这里完成“字符串 -> 正整数”收敛，避免调用方再 int(...) 产生非业务异常。
    """
    raw = payload.get("sub")
    sub = str(raw).strip() if raw is not None else ""
    if not sub:
        raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
            message="Refresh Token 缺少 sub",
        )

    try:
        uid = int(sub)
        if uid < 1:
            raise ValueError("uid < 1")
    except Exception as exc:
        raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
            message="Refresh Token 的 sub 非法",
        ) from exc

    return uid


def _normalize_sv(payload: Mapping[str, Any]) -> int:
    """
    从 payload 提取并校验 sv（会话版本号）。
    """
    raw_sv: Any = payload.get("sv")

    if raw_sv is None:
        raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
            message="Refresh Token 缺少 sv",
        )

    if isinstance(raw_sv, bool):
        raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
            message="Refresh Token 的 sv 非法",
        )

    if not isinstance(raw_sv, (int, float, str, bytes, bytearray)):
        raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
            message="Refresh Token 的 sv 类型非法",
        )

    try:
        sv_int = int(raw_sv)
    except (TypeError, ValueError) as exc:
        raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
            message="Refresh Token 的 sv 非法",
        ) from exc

    if sv_int < 1:
        raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_TOKEN,
            message="Refresh Token 的 sv 非法",
        )

    return sv_int


class TokenIssuerService:
    """
    JWT 签发服务。

    说明：
    - access scope 动态按用户角色生成
    - refresh scope 固定为 "refresh"
    - 两类 token 都写入同一个当前 sess_ver，用于后续 sv 比对
    """

    def __init__(self, user: User):
        self.user = user
        self.signer = AzureES256Signer.get_instance()

    def _build_amr(self) -> list[str]:
        """
        生成 amr（认证方式）字段。

        约定：
        - 默认 pwd
        - 若用户启用 TOTP，则加入 totp
        """
        if bool(getattr(self.user, "totp_enabled", False)):
            return ["pwd", "totp"]
        return ["pwd"]

    def issue_tokens(self) -> Dict[Literal["access", "refresh"], str]:
        """
        签发 access + refresh。
        """
        try:
            user_id = str(self.user.id).strip()
            if not user_id:
                raise AppException.internal_error(
                    code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                    message="用户标识异常，无法签发令牌",
                )

            access_scope = str(get_scope_for_user(self.user))
            sess_ver = int(UserStateService.get_sess_ver(int(self.user.id)))

            access_lifetime = _cfg_int("JWT_ACCESS_TOKEN_LIFETIME", 15 * 60)
            refresh_lifetime = _cfg_int("JWT_REFRESH_TOKEN_LIFETIME", 7 * 24 * 3600)
            amr = self._build_amr()

            access_payload = build_jwt_payload(
                user_id=user_id,
                token_type="access",
                scope=access_scope,
                lifetime=access_lifetime,
                sess_ver=sess_ver,
                amr=amr,
            )

            refresh_payload = build_jwt_payload(
                user_id=user_id,
                token_type="refresh",
                scope="refresh",
                lifetime=refresh_lifetime,
                sess_ver=sess_ver,
                amr=amr,
            )

            access_token = self.signer.sign(HEADER, access_payload)
            refresh_token = self.signer.sign(HEADER, refresh_payload)

            logger.info(
                "[TokenIssuerService] issue ok user_id=%s scope=%s sv=%s",
                user_id,
                access_scope,
                sess_ver,
            )

            return {
                "access": access_token,
                "refresh": refresh_token,
            }

        except AppException:
            raise
        except Exception as exc:
            logger.error("[TokenIssuerService] issue failed user_id=%s err=%r", self.user.id, exc)
            raise AppException.internal_error(
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="令牌签发失败，请稍后重试",
            ) from exc

    def issue_access_token(self, *, sess_ver: Optional[int] = None) -> Dict[Literal["access"], str]:
        """
        仅签发新的 access token。
        """
        try:
            user_id = str(self.user.id).strip()
            if not user_id:
                raise AppException.internal_error(
                    code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                    message="用户标识异常，无法签发令牌",
                )

            access_scope = str(get_scope_for_user(self.user))
            final_sess_ver = (
                int(sess_ver)
                if sess_ver is not None
                else int(UserStateService.get_sess_ver(int(self.user.id)))
            )
            access_lifetime = _cfg_int("JWT_ACCESS_TOKEN_LIFETIME", 15 * 60)

            access_payload = build_jwt_payload(
                user_id=user_id,
                token_type="access",
                scope=access_scope,
                lifetime=access_lifetime,
                sess_ver=final_sess_ver,
                amr=self._build_amr(),
            )
            access_token = self.signer.sign(HEADER, access_payload)

            logger.info(
                "[TokenIssuerService] issue access ok user_id=%s scope=%s sv=%s",
                user_id,
                access_scope,
                final_sess_ver,
            )

            return {"access": access_token}

        except AppException:
            raise
        except Exception as exc:
            logger.error("[TokenIssuerService] issue access failed user_id=%s err=%r", self.user.id, exc)
            raise AppException.internal_error(
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="令牌签发失败，请稍后重试",
            ) from exc


class TokenRefreshService:
    """
    Refresh Token 刷新服务（固定 refresh 模式）。

    流程：
    1. 校验 refresh token（签名 + claims + 黑名单）
    2. 校验 typ=refresh
    3. 校验用户 Redis 状态（禁用/删除）+ 校验 sv 一致性
    4. 签发新 access，refresh token 保持不变
    """
    MAX_TOKEN_LENGTH = 4096

    def __init__(self, refresh_token: str):
        if not isinstance(refresh_token, str):
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message="Refresh Token 格式非法",
            )

        token = refresh_token.strip()
        if not token:
            raise AppException.bad_request(
                code=ErrorCodes.AUTH_TOKEN_MISSING,
                message="Refresh Token 不能为空",
            )
        if len(token) > self.MAX_TOKEN_LENGTH:
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message="Refresh Token 格式非法",
            )

        self.refresh_token = token
        self.verifier = AzureES256Verifier.get_instance()

    @staticmethod
    def _get_user(user_id: int) -> User:
        """
        根据 user_id 获取用户对象（用于 scope 计算与签发）。
        """
        try:
            return cast(User, User.objects.get(id=user_id))
        except User.DoesNotExist as exc:
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_USER,
                message="用户不存在或状态失效",
            ) from exc

    def _verify_refresh_payload(self) -> Mapping[str, Any]:
        """
        调用 verifier 执行技术校验，返回 payload
        """
        try:
            payload = cast(Mapping[str, Any], self.verifier.verify(self.refresh_token))
        except JWTValidationError as exc:
            logger.warning("[TokenRefreshService] verify failed err=%s", exc)
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_TOKEN,
                message="Refresh Token 无效或已过期",
            ) from exc
        except Exception as exc:
            logger.error("[TokenRefreshService] verify exception err=%r", exc)
            raise AppException.internal_error(
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="系统繁忙，请稍后重试",
            ) from exc

        typ = str(payload.get("typ", "")).strip().lower()
        if typ != "refresh":
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_TOKEN,
                message="提供的 Token 不是 Refresh Token",
            )

        return payload

    @staticmethod
    def _ensure_refresh_state_allowed(user_id: int, token_sv: int) -> None:
        """
        校验 refresh 请求是否仍被允许

        校验项：
        1. 用户状态事实源（is_active / is_deleted）
        2. token.sv == redis.sess_ver（全局会话版本一致）

        说明：
        - 这一步非常关键，因为 refresh 接口通常是 AllowAny，不会走 jwt_auth 的状态校验链。
        """
        UserStateGuard.ensure_user_state_and_sv_allowed(
            user_id=user_id,
            token_sv=token_sv,
            stage="token_refresh",
        )

    def refresh_tokens(self) -> Dict[str, str]:
        """
        标准刷新入口（推荐新代码使用）。
        """
        payload = self._verify_refresh_payload()

        user_id = _normalize_sub_to_uid(payload)
        token_sv = _normalize_sv(payload)

        # Redis 状态校验 + sv 一致性校验（防止禁用用户继续刷新）
        self._ensure_refresh_state_allowed(user_id, token_sv)

        # 用户对象用于后续重新计算 scope 与签发 access
        user = self._get_user(user_id)
        tokens = TokenIssuerService(user).issue_access_token(sess_ver=token_sv)

        logger.info("[TokenRefreshService] refresh access ok user_id=%s", user_id)

        return cast(Dict[str, str], tokens)

    def refresh_access_token(self) -> Dict[str, str]:
        """
        兼容旧调用方的方法名。

        兼容说明：
        - 旧名称是 refresh_access_token，当前语义为仅返回新的 access token。
        """
        return self.refresh_tokens()


class TokenRevoker:
    """
    Token 拉黑器。

    使用场景：
    - logout
    - 管理后台主动失效特定 token（按 jti）
    """

    def __init__(
        self,
        *,
        jti: str,
        exp: int,
        user_id: Optional[str] = None,
        token_type: TokenType = "access",
    ):
        self.user_id = (user_id or "unknown").strip() or "unknown"
        self.jti = str(jti).strip()
        self.exp = int(exp)
        self.token_type = token_type

    def revoke_token(self) -> bool:
        """
        拉黑 token。

        返回：
        - True：成功/已存在/已过期（幂等语义）
        - False：输入非法或基础设施异常
        """
        if not self.jti:
            logger.error(
                "[TokenRevoker] empty jti user_id=%s type=%s",
                self.user_id,
                self.token_type,
            )
            return False

        logger.info(
            "[TokenRevoker] revoke request user_id=%s type=%s jti=%s exp=%s",
            self.user_id,
            self.token_type,
            self.jti,
            self.exp,
        )
        return add_to_blacklist(self.jti, self.exp)
