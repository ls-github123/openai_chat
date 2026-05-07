from __future__ import annotations
"""
用户退出登录服务类

目标:
- 同时接收 access_token + refresh_token，并分别加入黑名单
- 幂等：重复调用退出接口不应报错
- 普通退出仅使当前传入的 token 失效，不修改用户状态事实源，不触发全局下线
- 统一错误路径：仅抛 AppException + ErrorCodes（不使用 RuntimeError 等其他异常）

说明:
- verifier.verify(token) 负责 JWT 签名校验 + exp/nbf/iat 等时间字段校验
- TokenRevoker 负责将 jti 写入 Redis 黑名单，TTL 通常以 exp 为上限
"""
from dataclasses import dataclass # 命令对象
from typing import Any, Mapping, Optional, Literal, Tuple

from openai_chat.settings.utils.jwt.jwt_verifier import AzureES256Verifier # JWT验签/解析(exp/nbf/iat校验)
from openai_chat.settings.utils.jwt.jwt_token_service import TokenRevoker # JWT Token黑名单写入器

from openai_chat.settings.utils.exceptions import AppException # 统一业务异常
from openai_chat.settings.utils.error_codes import ErrorCodes # 统一错误码

from openai_chat.settings.utils.logging import get_logger

logger = get_logger("users")

TokenType = Literal["access", "refresh"]

@dataclass(frozen=True, slots=True)
class LogoutCommand:
    """
    退出登录命令对象
    - access_token/refresh_token: 推荐同时传入；允许只传一个
    """
    access_token: Optional[str] = None 
    refresh_token: Optional[str] = None
    
class LogoutService:
    """
    用户退出登录服务类
    - 单端退出(拉黑 access + refresh token )
    """
    def __init__(self, cmd: LogoutCommand):
        self._cmd = cmd
        # 单例: 避免重复初始化/加载缓存
        self._verifier = AzureES256Verifier.get_instance()
    
    def execute(self) -> None:
        """
        执行退出(幂等)
        
        错误策略:
        - 仅在两个 token 都缺失时,抛出 400
        - 写入黑名单发生系统异常(如 Redis异常)时抛 500
        - 其他 token 问题(过期/无效/已拉黑等)视为幂等成功
        """
        access_token = self._clean_token(self._cmd.access_token)
        refresh_token = self._clean_token(self._cmd.refresh_token)
        
        # 至少需要一个token, 否则无法表达具体要退出的会话
        if not access_token and not refresh_token:
            raise AppException.bad_request(
                code=ErrorCodes.AUTH_TOKEN_MISSING,
                message="令牌缺失",
            )
        
        # 尝试验签(失败则返回 None, 按幂等退出处理)
        access_payload = self._try_verify(token=access_token, token_type="access") if access_token else None
        refresh_payload = self._try_verify(token=refresh_token, token_type="refresh") if refresh_token else None
        
        # 两个 token 都验签失败 -> 按幂等退出处理: 直接视为已退出
        if access_payload is None and refresh_payload is None:
            logger.info("[LogoutService] idempotent logout: both tokens unverifiable (treated success).")
            return
        
        # 两个令牌都验签成功 -> sub 必须一致, 防止混搭 token
        access_sub = self._extract_sub(payload=access_payload) if access_payload else None
        refresh_sub = self._extract_sub(payload=refresh_payload) if refresh_payload else None
        if access_sub and refresh_sub and access_sub != refresh_sub:
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message="access_token 与 refresh_token 不匹配",
            )
        
        # 对验签成功的 token 分别执行黑名单写入
        if access_payload is not None:
            self._revoke_verified_token(payload=access_payload, token_type="access")
        if refresh_payload is not None:
            self._revoke_verified_token(payload=refresh_payload, token_type="refresh")
        
    def _try_verify(self, *, token: str, token_type: TokenType) -> Optional[Mapping[str, Any]]:
        """
        尝试验签
        - 成功: 返回 payload
        - 失败: 返回 None(按幂等退出处理)
        """
        try:
            payload: Mapping[str, Any] = self._verifier.verify(token, check_blacklist=False)
            actual_type = str(payload.get("typ", "")).strip().lower()
            if actual_type != token_type:
                raise AppException.bad_request(
                    code=ErrorCodes.COMMON_INVALID_PARAMS,
                    message=f"{token_type}_token 类型不匹配",
                )
            logger.info(
                "[LogoutService] token verified for logout token_type=%s sub=%s jti=%s",
                token_type,
                payload.get("sub"),
                payload.get("jti"),
            )
            return payload
        except AppException:
            raise
        except Exception as e:
            logger.info("[LogoutService] verify failed: token_type=%s, err=%s", token_type, e)
            return None
    
    @staticmethod
    def _extract_sub(*, payload: Mapping[str, Any]) -> Optional[str]:
        """
        提取 sub(user_id)
        - 用于一致性校验
        """
        sub = payload.get("sub")
        return str(sub) if sub else None
    
    @staticmethod
    def _extract_required_fields(
        *,
        payload: Mapping[str, Any],
        token_type: TokenType
        ) -> Tuple[str, int, str]:
        """
        严格字段契约(仅对已验签通过的 token 执行):
        - jti/exp/sub 必须存在
        - exp 必须为 int
        """
        jti = payload.get("jti")
        exp = payload.get("exp")
        sub = payload.get("sub")
        
        if not jti or exp is None or not sub:
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message=f"{token_type}_token 缺少必要字段(jti/exp/sub)",
            )
        
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message=f"{token_type}_token 的 exp 字段类型非法",
            )
        
        return str(jti), int(exp), str(sub)
    
    def _revoke_verified_token(self, *, payload: Mapping[str, Any], token_type: TokenType) -> None:
        """
        对验签成功的 token 执行黑名单写入
        - 先做字段契约校验
        - 再写入黑名单(幂等)
        """
        jti, exp, user_id = self._extract_required_fields(payload=payload, token_type=token_type)
        
        try:
            revoker = TokenRevoker(
                jti=jti,
                exp=exp,
                user_id=user_id,
                token_type=token_type,
            )
            
            ok = bool(revoker.revoke_token())
            if ok:
                logger.info("[LogoutService] token revoked: user=%s, type=%s, jti=%s", user_id, token_type, jti)
            else:
                # 允许退出幂等, 已存在黑名单通常视为成功
                logger.warning(
                    "[LogoutService] revoke_token returned False (treated idempotent): user=%s, type=%s, jti=%s",
                    user_id, token_type, jti
                )
        except AppException:
            raise
        except Exception as e:
            logger.error("[LogoutService] revoke blacklist failed: user=%s, type=%s, jti=%s, err=%s", user_id, token_type, jti, e)
            raise AppException.internal_error(
                code=ErrorCodes.AUTH_LOGOUT_FAILED,
                message="安全退出失败, 请稍后重试",
            ) from e
    
    @staticmethod
    def _clean_token(token: Optional[str]) -> Optional[str]:
        """
        清洗 token
        """
        if not token:
            return None
        v = token.strip()
        return v or None
