from __future__ import annotations
"""
用户密码重置服务类

包含两个阶段:
1. PasswordResetRequestService: 申请密码重置验证码
2. PasswordResetConfirmService: 校验验证码并重置密码

设计要点:
- 不泄露账号是否存在: 申请阶段对外统一返回成功
- Redis 不保存明文验证码/明文密码: 只保存验证码 SHA256
- 确认阶段加分布式锁: 防止同一邮箱并发改密
- 确认阶段支持 Idempotency-Key: 防止重复提交
- 改密成功后 bump sess_ver: 使旧 JWT 全部失效
"""
import hashlib, json, secrets
from typing import Any, Dict, Optional, cast
from django.conf import settings
from users.models import User
from django.db import transaction

from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.locks import build_lock
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client
from openai_chat.settings.utils.redis.idempotency import (
    IdempotencyExecutor,
    IdempotencyInProgressError,
    IdempotencyKeyConflictError,
)
from tasks.email_tasks import send_email_async_task
from users.services.user_state_service import UserStateService

logger = get_logger("users")

class PasswordResetRequestService:
    """
    密码重置申请服务类
    
    输入:
    - validated_data: serializer 校验后的数据, 至少包含 email
    - cf_token: Turnstile token, 当前保留接口位
    - remote_ip: 客户端 IP, 用于日志和后续风控
    
    输出:
    - dict: 传给 view 的 json_response.data
    """
    RESET_TTL_SECONDS = 15 * 60
    COOLDOWN_TTL_SECONDS = 60
    
    KEY_PREFIX_RESET = "password_reset:pending"
    KEY_PREFIX_COOLDOWN = "password_reset:cooldown"
    
    def __init__(self, validated_data: Dict[str, Any], cf_token: str = "", remote_ip: str = "") -> None:
        self.validated_data = validated_data
        self.email = str(validated_data["email"]).strip().lower()
        self.cf_token = str(cf_token or "")
        self.remote_ip = str(remote_ip or "")
        
        redis_db = getattr(
            settings,
            "REDIS_DB_USERS_PASSWORD_RESET_CACHE",
            getattr(settings, "REDIS_DB_USERS_REGISTER_CACHE", 0),
        )
        self.redis = cast(Any, get_redis_client(db=redis_db))
        
    def _key_reset(self) -> str:
        return f"{self.KEY_PREFIX_RESET}:{self.email}"
    
    def _key_cooldown(self) -> str:
        return f"{self.KEY_PREFIX_COOLDOWN}:{self.email}"
    
    @staticmethod
    def _generate_verify_code() -> str:
        """生成6位安全随机验证码"""
        return f"{secrets.randbelow(10**6):06d}"
    
    @staticmethod
    def _hash_verify_code(code: str) -> str:
        """验证码入库前, 先进行哈希转换, 避免Redis泄露后可直接使用验证码"""
        return hashlib.sha256(code.encode("utf-8")).hexdigest()
    
    def _send_email_async(self, verify_code: str, biz_key: str) -> None:
        subject = "【OpenAI Chat】密码重置验证码"
        html_body = (
            f"<p>您的密码重置验证码是: <strong>{verify_code}</strong></p>"
            f"<p>验证码有效期 15 分钟。如非本人操作, 请忽略此邮件。</p>"
        )
        
        try:
            task = cast(Any, send_email_async_task)
            task.delay(
                biz_key=biz_key,
                to_email=self.email,
                subject=subject,
                html_content=html_body,
            )
        except Exception as exc:
            logger.exception("[password_reset] send email task failed", extra={"email": self.email})
            self.redis.delete(self._key_reset(), self._key_cooldown())
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_ERROR,
                message="验证码发送失败, 请稍后重试",
            ) from exc
    
    def process(self) -> Dict[str, Any]:
        """
        申请密码重置验证码
        
        安全策略:
        - 先写入冷却key, 对存在和不存在的账号都限流
        - 账号不存在、禁用、注销时不发邮件, 但对外仍返回成功
        """
        cooldown_key = self._key_cooldown()
        try:
            cooldown_ok = self.redis.set(
                cooldown_key,
                "1",
                nx=True,
                ex=self.COOLDOWN_TTL_SECONDS + secrets.randbelow(10),
            )
        except Exception as exc:
            logger.exception("[password_reset] cooldown redis failed", extra={"email": self.email})
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_ERROR,
                message="系统繁忙, 请稍后重试",
            ) from exc
        
        if not cooldown_ok:
            ttl_raw = self.redis.ttl(cooldown_key)
            ttl = int(ttl_raw) if ttl_raw is not None else -1
            raise AppException.bad_request(
                code=ErrorCodes.RATE_LIMIT_TOO_MANY_REQUESTS,
                message=f"验证码已发送, 请勿重复操作({ttl} 秒后可重新申请)" if ttl > 0 else "验证码已发送, 请勿重复操作",
                data={"retry_after": ttl} if ttl > 0 else {},
            )
        
        user = cast(User, User.objects.filter(email__iexact=self.email).only(
            "id",
            "email",
            "is_active",
            "is_deleted",
        ).first())
        
        if not user or bool(getattr(user, "is_deleted", False)) or not bool(getattr(user, "is_active", True)):
            logger.info("[password_reset] request ignored for unavailable account email=%s", self.email)
            return {
                "email": self.email,
                "expire_in": self.RESET_TTL_SECONDS,
                "cooldown_in": self.COOLDOWN_TTL_SECONDS,
            }
            
        verify_code = self._generate_verify_code()
        verify_code_hash = self._hash_verify_code(verify_code)
        
        payload = {
            "email": self.email,
            "user_id": str(user.id),
            "verify_code_hash": verify_code_hash,
        }
        
        try:
            self.redis.set(
                self._key_reset(),
                json.dumps(payload, ensure_ascii=False),
                ex=self.RESET_TTL_SECONDS,
            )
        except Exception as exc:
            logger.exception("[password_reset] write reset cache failed", extra={"email": self.email})
            self.redis.delete(cooldown_key)
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_ERROR,
                message="系统繁忙, 请稍后重试",
            ) from exc
        
        biz_key = f"password_reset:email:verify:{self.email}:{verify_code_hash}"
        self._send_email_async(verify_code=verify_code, biz_key=biz_key)
        
        return {
            "email": self.email,
            "expire_in": self.RESET_TTL_SECONDS,
            "cooldown_in": self.COOLDOWN_TTL_SECONDS,
        }
        
class PasswordResetConfirmService:
    """
    密码重置确认服务类
    
    输入:
    - email
    - verify_code
    - new_password
    """
    KEY_PREFIX_RESET = "password_reset:pending"
    KEY_PREFIX_COOLDOWN = "password_reset:cooldown"
    KEY_PREFIX_CODE_ERR = "password_reset:code_err"
    KEY_PREFIX_LOCK = "lock:password_reset:confirm"

    IDEM_SCOPE = "users:password_reset:confirm"

    MAX_ERR_TIMES = 5
    RESET_TTL_SECONDS = 15 * 60
    ERR_TTL_JITTER_SECONDS = 15
    LOCK_TTL_SECONDS = 15
    LOCK_STRATEGY = "safe"
    
    def __init__(self, *, email: str, verify_code: str, new_password: str) -> None:
        self.email = str(email or "").strip().lower()
        self.verify_code = str(verify_code or "").strip()
        self.new_password = str(new_password or "")
        
        redis_db = getattr(
            settings,
            "REDIS_DB_USERS_PASSWORD_RESET_CACHE",
            getattr(settings, "REDIS_DB_USERS_REGISTER_CACHE", 0),
        )
        self.redis = cast(Any, get_redis_client(db=redis_db))
        self.idem = IdempotencyExecutor()
        
    @staticmethod
    def _error_code(name: str, fallback: str = "COMMON_ERROR") -> Any:
        return getattr(ErrorCodes, name, getattr(ErrorCodes, fallback))
    
    def _key_reset(self) -> str:
        return f"{self.KEY_PREFIX_RESET}:{self.email}"
    
    def _key_cooldown(self) -> str:
        return f"{self.KEY_PREFIX_COOLDOWN}:{self.email}"
    
    def _key_err(self) -> str:
        return f"{self.KEY_PREFIX_CODE_ERR}:{self.email}"
    
    def _key_lock(self) -> str:
        return f"{self.KEY_PREFIX_LOCK}:{self.email}"
    
    @staticmethod
    def _to_str(raw: Any) -> str:
        if raw is None:
            return ""
        if isinstance(raw, (bytes, bytearray)):
            return raw.decode("utf-8", errors="ignore")
        return str(raw)

    @staticmethod
    def _hash_verify_code(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    def _request_fingerprint(self) -> str:
        """
        将请求语义绑定到 Idempotency-Key。
        注意: 不把 new_password 明文放入 Redis, 只使用哈希参与指纹计算
        """
        payload = {
            "email": self.email,
            "verify_code_hash": self._hash_verify_code(self.verify_code),
            "new_password_hash": hashlib.sha256(self.new_password.encode("utf-8")).hexdigest(),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    
    def _load_reset_info(self) -> Optional[Dict[str, Any]]:
        raw = self.redis.get(self._key_reset())
        if not raw:
            return None

        try:
            data = json.loads(self._to_str(raw))
            return data if isinstance(data, dict) else None
        except Exception:
            logger.exception("[password_reset] reset cache parse failed", extra={"email": self.email})
            return None

    def _increase_err_count(self, reset_ttl: int) -> int:
        err_key = self._key_err()
        count = int(self.redis.incr(err_key))

        if count == 1:
            ttl_base = reset_ttl if reset_ttl > 0 else self.RESET_TTL_SECONDS
            self.redis.expire(err_key, ttl_base + secrets.randbelow(self.ERR_TTL_JITTER_SECONDS + 1))

        return count

    def _validate_and_get_cached_info(self) -> Dict[str, Any]:
        cached_info = self._load_reset_info()
        if not cached_info:
            raise AppException.bad_request(
                code=self._error_code("PASSWORD_RESET_CODE_EXPIRED"),
                message="验证码已过期, 请重新获取",
            )

        reset_ttl = int(self.redis.ttl(self._key_reset()) or -1)
        expected_hash = str(cached_info.get("verify_code_hash", "")).strip()

        if not expected_hash:
            raise AppException.bad_request(
                code=self._error_code("PASSWORD_RESET_DATA_INVALID"),
                message="重置信息异常, 请重新获取验证码",
            )

        if self._hash_verify_code(self.verify_code) != expected_hash:
            err_times = self._increase_err_count(reset_ttl)

            if err_times >= self.MAX_ERR_TIMES:
                self.redis.delete(self._key_reset())
                raise AppException.forbidden(
                    code=self._error_code("PASSWORD_RESET_CODE_LIMIT"),
                    message="验证码错误次数过多, 请重新获取验证码",
                )

            remaining = self.MAX_ERR_TIMES - err_times
            raise AppException.forbidden(
                code=self._error_code("PASSWORD_RESET_CODE_INVALID"),
                message=f"验证码错误, 还可尝试 {remaining} 次",
                data={"remaining_times": remaining},
            )

        self.redis.delete(self._key_err())
        return cached_info

    def _clear_cache(self) -> None:
        try:
            self.redis.delete(self._key_reset(), self._key_err(), self._key_cooldown())
        except Exception:
            logger.exception("[password_reset] clear cache failed", extra={"email": self.email})

    def _biz_confirm(self) -> Dict[str, Any]:
        cached_info = self._validate_and_get_cached_info()
        user_id = str(cached_info.get("user_id", "")).strip()

        if not user_id:
            raise AppException.bad_request(
                code=self._error_code("PASSWORD_RESET_DATA_INVALID"),
                message="重置信息异常, 请重新获取验证码",
            )

        lock_ttl_ms = int(self.LOCK_TTL_SECONDS * 1000)

        with build_lock(key=self._key_lock(), ttl=lock_ttl_ms, strategy=self.LOCK_STRATEGY).lock() as acquired:
            if not acquired:
                raise AppException.bad_request(
                    code=self._error_code("COMMON_SYSTEM_BUSY", fallback="COMMON_ERROR"),
                    message="请求处理中, 请勿重复提交",
                )

            with transaction.atomic():
                user = User.objects.select_for_update().filter(id=user_id, email__iexact=self.email).first()
                if not user:
                    raise AppException.bad_request(
                        code=self._error_code("PASSWORD_RESET_ACCOUNT_INVALID"),
                        message="账号状态异常, 请重新获取验证码",
                    )

                if bool(getattr(user, "is_deleted", False)) or not bool(getattr(user, "is_active", True)):
                    raise AppException.forbidden(
                        code=self._error_code("PASSWORD_RESET_ACCOUNT_INVALID"),
                        message="账号状态异常, 无法重置密码",
                    )

                # 关键位置: 使用 Django set_password, 确保密码按项目 PASSWORD_HASHERS 安全哈希。
                user.set_password(self.new_password)
                user.save(update_fields=["password"])

                # 关键位置: 改密成功后提升 sess_ver, 让旧 access/refresh token 全部失效。
                new_sess_ver = UserStateService.invalidate_sessions(
                    int(user.id),
                    reason="password_reset",
                )

        self._clear_cache()

        logger.info("[password_reset] password reset ok user_id=%s email=%s", user_id, self.email)

        return {
            "user_id": int(user_id),
            "email": self.email,
            "status": "PASSWORD_RESET",
            "sess_ver": new_sess_ver,
        }

    def execute_confirm(self, *, idem_key: str, ttl_seconds: int = 0) -> Dict[str, Any]:
        if not idem_key:
            raise AppException.bad_request(
                code=self._error_code("IDEMPOTENCY_KEY_MISSING"),
                message="缺少 Idempotency-Key",
            )

        try:
            return self.idem.execute(
                scope=self.IDEM_SCOPE,
                idem_key=idem_key,
                ttl_seconds=ttl_seconds,
                func=self._biz_confirm,
                allow_retry_after_failed=True,
                request_fingerprint=self._request_fingerprint(),
            )

        except IdempotencyInProgressError:
            raise AppException.bad_request(
                code=self._error_code("IDEMPOTENCY_IN_PROGRESS"),
                message="请求处理中, 请勿重复提交",
            )

        except IdempotencyKeyConflictError:
            raise AppException.bad_request(
                code=self._error_code("IDEMPOTENCY_KEY_CONFLICT"),
                message="请求参数已变化, 请更换 Idempotency-Key",
            )

        except AppException:
            raise

        except Exception as exc:
            logger.exception("[password_reset] unexpected error", extra={"email": self.email})
            raise AppException.bad_request(
                code=self._error_code("COMMON_ERROR"),
                message="系统异常, 请稍后重试",
            ) from exc