from __future__ import annotations
"""
用户注册确认服务类

设计:
- validate_code(): 读取 prereg 缓存 + 校验验证码hash + 错误计数
- 复用 IdempotencyExecutor 做接口幂等()
- 邮箱粒度写入互斥：lock:register:confirm:{email} (最小锁范围，仅包写库)
- create_user(): 加锁后落库 + 幂等检查
- clear_cache(): 清理 prereg / 错误计数 / cooldown
- Service 层失败统一抛 AppException(携带 ErrorCodes 与 message)
- 成功返回 dict(用于幂等缓存回放)
"""
import json, hashlib, secrets, time
from typing import Any, Dict, Optional, cast
from django.contrib.auth import get_user_model
from django.db import transaction # 数据库事务(原子写库)
from django.conf import settings

from openai_chat.settings.utils.redis import get_redis_client
from openai_chat.settings.utils.locks import build_lock # Redlock 分布式锁构建
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.exceptions import AppException # 业务异常：统一抛出（DRF异常处理器负责输出）
from openai_chat.settings.utils.error_codes import ErrorCodes # 错误码常量表

# 幂等性模块(Redis + Lua 状态机)
from openai_chat.settings.utils.redis.idempotency import (
    IdempotencyExecutor,
    IdempotencyInProgressError,
    IdempotencyKeyConflictError,
)

logger = get_logger("users")
User = get_user_model()

class ConfirmRegisterService:
    """
    用户注册确认服务类(幂等 + 并发互斥 + 业务抛错标准化)
    - prereg 校验
    - Redlock 写库互斥
    - 幂等执行(绑定 request fingerprint)
    """
    # Redis key 前缀
    KEY_PREFIX_PREREG = "register:prereg" # 预注册信息 key
    KEY_PREFIX_COOLDOWN = "register:cooldown" # 冷却窗口 key
     
    # 验证码错误计数 key
    KEY_PREFIX_CODE_ERR = "register:prereg:code_err"
    
    # 邮箱粒度写入锁 key (idem_key 写入互斥)
    KEY_PREFIX_LOCK = "lock:register:confirm"
    
    # 幂等 scope (固定字符串, 避免跨接口污染)
    IDEM_SCOPE = "users:register:confirm"
    
    # ---业务参数---
    MAX_ERR_TIMES = 5 # 验证码最大错误次数
    DEFAULT_PREREG_TTL_SECONDS = 900 # prereg 默认 TTL
    ERR_TTL_JITTER_SECONDS = 15 # 错误计数 TTL 抖动
    # 锁参数(写库阶段)
    LOCK_TTL_SECONDS = 15 # 锁过期时间
    LOCK_STRATEGY = "safe" # "safe"=RedLock
    
    def __init__(self, *, email: str, verify_code: str) -> None:
        self.email = email
        self.verify_code = verify_code
        
        # 注册缓存分库(与预注册一致)
        redis_db = getattr(settings, "REDIS_DB_USERS_REGISTER_CACHE", 0)
        self.redis = cast(Any, get_redis_client(db=redis_db))
        
        # 幂等执行器
        self.idem = IdempotencyExecutor()
    
    # 错误码工具
    @staticmethod
    def _error_code(name: str, fallback: str = "COMMON_ERROR") -> Any:
        """
        安全获取 ErrorCodes 中的错误码常量
        - name 不存在时使用 fallback
        """
        return getattr(ErrorCodes, name, getattr(ErrorCodes, fallback))
    
    # Key 构造(集中维护)
    def _key_prereg(self) -> str:
        # 用户预注册缓存信息 key
        return f"{self.KEY_PREFIX_PREREG}:{self.email}"
    
    def _key_cooldown(self) -> str:
        # 冷却窗口 key
        return f"{self.KEY_PREFIX_COOLDOWN}:{self.email}"
    
    def _key_err(self) -> str:
        # 验证码错误计数 key
        return f"{self.KEY_PREFIX_CODE_ERR}:{self.email}"
    
    def _key_lock(self) -> str:
        # 锁 key
        return f"{self.KEY_PREFIX_LOCK}:{self.email}"
    
    # bytes -> str 处理: 适配 decode_response=False 的 Redis 返回
    @staticmethod
    def _to_str(raw: Any) -> str:
        if raw is None:
            return ""
        if isinstance(raw, (bytes, bytearray)):
            return raw.decode("utf-8", errors="ignore")
        return str(raw)
    
    # verify_code -> hash
    @staticmethod
    def _hash_verify_code(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()
    
    # 幂等请求指纹
    def _request_fingerprint(self) -> str:
        """
        将"请求身份"绑定到幂等key:
        - email
        注: 任何变化都将视为不同请求
        """
        # 使用 token_hex 作为 register_token, 替代验证码
        payload = f"{self.email}|{secrets.token_hex(16)}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    
    # 读取与解析 prereg 缓存
    def _load_prereg_info(self) -> Optional[Dict[str, Any]]:
        """
        从 Redis 读取 prereg JSON, 并解析为 dict
        """
        raw = self.redis.get(self._key_prereg())
        if not raw:
            return None
        try:
            text = self._to_str(raw)
            data = json.loads(text)
            return data if isinstance(data, dict) else None
        except Exception:
            logger.exception("[register_confirm] prereg 缓存解析失败", extra={"email": self.email})
            return None
    
    # Verify_code 错误计数(INCR + 首次设置TTL-TTL抖动)
    def _increase_err_count(self, prereg_ttl: int) -> int:
        err_key = self._key_err()
        cnt = int(self.redis.incr(err_key))
        
        # 首次出现错误时设置TTL
        if cnt == 1:
            ttl_base = prereg_ttl if isinstance(prereg_ttl, int) and prereg_ttl > 0 else self.DEFAULT_PREREG_TTL_SECONDS
            ttl = ttl_base + secrets.randbelow(self.ERR_TTL_JITTER_SECONDS + 1)
            try:
                self.redis.expire(err_key, ttl)
            except Exception:
                # TTL 设置失败不阻塞主流程
                pass
        return cnt
    
    # 校验 prereg + verify_code
    # - 失败抛 AppException(携带错误码与message)
    def _validate_and_get_cached_info(self) -> Dict[str, Any]:
        """
        返回: prereg dict(包含 pasword_hash / verify_code_hash)
        """
        cached_info = self._load_prereg_info()
        if not cached_info:
            # prereg 缓存不存在/过期: 注册确认无法继续
            raise AppException.bad_request(
                code=self._error_code("REGISTER_PREINFO_EXPIRED"),
                message="请求的邮箱不存在, 预注册信息已失效，请重新发起注册"
            )
        
        # 读取 prereg TTL: 用于限制错误计数 TTL
        prereg_ttl = -1
        try:
            ttl_raw = self.redis.ttl(self._key_prereg())
            prereg_ttl = int(ttl_raw) if ttl_raw is not None else -1
        except Exception:
            prereg_ttl = -1
            
        expected_hash = str(cached_info.get("verify_code_hash", "")).strip()
        if not expected_hash:
            # prereg 数据结构异常: 提示用户重新发起注册
            raise AppException.bad_request(
                code=self._error_code("REGISTER_DATA_INVALID"),
                message="注册信息异常, 请重新发起注册",
            )
        
        # 输入验证码 hash 与 缓存 hash比对校验
        input_code_hash = self._hash_verify_code(self.verify_code)
        if input_code_hash != expected_hash:
            err_times = self._increase_err_count(prereg_ttl=prereg_ttl)
            logger.warning("[register_confirm] 验证码错误", extra={"email": self.email, "err_times": err_times})
            
            if err_times >= self.MAX_ERR_TIMES:
                # 达到阈值: 删除 prereg, 强制用户重新发起注册流程
                try:
                    self.redis.delete(self._key_prereg())
                except Exception:
                    pass
                
                raise AppException.forbidden(
                    code=self._error_code("REGISTER_VERIFY_CODE_LIMIT"),
                    message="验证码错误次数超过限制, 请重新获取验证码",
                )
            
            remaining = self.MAX_ERR_TIMES - err_times
            raise AppException.forbidden(
                code=self._error_code("REGISTER_VERIFY_CODE_INVALID"),
                message=f"验证码错误: 还可尝试 {remaining} 次",
                data={"remaining_times": remaining},
            )
        
        # 校验通过: 清理错误计数
        try:
            self.redis.delete(self._key_err())
        except Exception:
            pass
        
        return cached_info
    
    
    # 成功后清理缓存: prereg / err / cooldown
    # - 清理失败不影响业务成功结果, 记录日志
    def _clear_cache(self) -> None:
        try:
            self.redis.delete(self._key_prereg(), self._key_err(), self._key_cooldown())
        except Exception:
            logger.exception("[register_confirm] 清理注册缓存失败", extra={"email": self.email})
            
    
    # === 业务主流程 ===
    def _biz_confirm(self) -> Dict[str, Any]:
        """
        单次'注册确认'业务执行:
        1) 校验 prereg + verify_code
        2) 获取邮箱写入锁
        3) 事务写库（邮箱已存在视为幂等成功）
        4) 清理缓存
        """
        cached_info = self._validate_and_get_cached_info()
        
        # 锁只包写库临界区
        lock_key = self._key_lock()
        
        # build_lock.ttl 单位: 毫秒
        lock_ttl_ms = int(self.LOCK_TTL_SECONDS * 1000)
        
        with build_lock(key=lock_key, ttl=lock_ttl_ms, strategy=self.LOCK_STRATEGY) as acquired:
            if not acquired:
                # 未拿到锁: 同邮箱正在被其他并发请求处理
                raise AppException.bad_request(
                    code=self._error_code("COMMON_SYSTEM_BUSY", fallback="COMMON_ERROR"),
                    message="请求处理中, 请勿重复提交",
                )
                
            # 获取锁后进入事务写库
            with transaction.atomic():
                # 幂等语义: 邮箱已存在 -> 视为成功(避免弱网重试得到 409)
                existing = User.objects.filter(email=self.email).only("pk").first()
                if existing:
                    user_id = int(existing.pk)
                    logger.info("[register_confirm] 邮箱已存在, 幂等成功回放", extra={"email": self.email, "user_id": user_id})
                    # 即使存在, 也执行 prereg 残留清理
                    self._clear_cache()
                    return {"user_id": user_id, "email": self.email, "status": "ALREADY_REGISTERED"}
                    
                password_hash = str(cached_info.get("password_hash", "")).strip()
                if not password_hash:
                    # prereg 数据异常: 引导用户重新发起注册流程
                    raise AppException.bad_request(
                        code=self._error_code("REGISTER_DATA_INVALID"),
                        message="注册信息异常, 请重新发起注册",
                    )
                    
                # 从 prereg 缓存读取 pheon_number(可能为空或不存在)
                phone_number = str(cached_info.get("phone_number", "")).strip()
                    
                # create_kwargs: 基础字段(必须写入)
                create_kwargs: Dict[str, Any] = {
                    "email": self.email,
                    "password": password_hash,
                    "username": self.email, # username 默认写为 email
                }
                    
                # 当 prereg 缓存里存在 phone_number字段值时写入
                if phone_number:
                    create_kwargs["phone"] = phone_number
                    
                # 写库(创建用户)
                user = User.objects.create(**create_kwargs)
                
        # 锁已释放(build_lock负责), 写库成功后清理缓存
        self._clear_cache()
                
        logger.info("[register_confirm] 用户创建成功", extra={"email": self.email, "user_id": user.pk})
        return {"user_id": int(user.pk), "email": self.email, "status": "REGISTERED"}
            
    # === 对外入口: 幂等注册确认(View直接调用) ===
    def execute_confirm(self, *, idem_key: str, ttl_seconds: int = 0) -> Dict[str, Any]:
        """
        幂等注册确认入口(Service层API)
        
        参数:
        - idem_key：View 透传的 Idempotency-Key（必填）
        - ttl_seconds：幂等缓存 TTL（<=0 使用 IdempotencyExecutor 默认 10min）
        
        返回:
        - dict: 用于 json_response.data(同时会被幂等模块缓存用于重复请求回放)
        
        失败:
        - 统一抛 AppException(携带 code/message/http_status)
        """
        if not idem_key:
            # 幂等 key 缺失, 明确提示
            raise AppException.bad_request(
                code=self._error_code("IDEMPOTENCY_KEY_MISSING"),
                message="缺少 Idempotency-key",
            )
        
        # 绑定请求指纹
        fingerprint = self._request_fingerprint()
        
        try:
            # IdempotencyExecutor
            # - NEW：写 PENDING -> 执行 func -> SUCCEEDED 缓存 result
            # - DONE：直接回放缓存 result
            # - PENDING：抛 IdempotencyInProgressError
            # - FAILED：允许重试（allow_retry_after_failed=True）
            return self.idem.execute(
                scope=self.IDEM_SCOPE,
                idem_key=idem_key,
                ttl_seconds=ttl_seconds,
                func=self._biz_confirm,
                allow_retry_after_failed=True,
                request_fingerprint=fingerprint,
            )
        
        except IdempotencyInProgressError:
            # 同一幂等 key 正在处理中, 提示客户端稍后重试
            raise AppException.bad_request(
                code=self._error_code("IDEMPOTENCY_IN_PROGRESS"),
                message="请求处理中, 请勿重复提交",
            )
        
        except IdempotencyKeyConflictError:
            # 不同请求体却复用同一 Idempotency-Key
            raise AppException.bad_request(
                code=self._error_code("IDEMPOTENCY_KEY_CONFLICT"),
                message="请求参数已变化，请更换 Idempotency-Key",
            )
        
        except AppException:
            # 业务异常: 原样抛出(DRF统一异常处理器输出标准响应)
            raise
        
        except Exception:
            # 系统异常: 统一转 AppException，避免泄露内部错误
            logger.exception("[register_confirm] 未捕获系统异常", extra={"email": self.email})
            raise AppException.bad_request(
                code=self._error_code("COMMON_ERROR"),
                message="系统异常, 请稍后重试",
            )