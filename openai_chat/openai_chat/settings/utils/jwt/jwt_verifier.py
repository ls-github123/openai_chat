"""
JWT 验证器模块(ES256)

功能:
- 仅负责“技术验证”（结构解析、验签、claims 校验、黑名单校验、缓存）
- 不负责业务异常映射，不返回 HTTP/JSON，不抛 AppException
- 统一抛 JWTValidationError，由上层（jwt_auth / service）转换为业务错误

注:
- 只接受 ES256 JWT
- 缓存命中后仍执行 claims + 黑名单校验，避免"缓存绕过撤销"
- 公钥（PEM）缓存到 Redis（默认 1 小时）
- payload 结果短缓存（默认不超过 60 秒，且不超过 token 剩余寿命）
- 验签失败时支持“强制刷新公钥再验一次”（应对密钥轮换窗口）
"""
from __future__ import annotations
import base64, hashlib, json, time, uuid
from typing import Any, Dict, Optional, Union, cast
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from django.conf import settings
from openai_chat.settings.base import REDIS_DB_JWT_CACHE
from openai_chat.settings.utils.locks import build_lock
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client
from .jwt_blacklist import is_blacklisted

logger = get_logger("project.jwt")

class JWTValidationError(Exception):
    """JWT 验证失败统一异常"""
    def __init__(self, message: str):
        super().__init__(f"[JWT Verify Error] {message}")

class AzureES256Verifier:
    """
    ES256 JWT 验证器(Azure Key Vault公钥)
    
    主要功能:
    - 从 Key Vault 读取 EC(P-256) 公钥参数 x/y 并构造公钥对象
    - 验证 JWT 签名(ES256)
    - 校验 claims (exp/iat/nbf/iss/aud/sub/jti/typ/scope/sv)
    - 黑名单校验(jti)
    - Redis 缓存公钥与 payload
    
    注:
    - JWT ES256 签名格式是 raw(r||s, 64 bytes)
    """
    _instance: Optional[AzureES256Verifier] = None
    ALGORITHM = "ES256"
    
    def __init__(self, vault_url: str, key_name: str, redis_prefix: str = "jwt:verify:"):
        self.vault_url = vault_url
        self.key_name = key_name
        self.redis_prefix = redis_prefix.decode() if isinstance(redis_prefix, bytes) else redis_prefix
        
        # Redis 用于缓存公钥与payload
        self.redis = get_redis_client(db=REDIS_DB_JWT_CACHE)
        
        # Azure SDK 客户端
        self.credential = DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=self.vault_url, credential=self.credential)
        
        # 初始化公钥(优先读取缓存)
        self.public_key = self._load_or_cache_public_key(force_refresh=False)
    
    @property
    def _is_dev(self) -> bool:
        """
        环境判定:
        -  DEBUG=True 或 ENVIRONMENT=dev 视为开发环境
        - 开发环境默认不启用 payload 缓存(便于调试一致性)
        """
        env = str(getattr(settings, "ENVIRONMENT", "")).lower()
        return bool(getattr(settings, "DEBUG", False)) or env == "dev"
    
    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        """
        Base64URL 解码(自动补齐 '=' padding)
        """
        data += "=" * ((4 - len(data) % 4) % 4)
        return base64.urlsafe_b64decode(data.encode("utf-8"))
    
    @staticmethod
    def _raw_to_int(value: Union[str, bytes, int]) -> int:
        """
        将密钥参数统一转换为 int
        - int 直接返回
        - bytes 按大端整数
        - str 按 base64url 解码后再转大端整数
        """
        if isinstance(value, int):
            return value
        if isinstance(value, bytes):
            return int.from_bytes(value, "big")
        if isinstance(value, str):
            raw = AzureES256Verifier._b64url_decode(value)
            return int.from_bytes(raw, "big")
        raise TypeError(f"Unsupported key parameter type: {type(value)}")
    
    @staticmethod
    def _jws_raw_to_der(raw_sig: bytes, part_len: int = 32) -> bytes:
        """
        JWT ES256 签名 raw(r||s) -> DER 转换
        ES256 使用 P-256曲线
        - r: 32 bytes
        - s: 32 bytes
        - 总长度必须 64 bytes
        """
        if len(raw_sig) != part_len * 2:
            raise JWTValidationError("Invalid ES256 signature length (expect 64 bytes)")
        
        r = int.from_bytes(raw_sig[:part_len], "big")
        s = int.from_bytes(raw_sig[part_len:], "big")
        return asym_utils.encode_dss_signature(r, s)
    
    def _expected_issuer(self) -> str:
        return str(getattr(settings, "JWT_ISSUER", "openai-chat.xyz"))
    
    def _expected_audience(self) -> str:
        return str(getattr(settings, "JWT_AUDIENCE", "openai_chat_user"))
    
    def _allowed_scopes(self) -> set[str]:
        """
        允许的 scope 集合。
        可通过 settings.JWT_ALLOWED_SCOPES 覆盖
        """
        scopes = getattr(settings, "JWT_ALLOWED_SCOPES", {"user", "admin", "super", "refresh"})
        return {str(s) for s in scopes}
    
    def _load_or_cache_public_key(self, force_refresh: bool = False) -> ec.EllipticCurvePublicKey:
        """
        加载 ES256 公钥 (P-256)：
        1) 非 force_refresh 时先读 Redis PEM 缓存；
        2) 未命中或强制刷新则从 Azure Key Vault 读取 x/y 构建公钥；
        3) 写回 Redis(失败仅告警，不阻断主流程)。
        """
        cache_key = f"{self.redis_prefix}pem:{self.ALGORITHM}:{self.key_name}"
        lock_key = f"lock:jwt:publickey:{self.ALGORITHM}:{self.key_name}"
        
        # 分布式锁: 避免并发下重复回源 Azure
        with build_lock(lock_key, ttl=3000, strategy="safe"):
            if not force_refresh:
                try:
                    pem_cached = self.redis.get(cache_key)
                    if pem_cached:
                        pem_bytes = pem_cached if isinstance(pem_cached, bytes) else str(pem_cached).encode("utf-8")
                        key = serialization.load_pem_public_key(pem_bytes)
                        if not isinstance(key, ec.EllipticCurvePublicKey):
                            raise JWTValidationError("Cached key type mismatch: expect EC public key")
                        return key
                except Exception as e:
                    logger.warning("[JWT Verify] read public key cache failed: %s", e)
            
            # 回源 Azure Key Vault
            key_bundle = self.key_client.get_key(name=self.key_name)
            x_raw = getattr(key_bundle, "x", None)
            y_raw = getattr(key_bundle, "y", None)
            
            if x_raw is None or y_raw is None:
                raise JWTValidationError("Azure EC key missing x/y")
            
            public_numbers = ec.EllipticCurvePublicNumbers(
                x=self._raw_to_int(x_raw),
                y=self._raw_to_int(y_raw),
                curve=ec.SECP256R1(),
            )
            public_key = public_numbers.public_key()
            
            try:
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
                self.redis.set(cache_key, pem, ex=3600, nx=not force_refresh) # 1小时缓存，force_refresh时强制覆盖
            except Exception as e:
                logger.warning("[JWT Verify] write public key cache failed: %s", e)
            
            return public_key
    
    def _verify_signature_with_rotation(self, signing_input: bytes, raw_signature: bytes) -> None:
        """
        验签并处理密钥轮换窗口：
        - 第一次验签失败（InvalidSignature）时，强制刷新公钥再验一次；
        - 若仍失败则判定签名无效。
        """
        der_signature = self._jws_raw_to_der(raw_signature, part_len=32)
        
        def _do_verify(pub_key: ec.EllipticCurvePublicKey) -> None:
            pub_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
        
        try:
            _do_verify(self.public_key)
        except InvalidSignature:
            # 可能发生密钥轮换, 强制刷新公钥后再校验
            self.public_key = self._load_or_cache_public_key(force_refresh=True)
            try:
                _do_verify(self.public_key)
                return
            except Exception as e:
                raise JWTValidationError(f"Token signature invalid after key refresh: {e}") from e
        except Exception as e:
            raise JWTValidationError(f"Token signature verify failed: {e}") from e
    
    @staticmethod
    def _validate_sub(sub: Any) -> None:
        """
        sub 约束（项目语义）：
        - 必须是数字字符串（用户ID字符串化）。
        """
        if not isinstance(sub, str) or not sub.isdigit():
            raise JWTValidationError("Token sub invalid")
    
    @staticmethod
    def _validate_jti(jti: Any) -> str:
        """
        jti 约束：
        - 必须是 UUID 字符串。
        """
        if not isinstance(jti, str):
            raise JWTValidationError("Token jti invalid")

        try:
            uuid.UUID(jti)
            return jti
        except Exception as e:
            raise JWTValidationError(f"Token jti invalid: {e}") from e
    
    def _validate_claims(self, payload: Dict[str, Any]) -> str:
        """
        claims 校验，返回 jti（供黑名单校验）：
        - exp 必须存在且未过期
        - iat 必须存在且不在未来
        - nbf 如存在则必须已生效
        - iss/aud/sub/jti/typ/scope/sv（可选）必须合法
        """
        now = int(time.time())

        # exp
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)):
            raise JWTValidationError("Token exp missing or invalid")
        if now > int(exp):
            raise JWTValidationError("Token expired")

        # iat
        iat = payload.get("iat")
        if not isinstance(iat, (int, float)) or int(iat) > now:
            raise JWTValidationError("Token iat invalid")

        # nbf（可选）
        nbf = payload.get("nbf")
        if nbf is not None:
            if not isinstance(nbf, (int, float)) or int(nbf) > now:
                raise JWTValidationError("Token nbf invalid")

        # sub / iss / aud
        self._validate_sub(payload.get("sub"))

        if payload.get("iss") != self._expected_issuer():
            raise JWTValidationError("Token issuer mismatch")

        expected_aud = self._expected_audience()
        aud = payload.get("aud")
        if isinstance(aud, list):
            if expected_aud not in aud:
                raise JWTValidationError("Token audience mismatch")
        elif aud != expected_aud:
            raise JWTValidationError("Token audience mismatch")

        # typ / scope
        if payload.get("typ") not in {"access", "refresh"}:
            raise JWTValidationError("Token typ invalid")

        if payload.get("scope") not in self._allowed_scopes():
            raise JWTValidationError("Token scope invalid")

        # sv（可选，会话版本号）
        sv = payload.get("sv")
        if sv is not None:
            try:
                if int(sv) < 1:
                    raise ValueError("sv < 1")
            except Exception as e:
                raise JWTValidationError(f"Token sv invalid: {e}") from e

        return self._validate_jti(payload.get("jti"))
    
    @staticmethod
    def _ensure_not_blacklisted(jti: str) -> None:
        """
        黑名单校验。
        约定：is_blacklisted 内部应 fail-closed（依赖异常时按“已撤销”处理）。
        """
        try:
            if is_blacklisted(jti):
                raise JWTValidationError("Token revoked")
        except JWTValidationError:
            raise
        except Exception as e:
            raise JWTValidationError(f"Blacklist check failed: {e}") from e

    def _read_payload_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """
        读取 payload 缓存。
        - 成功返回 dict
        - 异常或脏数据返回 None（不中断主流程）
        """
        try:
            cached_raw = self.redis.get(key)
            if not cached_raw:
                return None

            if isinstance(cached_raw, str):
                payload_json = cached_raw
            elif isinstance(cached_raw, (bytes, memoryview)):
                payload_json = bytes(cached_raw).decode("utf-8")
            else:
                raise TypeError(f"Unexpected payload cache type: {type(cached_raw)}")

            payload = json.loads(payload_json)
            if not isinstance(payload, dict):
                raise TypeError("Cached payload is not dict")
            return cast(Dict[str, Any], payload)
        except Exception as e:
            logger.warning("[JWT Verify] read payload cache failed: %s", e)
            return None

    def _write_payload_cache(self, key: str, payload: Dict[str, Any]) -> None:
        """
        payload 短缓存：
        - TTL = min(token剩余寿命, 60秒)
        - 至少 1 秒
        """
        try:
            now = int(time.time())
            exp = int(payload.get("exp", now))
            ttl = max(min(exp - now, 60), 1)
            self.redis.set(key, json.dumps(payload, separators=(",", ":")), ex=ttl, nx=True)
        except Exception as e:
            logger.warning("[JWT Verify] write payload cache failed: %s", e)

    def verify(self, token: str) -> Dict[str, Any]:
        """
        JWT 验证主入口 (ES256):

        流程：
        1) 校验 token 基本格式并解析 header/payload/signature 三段；
        2) 校验 header.alg 必须为 ES256；
        3) 生产环境先尝试 payload 缓存（命中仍执行 claims + 黑名单）；
        4) 验签（raw->DER，支持公钥刷新重试）；
        5) 解码 payload 并执行 claims + 黑名单；
        6) 生产环境写 payload 短缓存。
        """
        if not isinstance(token, str) or not token.strip():
            raise JWTValidationError("Token is empty")

        token = token.strip()

        try:
            header_b64, payload_b64, signature_b64 = token.split(".")
        except ValueError as e:
            raise JWTValidationError(f"JWT format invalid: {e}") from e

        # 解析 header
        try:
            header_obj = json.loads(self._b64url_decode(header_b64))
            if not isinstance(header_obj, dict):
                raise TypeError("JWT header is not object")
            header = cast(Dict[str, Any], header_obj)
        except Exception as e:
            raise JWTValidationError(f"JWT header decode failed: {e}") from e

        # 强制算法校验，防算法降级
        alg = str(header.get("alg", "")).upper()
        if alg != self.ALGORITHM:
            raise JWTValidationError(f"JWT alg mismatch: expect {self.ALGORITHM}, got {alg}")

        # 可选：typ 检查（若存在则要求 JWT）
        typ = header.get("typ")
        if typ is not None and str(typ).upper() != "JWT":
            raise JWTValidationError("JWT header typ invalid")

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        payload_cache_key = f"{self.redis_prefix}payload:{token_hash}"

        # 缓存路径（生产环境）
        if not self._is_dev:
            cached_payload = self._read_payload_cache(payload_cache_key)
            if cached_payload is not None:
                jti = self._validate_claims(cached_payload)
                self._ensure_not_blacklisted(jti)
                return cached_payload

        # 非缓存路径：验签
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        try:
            raw_signature = self._b64url_decode(signature_b64)
        except Exception as e:
            raise JWTValidationError(f"JWT signature decode failed: {e}") from e

        self._verify_signature_with_rotation(signing_input, raw_signature)

        # 解码 payload
        try:
            payload_obj = json.loads(self._b64url_decode(payload_b64))
            if not isinstance(payload_obj, dict):
                raise TypeError("JWT payload is not object")
            payload = cast(Dict[str, Any], payload_obj)
        except Exception as e:
            raise JWTValidationError(f"JWT payload decode failed: {e}") from e

        # claims + 黑名单
        jti = self._validate_claims(payload)
        self._ensure_not_blacklisted(jti)

        # 写短缓存
        if not self._is_dev:
            self._write_payload_cache(payload_cache_key, payload)

        return payload

    @classmethod
    def get_instance(cls) -> "AzureES256Verifier":
        """
        单例入口。
        避免频繁创建 Azure / Redis 客户端。
        """
        if cls._instance is None:
            cls._instance = cls(
                vault_url=settings.AZURE_VAULT_URL,
                key_name=settings.JWT_KEY,
            )
        return cls._instance