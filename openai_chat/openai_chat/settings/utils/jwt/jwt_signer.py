"""
ES256 JWT 签名器(Azure Key Vault - ES256)
1. 使用 EC P-256 私钥
2. JWT(JWS) 的 ES256 签名要求 raw(64字节, r||s)
3. Azure Key Vault ES256 通常直接返回 raw 签名；本模块兼容 DER 返回
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping, cast

from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from django.conf import settings

from openai_chat.settings.base import REDIS_DB_JWT_CACHE
from openai_chat.settings.utils.locks import build_lock
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client

logger = get_logger("project.jwt.signer")


class AzureES256Signer:
    """
    基于 Azure Key Vault 的 ES256 JWT 签名器（单例）

    关键约束：
    - 仅支持 ES256（P-256 曲线）
    - header["alg"] 必须为 "ES256"
    """

    # 签名缓存默认 TTL（秒）
    DEFAULT_TTL = 30
    # 分布式锁默认过期（毫秒）
    DEFAULT_LOCK_TTL_MS = 1000

    _instance = None

    def __init__(self, vault_url: str, key_name: str, redis_prefix: str = "jwt:sign:") -> None:
        # 初始化 Azure Key Vault 客户端与加密客户端
        self.credential = DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=vault_url, credential=self.credential)
        self.key = self.key_client.get_key(name=key_name)
        self.crypto_client = CryptographyClient(key=self.key, credential=self.credential)

        # 初始化 Redis（用于签名结果缓存）
        self.redis = get_redis_client(db=REDIS_DB_JWT_CACHE)
        self.prefix = redis_prefix

        logger.info("[JWT-Signer Init] initialized ES256 signer, key=%s", key_name)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        """
        进行 JWT 需要的 base64url 编码（去掉 '=' padding）。
        """
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _normalize_positive_int(value: int | None, default: int, field_name: str) -> int:
        """
        将可空整数参数规范化为正整数，避免 None/0/负数导致行为异常。

        - value 为 None 时使用 default
        - value 非法（<=0）时抛出 ValueError
        """
        final_value = default if value is None else int(value)
        if final_value <= 0:
            raise ValueError(f"{field_name} must be a positive integer, got {final_value}")
        return final_value

    @staticmethod
    def _signature_to_jws_raw(signature: bytes, part_len: int = 32) -> bytes:
        """
        将 ECDSA 签名转换为 JWT 规范所需的 raw 签名（r||s）。

        Azure Key Vault ES256 签名结果通常已经是 raw(64字节)。
        为兼容其他实现或 SDK 行为，这里也接受 DER 编码签名。
        """
        raw_len = part_len * 2
        if len(signature) == raw_len:
            return signature

        r, s = asym_utils.decode_dss_signature(signature)
        r_bytes = int(r).to_bytes(part_len, byteorder="big")
        s_bytes = int(s).to_bytes(part_len, byteorder="big")
        return r_bytes + s_bytes

    def _generate_cache_key(self, header: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
        """
        基于 header + payload 的稳定 JSON 生成缓存 key。

        说明：
        - 使用 sort_keys + 固定 separators 确保序列化稳定；
        - 使用 sha256 摘要避免超长 key。
        """
        raw = json.dumps({"h": header, "p": payload}, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return f"{self.prefix}{digest}"

    def sign(
        self,
        header: Mapping[str, Any],
        payload: Mapping[str, Any],
        ttl: int | None = None,
        lock_ttl_ms: int | None = None,
    ) -> str:
        """
        生成 ES256 JWT 字符串（header.payload.signature）。

        流程：
        1. 参数校验与归一化；
        2. 首次读取缓存（命中直接返回）；
        3. 获取分布式锁后再次读缓存（双重检查）；
        4. 组装 signing_input；
        5. SHA-256 摘要 -> Key Vault ES256 签名；
        6. 签名 -> raw -> base64url；
        7. 写入缓存并返回 token。
        """
        final_ttl = self._normalize_positive_int(ttl, self.DEFAULT_TTL, "ttl")
        final_lock_ttl_ms = self._normalize_positive_int(
            lock_ttl_ms, self.DEFAULT_LOCK_TTL_MS, "lock_ttl_ms"
        )

        if header.get("alg") != "ES256":
            raise ValueError("Only ES256 is supported by AzureES256Signer")

        cache_key = self._generate_cache_key(header, payload)
        lock_key = f"{cache_key}:lock"

        # 1) 先查缓存：减少 Key Vault 调用
        try:
            cached = self.redis.get(cache_key)
            if cached:
                return cached.decode("utf-8") if isinstance(cached, bytes) else str(cached)
        except Exception as exc:
            logger.warning("[JWT Sign] read cache failed key=%s err=%s", cache_key, exc)

        # 2) 加锁：避免并发下重复签名
        with build_lock(lock_key, ttl=final_lock_ttl_ms, strategy="safe"):
            # 2.1) 双重检查缓存
            try:
                cached = self.redis.get(cache_key)
                if cached:
                    return cached.decode("utf-8") if isinstance(cached, bytes) else str(cached)
            except Exception:
                # 加锁后再次读缓存失败，不影响继续签名
                pass

            # 3) 组装 header/payload 的 base64url 字符串
            encoded_header = self._b64url_encode(
                json.dumps(dict(header), sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            encoded_payload = self._b64url_encode(
                json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")

            # 4) ES256：先对 signing_input 做 SHA-256，再交给 Key Vault 进行签名
            digest = hashlib.sha256(signing_input).digest()
            sign_result = self.crypto_client.sign(SignatureAlgorithm.es256, digest)

            # 5) raw/DER -> raw(64字节) -> base64url
            raw_sig = self._signature_to_jws_raw(sign_result.signature, part_len=32)
            encoded_sig = self._b64url_encode(raw_sig)

            token = f"{encoded_header}.{encoded_payload}.{encoded_sig}"

            # 6) 写入缓存（失败不阻塞主流程）
            try:
                self.redis.setex(cache_key, final_ttl, token)
            except Exception as exc:
                logger.warning("[JWT Sign] write cache failed key=%s err=%s", cache_key, exc)

            logger.info(
                "[JWT Sign] token generated jti=%s typ=%s sub=%s",
                payload.get("jti"),
                payload.get("typ"),
                payload.get("sub"),
            )
            return token

    @classmethod
    def _read_vault_settings(cls) -> tuple[str, str]:
        """
        读取并校验 ES256 签名所需配置
        """
        vault_url = getattr(settings, "AZURE_VAULT_URL", None)
        key_name = getattr(settings, "JWT_KEY", None)

        if not vault_url or not key_name:
            raise RuntimeError("Missing required settings: AZURE_VAULT_URL and JWT_KEY")

        return str(vault_url), str(key_name)

    @classmethod
    def get_instance(cls) -> "AzureES256Signer":
        """
        获取签名器单例实例。
        """
        if cls._instance is None:
            vault_url, key_name = cls._read_vault_settings()
            cls._instance = cls(
                vault_url=vault_url,
                key_name=key_name,
            )
        return cast(AzureES256Signer, cls._instance)
