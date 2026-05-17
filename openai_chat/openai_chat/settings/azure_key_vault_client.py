"""
Azure Key Vault 客户端封装

设计目标:
- 导入阶段不创建 Azure SDK 网络连接
- Secret 按需读取并带 TTL 缓存，避免每次 settings 使用都回源 Key Vault
- 日志不输出完整 secret name，更不输出 secret value
- 刷新失败时是否允许使用旧缓存由调用方显式决定
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from threading import RLock
from typing import Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from openai_chat.settings.utils.logging import get_logger

logger = get_logger("clients.azure_vault_key")


class AzureKeyVaultError(RuntimeError):
    """Key Vault 访问失败的统一异常。"""


@dataclass(frozen=True)
class _CachedSecret:
    value: str
    expires_at: float


class AzureKeyVaultClient:
    """
    Azure Key Vault Secret 客户端

    注意:
    - SecretClient 和 DefaultAzureCredential 在首次真正读取 secret 时才创建
    - 缓存是进程内缓存，多进程部署下每个 worker 都有自己的缓存
    """

    DEFAULT_CACHE_TTL_SECONDS = 300

    def __init__(
        self,
        vault_url: str,
        *,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    ) -> None:
        vault_url = (vault_url or "").strip()
        if not vault_url.startswith("https://"):
            raise ValueError("Azure Key Vault URL 必须使用 https://")

        self.vault_url = vault_url.rstrip("/")
        self.cache_ttl_seconds = max(0, int(cache_ttl_seconds))
        self._cache: dict[str, _CachedSecret] = {}
        self._client: Optional[SecretClient] = None
        self._lock = RLock()

    def get_secret(
        self,
        secret_name: str,
        *,
        force_refresh: bool = False,
        allow_stale_on_error: bool = False,
    ) -> str:
        """
        获取指定 secret 值

        参数:
        - force_refresh: 忽略有效缓存，强制回源 Key Vault。
        - allow_stale_on_error: 回源失败时是否允许返回旧缓存。
          普通运行期读取可按需开启；高风险密钥刷新建议保持 False。
        """
        secret_name = self._normalize_secret_name(secret_name)
        now = time.monotonic()

        if not force_refresh:
            cached = self._get_valid_cached_secret(secret_name, now=now)
            if cached is not None:
                return cached

        with self._lock:
            if not force_refresh:
                cached = self._get_valid_cached_secret(secret_name, now=time.monotonic())
                if cached is not None:
                    return cached

            try:
                secret = self._fetch_secret(secret_name)
            except Exception as exc:
                stale = self._cache.get(secret_name)
                if allow_stale_on_error and stale is not None:
                    logger.warning(
                        "[Azure-Key-Vault] secret refresh failed, using stale cache. secret_hash=%s",
                        self._secret_hash(secret_name),
                    )
                    return stale.value
                vault_error = self._to_vault_error(secret_name, exc)
                if vault_error is exc:
                    raise vault_error
                raise vault_error from exc

            expires_at = time.monotonic() + self.cache_ttl_seconds if self.cache_ttl_seconds else 0
            self._cache[secret_name] = _CachedSecret(value=secret, expires_at=expires_at)
            return secret

    def refresh_secret(self, secret_name: str, *, allow_stale_on_error: bool = True) -> str:
        """
        强制刷新 secret

        默认保留旧行为: 刷新失败时可使用旧缓存。调用 OpenAI Admin Key
        这类高权限密钥时，建议传 allow_stale_on_error=False。
        """
        return self.get_secret(
            secret_name,
            force_refresh=True,
            allow_stale_on_error=allow_stale_on_error,
        )

    def clear_cache(self, secret_name: str | None = None) -> None:
        """清理进程内 secret 缓存。"""
        with self._lock:
            if secret_name is None:
                self._cache.clear()
                return
            self._cache.pop(self._normalize_secret_name(secret_name), None)

    def _get_client(self) -> SecretClient:
        if self._client is not None:
            return self._client

        with self._lock:
            if self._client is None:
                credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
                self._client = SecretClient(vault_url=self.vault_url, credential=credential)
            return self._client

    def _fetch_secret(self, secret_name: str) -> str:
        secret = self._get_client().get_secret(secret_name).value
        if secret is None:
            raise AzureKeyVaultError("secret value is empty")
        return secret

    def _get_valid_cached_secret(self, secret_name: str, *, now: float) -> str | None:
        cached = self._cache.get(secret_name)
        if cached is None:
            return None
        if self.cache_ttl_seconds == 0:
            return None
        if cached.expires_at > now:
            return cached.value
        return None

    @staticmethod
    def _normalize_secret_name(secret_name: str) -> str:
        secret_name = (secret_name or "").strip()
        if not secret_name:
            raise ValueError("secret_name 不能为空")
        return secret_name

    @staticmethod
    def _secret_hash(secret_name: str) -> str:
        return hashlib.sha256(secret_name.encode("utf-8")).hexdigest()[:12]

    def _to_vault_error(self, secret_name: str, exc: Exception) -> AzureKeyVaultError:
        secret_hash = self._secret_hash(secret_name)

        if isinstance(exc, ResourceNotFoundError):
            logger.critical("[Azure-Key-Vault] secret not found. secret_hash=%s", secret_hash)
            return AzureKeyVaultError("Azure Key Vault secret not found")

        if isinstance(exc, HttpResponseError):
            logger.critical(
                "[Azure-Key-Vault] request failed. secret_hash=%s status_code=%s",
                secret_hash,
                getattr(exc, "status_code", None),
            )
            return AzureKeyVaultError("Azure Key Vault request failed")

        if isinstance(exc, AzureKeyVaultError):
            logger.error("[Azure-Key-Vault] invalid secret. secret_hash=%s", secret_hash)
            return exc

        logger.error(
            "[Azure-Key-Vault] unexpected error. secret_hash=%s error_type=%s",
            secret_hash,
            type(exc).__name__,
        )
        return AzureKeyVaultError("Azure Key Vault secret fetch failed")
