from __future__ import annotations

import os
from threading import RLock
from typing import ClassVar

from decouple import UndefinedValueError, config

from openai_chat.settings.utils.logging import get_logger

from .azure_key_vault_client import AzureKeyVaultClient

logger = get_logger("project.get_config")

_vault_lock = RLock()
_vault_client: AzureKeyVaultClient | None = None


def _is_prod_settings() -> bool:
    settings_module = os.getenv("DJANGO_SETTINGS_MODULE", "").strip().lower()
    return settings_module.endswith(".prod") or ".prod." in settings_module


def get_config(
    key: str,
    default: str | None = None,
    *,
    allow_blank: bool = False,
    required_in_prod: bool = False,
) -> str:
    """
    从环境变量或 .env 读取配置项。

    规则:
    - default=None 表示该配置必填。
    - required_in_prod=True 时，生产环境不允许因为缺失而使用默认值。
    - 默认不接受空字符串，确实允许为空时显式传 allow_blank=True。
    """
    key = (key or "").strip()
    if not key:
        raise RuntimeError("[Config]配置项名称不能为空")

    try:
        value = config(key, cast=str)
    except UndefinedValueError as exc:
        if required_in_prod and _is_prod_settings():
            logger.error("[Config]生产环境缺少必要配置:%s", key)
            raise RuntimeError(f"[Config]生产环境缺少必要配置:{key}") from exc

        if default is None:
            logger.error("[Config]缺少必要配置:%s", key)
            raise RuntimeError(f"[Config]缺少必要配置:{key}") from exc

        logger.warning("[Config]配置项%s缺失,使用默认值", key)
        value = default

    value_str = str(value).strip()
    if not allow_blank and value_str == "":
        logger.error("[Config]配置项%s为空", key)
        raise RuntimeError(f"[Config]配置项为空:{key}")

    return value_str


def get_optional_config(key: str, *, allow_blank: bool = False) -> str | None:
    """
    读取可选配置。

    与 get_config() 不同，本函数用于“探测是否存在”，缺失时不写 warning。
    """
    key = (key or "").strip()
    if not key:
        return None

    value = str(config(key, default="", cast=str)).strip()
    if value == "" and not allow_blank:
        return None
    return value


def get_vault_client() -> AzureKeyVaultClient:
    """
    懒加载 Azure Key Vault 客户端。

    只在真正读取 secret 时创建客户端，避免 manage.py / py_compile /
    普通模块导入阶段触发 Azure 凭据链和网络相关失败。
    """
    global _vault_client

    if _vault_client is not None:
        return _vault_client

    with _vault_lock:
        if _vault_client is None:
            vault_url = get_config(
                "AZURE_VAULT_URL",
                default="https://openai-chat-key.vault.azure.net/",
                required_in_prod=True,
            )
            raw_cache_ttl = get_optional_config("AZURE_KEY_VAULT_SECRET_CACHE_TTL_SECONDS")
            try:
                cache_ttl = int(raw_cache_ttl or AzureKeyVaultClient.DEFAULT_CACHE_TTL_SECONDS)
            except ValueError as exc:
                raise RuntimeError("AZURE_KEY_VAULT_SECRET_CACHE_TTL_SECONDS 必须为整数") from exc

            _vault_client = AzureKeyVaultClient(
                vault_url=vault_url,
                cache_ttl_seconds=cache_ttl,
            )
        return _vault_client


def get_secret_by_env(env_key: str, default_key: str, vault_client: AzureKeyVaultClient | None = None) -> str:
    """
    从环境变量读取 Azure Key Vault secret name，再从 Key Vault 获取 secret value。

    生产环境要求显式配置 secret name 并走 Key Vault。
    开发环境允许直接配置密钥值，例如:
    - DJANGO_SECRET_KEY_NAME 对应的直接密钥变量为 DJANGO_SECRET_KEY
    - REDIS_PASSWORD_NAME 对应的直接密钥变量为 REDIS_PASSWORD
    """
    direct_env_key = env_key[:-5] if env_key.endswith("_NAME") else ""
    if direct_env_key and not _is_prod_settings():
        direct_secret = get_optional_config(direct_env_key)
        if direct_secret:
            return direct_secret

    secret_name = get_config(
        env_key,
        default=default_key,
        required_in_prod=True,
    )
    client = vault_client or get_vault_client()

    try:
        return client.get_secret(secret_name)
    except Exception as exc:
        logger.error(
            "[Vault]获取密钥失败 env_key=%s error_type=%s",
            env_key,
            type(exc).__name__,
        )
        raise RuntimeError(f"[Vault]获取密钥失败:{env_key}") from exc


class _SecretConfigMeta(type):
    _secret_map: ClassVar[dict[str, tuple[str, str]]] = {
        "DJANGO_SECRET_KEY": ("DJANGO_SECRET_KEY_NAME", "Django-SECRET-KEY"),
        "REDIS_PASSWORD": ("REDIS_PASSWORD_NAME", "openai-redis-pd"),
        "MONGO_PASSWORD": ("MONGO_PASSWORD_NAME", "mongodb-chatuser-pwd"),
        "DB_PASSWORD": ("DB_PASSWORD_NAME", "openai-mysql-root"),
        "RESEND_API_KEY": ("RESEND_EMAIL_API_KEY_NAME", "RESEND-API-KEY"),
        "TURNSTILE_ADMIN_SECRET_KEY": (
            "TURNSTILE_ADMIN_SECRET_KEY_NAME",
            "trunstile-admin-secret-key",
        ),
        "TURNSTILE_USERS_SECRET_KEY": (
            "TURNSTILE_USERS_SECRET_KEY_NAME",
            "turnstile-users-secret-key",
        ),
    }

    def __getattr__(cls, name: str) -> str:
        if name not in cls._secret_map:
            raise AttributeError(name)
        env_key, default_key = cls._secret_map[name]
        return get_secret_by_env(env_key, default_key)


class SecretConfig(metaclass=_SecretConfigMeta):
    """集中管理密钥项，所有密钥均按需从 Azure Key Vault 读取。"""

    DJANGO_SECRET_KEY: str
    REDIS_PASSWORD: str
    MONGO_PASSWORD: str
    DB_PASSWORD: str
    RESEND_API_KEY: str
    TURNSTILE_ADMIN_SECRET_KEY: str
    TURNSTILE_USERS_SECRET_KEY: str


class _VaultClientProxy:
    def __getattr__(self, name: str):
        return getattr(get_vault_client(), name)


class VaultClient:
    """暴露 Vault 客户端懒加载入口。"""

    instance = _VaultClientProxy()

    @classmethod
    def get_instance(cls) -> AzureKeyVaultClient:
        return get_vault_client()
