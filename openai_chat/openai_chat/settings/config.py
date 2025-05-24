import logging
from decouple import config
from .azure_key_vault_client import AzureKeyVaultClient

# 初始化日志记录器
logger = logging.getLogger("openai_chat.settings.config")  # 根据模块名动态获取logger

# === 工具方法:安全读取.env配置项 ===
def get_config(key: str, default: str | None = None) -> str:
    """
    从.env文件中安全读取配置项,支持默认值
    :param key: 配置项名称
    :param default: 默认值
    :return: 配置项值(字符串)
    :raise RuntimeError:若无默认值且环境变量缺失,则终止运行
    """
    try:
        return str(config(key, default=default, cast=str))
    except Exception as e:
        if default is not None:
            logger.warning(f"[Config]配置项{key}缺失,使用默认值{default}")
            return str(default)
        logger.error(f"[Config]缺少必要配置:{key}", exc_info=True)
        raise RuntimeError(f"[Config]缺少必要配置:{key}") from e

# === 工具方法:通过.env文件中密钥名获取对应密钥值 ===
def get_secret_by_env(env_key: str, default_key: str, vault_client:AzureKeyVaultClient) -> str:
    """
    从.env 中获取密钥名称，再从 Azure Key Vault 获取对应密钥值
    :param env_key: .env 中用于获取密钥名称的变量名
    :param default_key: 默认密钥名称变量名（用于缺省兜底）
    :param vault_client: AzureKeyVaultClient 实例
    :return: 从 Azure-Key-Vault 获取到的密钥值
    :raise RuntimeError: 若密钥名称缺失或获取失败,则终止运行
    """
    secret_name = get_config(env_key, default=default_key) # 从.env中获取密钥名称
    try:
        return vault_client.get_secret(secret_name) # 从 Azure Key Vault 中获取密钥值
    except Exception as e:
        logger.error(f"[Vault]获取密钥失败:{secret_name}", exc_info=True)
        raise RuntimeError(f"[Vault]获取密钥失败:{secret_name}") from e

# === Azure Key Vault 客户端初始化 ===
try:
    AZURE_KEY_VAULT_URL = get_config("AZURE_VAULT_URL", default="vault_url")
    vault = AzureKeyVaultClient(AZURE_KEY_VAULT_URL)
except Exception as e:
    logger.critical("[Config] Azure Key Vault 客户端初始化失败", exc_info=True)
    raise RuntimeError("[Vault]客户端初始化失败") from e

# === 密钥配置项(封装为类) ===
class SecretConfig:
    """集中管理所有密钥项"""
    DJANGO_SECRET_KEY: str = get_secret_by_env("DJANGO_SECRET_KEY_NAME", "Django-SECRET-KEY", vault)
    REDIS_PASSWORD: str = get_secret_by_env("REDIS_PASSWORD_NAME", "openai-redis-pd", vault)
    MONGO_PASSWORD: str = get_secret_by_env("MONGO_PASSWORD_NAME", "mongodb-chatuser-pwd", vault)
    MYSQL_PASSWORD: str = get_secret_by_env("DB_PASSWORD_NAME", "openai-mysql-root", vault)

class VaultClient:
    """暴露Vault实例接口(特殊情况下直接使用)"""
    instance = vault