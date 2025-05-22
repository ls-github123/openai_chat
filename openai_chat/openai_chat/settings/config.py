from decouple import config
from .azure_key_vault_client import AzureKeyVaultClient

# === 工具方法 ===
def get_secret_name_by_env(env_key: str, default_key: str, vault_client:AzureKeyVaultClient) -> str:
    """
    从.env 中获取密钥名称环境变量，再从 Azure Key Vault 获取对应密钥值
    :param env_key: .env 中用于获取密钥名称的变量名
    :param default_key: 默认密钥名称变量名（用于缺省兜底）
    :param vault_client: AzureKeyVaultClient 实例
    :return: 从 Azure-Key-Vault 获取到的密钥值
    """
    secret_name_key = config(env_key, default=default_key, cast=str)
    secret_value = vault_client.get_secret(secret_name_key) # type: ignore
    return secret_value

# === Azure Key Vault 客户端初始化 ===
AZURE_KEY_VAULT_URL: str = config("AZURE_VAULT_URL", default="vault_url", cast=str) # type: ignore
vault = AzureKeyVaultClient(AZURE_KEY_VAULT_URL)

# Django安全配置
DJANGO_SECRET_KEY: str = get_secret_name_by_env("DJANGO-SECRET-KEY-NAME", "Django-SECRET-KEY", vault)

# Redis缓存配置
REDIS_PASSWORD: str = get_secret_name_by_env("REDIS_PASSWORD_NAME", "openai-redis-pd", vault)

# MongoDB数据库配置
MONGO_PASSWORD: str = get_secret_name_by_env("MONGO_PASSWORD_NAME", "mongodb-chatuser-pwd", vault)

# MYSQL数据库配置
MYSQL_PASSWORD: str = get_secret_name_by_env("DB_PASSWORD_NAME", "openai-mysql-root", vault)