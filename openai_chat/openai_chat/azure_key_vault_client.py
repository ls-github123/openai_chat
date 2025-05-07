"""
Azure Key Vault 客户端封装
用于安全地从 Azure Key Vault 中读取密钥，且自动缓存读取结果
"""
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError # 导入异常处理类
import logging # 导入日志模块

logger = logging.getLogger(__name__) # 创建日志记录器

class AzureKeyVaultClient:
    def __init__(self, vault_url: str):
        """
        初始化 Azure Key Vault 客户端
        :param vault_url: Azure Key Vault 的 URL,例如 "https://<your-key-vault-name>.vault.azure.net/"
        """
        self.client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential()) # 使用默认凭据进行身份验证
        self._cache = {} # 缓存读取Secret
        
    def get_secret(self, secret_name: str) -> str:
        """
        获取指定名称Secret的值
        优先从本地缓存读取,如果缓存中不存在,则从 Azure Key Vault 中读取
        :param name: 密钥名称
        :return: 密钥值
        """
        if secret_name in self._cache:
            return self._cache[secret_name] # 如果缓存中存在,直接返回
        try:
            secret = self.client.get_secret(secret_name).value # 从 Azure Key Vault 中获取 Secret
            self._cache[secret_name] = secret # 缓存 Secret
            return secret # 返回 Secret 的值
        except ResourceNotFoundError:
            logger.error(f"[Vault] Secret not found:{secret_name}")
            raise Exception(f"[Vaule]未找到密钥:{secret_name}") # 如果未找到,抛出异常
        except HttpResponseError as e:
            logger.error(f"[Vault] 请求失败:{secret_name}, 状态码:{e.status_code}")
            raise Exception(f"[Vault] 获取密钥失败:{secret_name}, 状态码:{e.status_code}")
        except Exception as e:
            logger.exception(f"[Vault] 获取密钥失败:{secret_name}, 原因:{str(e)}")
            raise
    
    def refresh_secret(self, secret_name: str) -> str:
        """
        强制刷新并返回指定名称的密钥值
        :param secret_name: 密钥名称
        :return: 最新密钥值
        """
        try:
            latest_secret = self.client.get_secret(secret_name).value # 从 Azure Key Vault 中获取最新的 Secret
            self._cache[secret_name] = latest_secret # 更新缓存
            return latest_secret # 返回最新密钥值
        except Exception:
            logger.exception(f"[Vault] 刷新密钥失败:{secret_name}, 尝试从缓存获取")
            return self.get_secret(secret_name) # 如果刷新失败,尝试从缓存获取