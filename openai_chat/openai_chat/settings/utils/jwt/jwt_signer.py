"""
Azure Key Vault JWT签名工具模块(RSA)
- 使用Azure Key Vault 的 Key 服务对 JWT 进行 RS256 非对称签名
- 私钥始终保存在Azure Key Vault服务器中, 调用 Azure HSM 完成签名操作
- 使用Redis缓存 + 分布式锁 + 公钥验证
- 分布式锁机制(RedLock), 防止并发重复签名
- 用于用户登录模块中 生产 + 验证 access token
"""
import base64 # 用于JWT编码
import json # 序列化 header 和 payload
import hashlib # 计算摘要
from typing import Dict, cast
from azure.identity import DefaultAzureCredential # Azure 身份验证
from azure.keyvault.keys import KeyClient # Key Vault 中获取密钥对象
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm # 签名操作模块
from openai_chat.settings.utils.redis import get_redis_client # Redis 连接封装
from openai_chat.settings.utils.locks import build_lock # 分布式锁获取接口
from openai_chat.settings.base import REDIS_DB_JWT_CACHE # JWT签名Redis 缓存库db编号
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器接口

logger = get_logger("project.jwt.singer")

class AzureRS256Signer:
    """
    Azure Key Vault 签名器: 用于生成 RS256 JWT
    - 1.接收 header 和 payload
    - 2.构造 base64url 签名输入
    - 3.使用 Azure Key Vault 完成签名(SHA256摘要 + RSA私钥)
    - 4.使用 Redis 做缓存, 避免重复签名
    - 5.使用 RedLock 做并发锁控制
    """
    DEFAULT_TTL = 30 # 默认签名缓存时间(秒)
    DEFAULT_LOCK_TTL_MS = 1000 # 默认分布式锁持有时间(毫秒)
    
    def __init__(self, vault_url: str, key_name: str, redis_prefix: str = "jwt:sign:"):
        """
        初始化签名器
        :param key_id: Azure Key Vault 中的完整密钥URL(含Vault名称+Key名称)
        :param key_name: 密钥名称(key名)
        :param redis_prefix: Redis 缓存的键前缀, 默认 'jwt:sign:'
        """
        self.credential = DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=vault_url, credential=self.credential)
        self.key = self.key_client.get_key(name=key_name) # 获取密钥对象
        self.crypto_client = CryptographyClient(key=self.key, credential=self.credential)
        self.redis = get_redis_client(db=REDIS_DB_JWT_CACHE)
        self.prefix = redis_prefix
        logger.info(f"[JWT-Signer Init] 初始化 JWT 签名器, Vault: {vault_url}, key: {key_name}")
    
    @staticmethod
    def base64url_encode(data: bytes) -> str:
        """
        执行 base64url 编码(用于 JWT 中)
        - 无 '=' 补齐
        - URL 安全字符集
        """
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    
    def _generate_cache_key(self, header: Dict, payload: Dict) -> str:
        """
        生成唯一缓存 key: 基于 header+payload 的JSON内容计算 SHA256哈希
        :return: Redis 中使用的缓存 key
        """
        raw = json.dumps({"h": header, "p":payload}, sort_keys=True)
        sha256_hash = hashlib.sha256(raw.encode()).hexdigest()
        return f"{self.prefix}{sha256_hash}"
    
    def sign(self, header: Dict, payload: Dict, ttl: int = 30, lock_ttl_ms: int = 1000) -> str:
        """
        执行 JWT RS256 签名流程(缓存 + 锁)
        :param header: JWT Header(如 {"alg": "RS256", "typ": "JWT"})
        :param payload: JWT payload(如 sub, iat, exp, iss等)
        :param ttl: 签名结果缓存时间(秒)
        :param lock_ttl_ms: 分布式锁持有时间(毫秒)
        :return: 最终生成的 JWT 字符串(header.payload.signature)
        """
        ttl = ttl or self.DEFAULT_TTL
        lock_ttl_ms = lock_ttl_ms or self.DEFAULT_LOCK_TTL_MS
        
        if header.get("alg") != "RS256":
            raise ValueError("仅支持 RS256 签名算法")
        
        # 构造缓存 key
        cache_key = self._generate_cache_key(header, payload)
        
        try:
            # 尝试从Redis 获取签名结果
            cached_token = self.redis.get(cache_key)
            if cached_token:
                logger.info(f"[JWT Cache Hit] 命中缓存 key:{cache_key}")
                return cached_token.decode("utf-8") if isinstance(cached_token, bytes) else str(cached_token)
        except Exception as e:
            logger.warning(f"[Redis Read Error] 获取缓存失败:{cache_key}, 错误:{e}")
        
        # 使用 RedLock 加锁, 防止高并发重复签名
        with build_lock(cache_key, ttl=lock_ttl_ms, strategy='safe'):
            try:
                # Double check(防止并发竞争)
                cached_token = self.redis.get(cache_key)
                if cached_token:
                    return cached_token.decode("utf-8") if isinstance(cached_token, bytes) else str(cached_token)
                
                # 编码 header 和 payload(base64url)
                encoded_header = self.base64url_encode(json.dumps(header, separators=(',', ':')).encode())
                encoded_payload = self.base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
                
                # 拼接为bytes, 不引发类型错误
                signing_input = ".".join([encoded_header, encoded_payload]).encode("utf-8")
                
                digest = hashlib.sha256(signing_input).digest()
                # 使用 Azure Key Vault 执行签名(RS256)
                sign_result = self.crypto_client.sign(SignatureAlgorithm.rs256, digest)
                encoded_signature = self.base64url_encode(sign_result.signature)
                
                # 组装最终 JWT
                jwt_token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"
                
                # 写入结果到Redis缓存(注:转换为字符串)
                try:
                    self.redis.setex(cache_key, ttl, jwt_token)
                except Exception as e:
                    logger.error(f"[Redis Write Error] JWT 写入缓存失败: {e}")
                
                logger.debug(f"[JWT Sign] 生成JWT: {jwt_token}")
                return jwt_token # 返回最终的完整JWT令牌
            
            except Exception as e:
                logger.error(f"[JWT Sign Error]签名失败, key={cache_key}, 错误: {e}")
                raise RuntimeError(f"[JWT Sign Error] 签名过程异常: {e}")
            
    # === 类方法: 单例懒加载 ===
    _instance = None
    
    @classmethod
    def get_instance(cls) -> "AzureRS256Signer":
        """
        获取全局单例实例
        """
        if cls._instance is None:
            try:
                from django.conf import settings
                cls._instance = cls(
                    vault_url = settings.AZURE_VAULT_URL,
                    key_name = settings.JWT_KEY,
                )
            except Exception as e:
                logger.critical(f"[JWT Sign Init Error] 初始化失败: {e}")
                raise
        return cast(AzureRS256Signer, cls._instance)