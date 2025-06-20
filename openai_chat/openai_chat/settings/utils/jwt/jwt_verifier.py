"""
Azure Key Vault 验证模块
- 自动从 Azure Key Vault 获取 RSA 密钥中的 n/e
- 构造 RSA 公钥对象，并缓存其 PEM 形式至 Redis
- 用于验证 RS256 JWT Token 的签名合法性
- 不依赖 x5c 或上传证书，仅依赖 Azure Key 类型资源
"""
import json, time, hashlib, base64, os, uuid
from typing import Dict, Any, cast, Union # 类型注解
from cryptography.hazmat.primitives.asymmetric import rsa, padding # RSA 加密与填充方式
from cryptography.hazmat.primitives import hashes, serialization # 哈希算法与序列化工具
from cryptography.hazmat.backends import default_backend # 加密算法后端实现
from azure.identity import DefaultAzureCredential # Azure 默认身份认证方式
from azure.keyvault.keys import KeyClient # Azure 密钥客户端
from openai_chat.settings.utils.redis import get_redis_client
from openai_chat.settings.base import REDIS_DB_JWT_CACHE # JWT模块签名结果 Redis 缓存占用库
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.locks import build_lock # 引入redlock分布式锁
from django.conf import settings

# === 环境判定与格式器策略 ===
DJANGO_SETTINGS_MODULE = os.getenv('DJANGO_SETTINGS_MODULE', 'openai_chat.settings.dev') # 获取当前环境变量
IS_DEV = "dev" in DJANGO_SETTINGS_MODULE.lower() # 判断是否为开发环境

logger = get_logger("jwt")

class AzureRS256Verifier:
    """
    JWT RS256 验证器 (Azure Key Vault 公钥)
    - 用于验证 access_token 是否有效
    """
    _instance: "AzureRS256Verifier | None" = None
    
    def __init__(self, vault_url: str, key_name: str, redis_prefix: str = "jwt:verify:"):
        self.vault_url = vault_url # Azure Key Vault 地址
        self.key_name = key_name # 密钥名称
        self.redis_prefix = (redis_prefix.decode() if isinstance(redis_prefix, bytes) else redis_prefix) # Redis 缓存前缀
        self.redis = get_redis_client(db=REDIS_DB_JWT_CACHE)
        self.credential = DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=self.vault_url, credential=self.credential)
        self.is_dev = IS_DEV # 是否处于开发环境
        self.public_key = self._load_or_cache_public_key() # 获取/构造并加载 RSA 公钥对象
    
    @staticmethod
    def _raw_to_int(val: str | bytes) -> int:
        """
        将 Azure SDK 返回的 n/e 字段统一转换 int
        """
        if isinstance(val, bytes): # 纯二进制大端整数表示
            return int.from_bytes(val, "big")
        if isinstance(val, str): # Base64URL编码
            return int.from_bytes(base64.urlsafe_b64decode(val + "=="), "big")
        raise TypeError(f"未知 n/e 类型: {type(val)}")
    
    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        data += "=" * ((4 - len(data) % 4) % 4)
        return base64.urlsafe_b64decode(data)
    
    def _load_or_cache_public_key(self, force_refresh: bool = False):
        """
        从 Redis 加载或通过 n/e 构造 RSA 公钥对象
        :param force_refresh: 是否强制刷新 Redis 中的缓存
        并缓存 PEM 格式文本
        """
        cache_key = f"{self.redis_prefix}pem:{self.key_name}"
        
        # 引入分布式锁防止并发刷新
        lock_key = f"lock:jwt:publickey:{self.key_name}"
        lock = build_lock(lock_key, ttl=3000, strategy="safe")
        
        with lock:
            if not force_refresh and not self.is_dev: # 开发模式下跳过缓存
                pem_cached = self.redis.get(cache_key)
                if pem_cached:
                    logger.info("[JWT Verify] Redis 缓存命中公钥")
                    pem_bytes = pem_cached if isinstance(pem_cached, bytes) else str(pem_cached).encode()
                    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())
                
            # 若缓存不存在, 则从 Azure 获取密钥对结构
            key_bundle = self.key_client.get_key(name=self.key_name)
            n_raw, e_raw = getattr(key_bundle.key, "n", None), getattr(key_bundle.key, "e", None)
            if n_raw is None or e_raw is None:
                raise RuntimeError("[JWT Verify] 获取公钥失败: n/e 字段缺失")
            
            # 构造 RSA 公钥对象
            public_numbers = rsa.RSAPublicNumbers(
                e=self._raw_to_int(e_raw),
                n=self._raw_to_int(n_raw),
            )
            public_key = public_numbers.public_key(default_backend())
            
            # 序列化为 PEM 格式并缓存到 Redis(缓存 1 小时)
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
            
            # 缓存 Redis 加入容错处理
            try:
                self.redis.set(cache_key, pem, ex=3600, nx=not force_refresh)
            except Exception as e:
                logger.error(f"[JWT Verify] Redis 缓存失败: {e}")
                
            logger.info(f"[JWT Verify] 构造并缓存 PEM 公钥成功: {self.key_name}")
            return public_key
    
        
    def verify(self, token: str) -> Dict[str, Any]:
        """
        验证 JWT Token 的签名合法性和过期状态(支持 payload 短时缓存)
        :param token: 待验证的 JWT 三段式字符串(header.payload.signature)
        :return: 解码后的 payload 内容(字典)
        """
        # 使用 sha256 哈希生成稳定缓存键
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        payload_cache_key = f"{self.redis_prefix}payload:{token_hash}" # 使用 hash 防止 token 过长
            
        # 读取缓存
        if not self.is_dev: # 仅在生产环境启用 payload redis 缓存
            cached_raw = self.redis.get(payload_cache_key)
            cached: Union[str, bytes, memoryview, None] = cast(Union[str, bytes, memoryview, None], cached_raw) # 告诉检查器真实类型
            if cached:
                if isinstance(cached, str):
                    payload_json = cached
                elif isinstance(cached, (bytes, memoryview)):
                    # memoryview先转 bytes
                    payload_json = bytes(cached).decode("utf-8")
                else: # 理论不会到达
                    raise TypeError(f"Unexpected redis payload type: {type(cached)}")
                return json.loads(payload_json)
            
        # 解析-验签
        try:
            # 解析 JWT 三段式
            header_b64, payload_b64, signature_b64 = token.split(".")
        except ValueError:
            raise RuntimeError("JWT 格式非法: 应当由header.payload.signature三段组成")
        
        # 拼接签名输入(header + "." + payload), 编码为 bytes
        signing_input = f"{header_b64}.{payload_b64}".encode()
        # 解码 base64url 格式签名段
        signature = self._b64url_decode(signature_b64)
            
        # 校验签名算法, 防止算法注入攻击(alg none漏洞)
        header = json.loads(self._b64url_decode(header_b64))
        if header.get("alg") != "RS256":
            raise RuntimeError(f"不支持的 JWT 签名算法: {header.get('alg')}")
                
        # 仅允许 RSA 公钥类型用于验证 RS256 签名
        if not isinstance(self.public_key, rsa.RSAPublicKey): # 检查公钥类型是否符合 RSA 标准
            raise RuntimeError("公用非有效的 RSA 公钥对象, 无法进行 RS256 验签")
                
        # 执行签名验证(RSASSA-PKCS1-v1_5 + SHA256)
        self.public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(), # 使用 RSA-PKCS#1 v1.5 + SHA256 进行标准 RS256 验签
            hashes.SHA256(),
        )
                
        # 解析 payload
        payload = json.loads(self._b64url_decode(payload_b64))
        now = int(time.time())
            
        # 字段校验
        CLOCK_SKEW = 120 # 允许2分钟时钟漂移
        if now > payload.get("exp", 0):
            raise RuntimeError("Token 已过期")
        if payload.get("iat", now + 1) > now:
            raise RuntimeError("Token时间非法")
            
        if not isinstance(payload.get("sub"), str) or len(payload["sub"]) < 6:
            raise RuntimeError("Token sub 字段非法")
            
        # 可选校验: 签发者字段
        if payload.get("iss") != getattr(settings, "JWT_ISSUER", "https://openai-chat.xyz"):
            raise RuntimeError("Token 签发者不受信任")
        # 可选校验: 受众字段
        if payload.get("aud") != getattr(settings, "JWT_AUDIENCE", "openai-chat-client"):
            raise RuntimeError("Token受众不匹配")
        # 可选校验: scope 权限字段
        if payload.get("scope") not in {"user", "admin", "super"}:
            raise RuntimeError("Token scope非法")
            
        # jti
        try:
            uuid.UUID(payload.get("jti", ""))
        except Exception:
            raise RuntimeError("Token typ字段非法")
            
        # 写入缓存
        if not self.is_dev:
            try:
                self.redis.set(payload_cache_key, json.dumps(payload), ex=60, nx=True)
            except Exception as e:
                logger.warning(f"[JWT Verify] 缓存写入失败: {e}")
            
        return payload
    
    # 单例
    @classmethod
    def get_instance(cls) -> "AzureRS256Verifier":
        """
        获取全局单例实例
        - 避免频繁初始化 Azure 和 Redis 客户端
        - 可直接用于需要JWT验证的模块
        """
        if cls._instance is None:
            cls._instance = cls(
                vault_url = settings.AZURE_VAULT_URL,
                key_name = settings.JWT_KEY,
            )
        return cast(AzureRS256Verifier, cls._instance)