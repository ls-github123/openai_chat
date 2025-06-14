"""
Azure Key Vault 验证模块
- 自动从 Azure Key Vault 获取 RSA 密钥中的 n/e
- 构造 RSA 公钥对象，并缓存其 PEM 形式至 Redis
- 用于验证 RS256 JWT Token 的签名合法性
- 不依赖 x5c 或上传证书，仅依赖 Azure Key 类型资源
"""
import json, time, hashlib, base64
from typing import Dict, Any # 类型注解
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

logger = get_logger("jwt")

class AzureRS256Verifier:
    """
    JWT RS256 验证器 (Azure Key Vault 公钥)
    - 用于验证 access_token 是否有效
    """
    def __init__(self, vault_url: str, key_name: str, redis_prefix: str = "jwt:verify:"):
        self.vault_url = vault_url # Azure Key Vault 地址
        self.key_name = key_name # 密钥名称
        self.redis_prefix = redis_prefix # Redis 缓存前缀
        self.redis = get_redis_client(db=REDIS_DB_JWT_CACHE)
        self.credential = DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=self.vault_url, credential=self.credential)
        self.public_key = self._load_or_cache_public_key() # # 获取/构造并加载 RSA 公钥对象
        self.debug = settings.DEBUG # 是否处于开发环境
        
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
            if not force_refresh and not self.debug: # 开发模式下跳过缓存
                cache_pem = self.redis.get(cache_key)
                if cache_pem:
                    logger.info(f"[JWT Verify] 命中 Redis 公钥缓存: {cache_key}")
                    pem_bytes = cache_pem if isinstance(cache_pem, bytes) else str(cache_pem).encode("utf-8")
                    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())
                
            # 若缓存不存在, 则从 Azure 获取密钥对结构
            key_bundle = self.key_client.get_key(name=self.key_name)
            jwk = key_bundle.key
            # 提取 base64url 编码的 n 和 e
            n_b64 = getattr(jwk, "n", None)
            e_b64 = getattr(jwk, "e", None)
            
            if not n_b64 or not e_b64:
                raise RuntimeError("[JWT Verify] 获取公钥失败: n/e 字段缺失")
            
            # 解码 base64url 编码的 n/e 字节流
            n_bytes = base64.urlsafe_b64decode(n_b64 + '==')
            e_bytes = base64.urlsafe_b64decode(e_b64 + '==')
            
            # 构造 RSA 公钥对象
            public_numbers = rsa.RSAPublicNumbers(
                e=int.from_bytes(e_bytes, byteorder='big'),
                n=int.from_bytes(n_bytes, byteorder='big')
            )
            public_key = public_numbers.public_key(default_backend())
            
            # 序列化为 PEM 格式并缓存到 Redis(缓存 1 小时)
            pem_text = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            # 缓存 Redis 加入容错处理
            try:
                result = self.redis.set(name=cache_key, value=pem_text, ex=3600, nx=not force_refresh)
                if result:
                    logger.info(f"[JWT Verify] Redis {'已刷新' if force_refresh else '已缓存'} PEM 公钥: {self.key_name}")
                else:
                    logger.warning(f"[JWT Verify] 公钥缓存已存在, 跳过覆盖: {self.key_name}")
            except Exception as e:
                logger.error(f"[JWT Verify] Redis 缓存失败: {e}")
                
            logger.info(f"[JWT Verify] 构造并缓存 PEM 公钥成功: {self.key_name}")
            return public_key
    
    def refresh_public_key(self):
        """
        外部调用接口:强制刷新Redis中的 PEM 公钥
        """
        self.public_key = self._load_or_cache_public_key(force_refresh=True)
    
    @staticmethod
    def base64url_decode(data: str) -> bytes:
        """
        JWT base64url 解码(自动补足 =)
        """
        try:
            # 清洗输入, 去除空格和换行符(常见于传输错误)
            clean_data = data.strip().replace('\n', '').replace(' ', '')
            # 补足 padding (=), base64 必须是4的倍数
            padding_len = (4 - len(clean_data) % 4) % 4
            clean_data += "=" * padding_len
            return base64.urlsafe_b64decode(clean_data)
        
        except Exception as e:
            raise RuntimeError(f"无效的 base64url 编码: {e}")
        
    def verify(self, token: str) -> Dict[str, Any]:
        """
        验证 JWT Token 的签名合法性和过期状态(支持 payload 短时缓存)
        :param token: 待验证的 JWT 三段式字符串(header.payload.signature)
        :return: 解码后的 payload 内容(字典)
        """
        try:
            # 使用 sha256 哈希生成稳定缓存键
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            payload_cache_key = f"{self.redis_prefix}payload:{token_hash}" # 使用 hash 防止 token 过长
            
            if not self.debug: # 仅在生产环境启用 payload 缓存
                # 尝试 Redis 命中 Payload 缓存
                cache_payload = self.redis.get(payload_cache_key)
                if cache_payload:
                    logger.info("[JWT Verify] 命中 Payload 缓存")
                    return json.loads(cache_payload if isinstance(cache_payload, bytes) else str(cache_payload))
                
            # 解析 JWT 三段式
            header_b64, payload_b64, signature_b64 = token.split(".")
            signing_input = f"{header_b64}.{payload_b64}".encode()
            signature = self.base64url_decode(signature_b64)
                
            # 校验签名算法, 防止算法注入攻击(alg none漏洞)
            header = json.loads(self.base64url_decode(header_b64))
            if header.get("alg") != "RS256":
                raise RuntimeError(f"不支持的 JWT 签名算法: {header.get('alg')}")
                
            # 仅允许 RSA 公钥类型用于验证 RS256 签名
            if not isinstance(self.public_key, rsa.RSAPublicKey): # 检查公钥类型是否符合 RSA 标准
                raise RuntimeError("Loaded public key is not an RSA public key and cannot verify RS256 signatures.")
                
            # 执行签名验证(RSASSA-PKCS1-v1_5 + SHA256)
            self.public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(), # 使用 RSA-PKCS#1 v1.5 + SHA256 进行标准 RS256 验签
                hashes.SHA256(),
            )
                
            # 解码 Payload 并做基本校验
            payload = json.loads(self.base64url_decode(payload_b64))
            
            if not self.debug:    
                try:
                    self.redis.set(payload_cache_key, json.dumps(payload), ex=60)
                    logger.info("[JWT Verify] Payload 缓存写入成功")
                except Exception as cache_err:
                    logger.warning(f"[JWT Verify] Payload 缓存写入失败: {cache_err}")
                
            # 字段校验逻辑
            now = int(time.time())
            exp = payload.get("exp")
            iat = payload.get("iat")
            sub = payload.get("sub")
                
            if not isinstance(exp, int) or now > exp:
                raise RuntimeError("JWT Token 已过期或无效")
            if not isinstance(iat, int) or iat > now:
                raise RuntimeError("JWT Token 时间异常")
            if not sub or not isinstance(sub, str) or len(sub.strip()) < 6:
                raise RuntimeError("JWT Token 中 sub 字段非法")
                
            # 可选校验: 签发者字段
            expected_issuer = "https://openai-chat.xyz"
            if payload.get("iss") != expected_issuer:
                raise RuntimeError("JWT Token 签发者不受信任")
                
            # 可选校验: 受众字段
            expected_audience = "openai-chat-client"
            if payload.get("aud") and payload["aud"] != expected_audience:
                raise RuntimeError("JWT Token 受众不匹配")
                
            # 可选校验: scope 权限字段
            allowed_scopes = {"user", "admin", "super"}
            if "scope" in payload and payload["scope"] not in allowed_scopes:
                raise RuntimeError("JWT 权限字段非法")
                
            return payload

        except Exception as e:
            logger.warning(f"[JWT Verify Failed] 验证失败: {e}")
            raise RuntimeError("JWT Token 非法或已过期")
    
    # === 类方法: 单例懒加载 ===
    _instance = None
    
    @classmethod
    def get_instance(cls) -> "AzureRS256Verifier":
        """
        获取全局单例实例
        - 避免频繁初始化 Azure 和 Redis 客户端
        - 可直接用于需要JWT验证的模块
        """
        if cls._instance is None:
            from django.conf import settings
            cls._instance = cls(
                vault_url = settings.AZURE_VAULT_URL,
                key_name = settings.JWT_KEY,
            )
        return cls._instance