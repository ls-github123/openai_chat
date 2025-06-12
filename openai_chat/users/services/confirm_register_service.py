# 注册确认服务类: 校验验证码 + 写入数据库
import json
from typing import Tuple, Dict, Any
from django.contrib.auth import get_user_model
from django.utils import timezone
from asgiref.sync import sync_to_async # 同步转异步工具
from openai_chat.settings.utils.redis import get_redis_client # Redis客户端封装
from openai_chat.settings.utils.locks import build_lock # 引入Redlock分布式锁
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from openai_chat.settings.base import REDIS_DB_USERS_REGISTER_CACHE # 用户模块预注册缓存信息占用库

logger = get_logger("users")
User = get_user_model() # 获取自定义用户模型

class ConfirmRegisterService:
    """
    注册确认服务类:
    - 验证码一致性校验
    - 用户注册信息落库
    - 清理redis注册缓存
    """
    def __init__(self, email: str, verify_code: str):
        self.email = email.strip().lower() # 去除空格 + 标准化邮箱
        self.verify_code = verify_code.strip()
        self.redis_key = f"register:{self.email}"
        self.redis = get_redis_client(db=REDIS_DB_USERS_REGISTER_CACHE)
        
    async def validate_code(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        异步校验验证码是否匹配 Redis 缓存
        - :return: 是否通过(True或False), 提示信息, Redis 中缓存的用户注册信息
        """
        try:
            raw = await self.redis.get(self.redis_key)
            if not raw:
                return False, "注册信息不存在或验证码已过期", {}
            info = json.loads(raw.decode("utf-8")) # 解析JSON
        
        except UnicodeDecodeError as e:
            logger.error(f"[用户注册] Redis 缓存解码失败: {e}")
            return False, "缓存格式错误", {}
        
        except json.JSONDecodeError as e:
            logger.error(f"[用户注册] Redis JSON解析失败: {e}")
            return False, "缓存数据损坏", {}
        
        except Exception as e:
            logger.error(f"[用户注册] Redis 获取注册缓存失败: {e}")
            return False, "服务器异常, 请稍后重试", {}
        
        if info.get("verify_code") != self.verify_code:
            return False, "验证码错误", {}
        
        return True, "验证通过", info
    
    async def create_user(self, register_info: Dict[str, Any]) -> Tuple[bool, str]:
        """
        异步创建用户(通过 sync_to_async 包装同步ORM)
        - with lock 加锁防止并发写入
        - :param register_info: Redis 缓存中的注册信息(含加密密码、手机号)
        """
        lock_key = f"lock:register:{self.email}"
        lock_ttl = 15000 # 锁超时时间(毫秒)
        lock = build_lock(lock_key, lock_ttl, strategy="safe") # 构建分布式锁实例
        
        @sync_to_async
        def _create():
            if User.objects.filter(email=self.email).exists():
                return False, "该邮箱已被注册"
                
            User.objects.create_user(
                email=self.email,
                username=self.email, # 用户名默认使用邮箱
                phone=register_info.get("phone_number", ""),
                password=register_info["password"], # 明文密码 -> 自定义 UserManager 自动加密
                date_joined=timezone.now(),
                is_active=True,
            )
            logger.info(f"[用户注册] 用户 {self.email} 注册成功")
            return True, "注册成功"
        
        with lock: # 加入分布式锁, 防止并发写入
            return await _create() # 等待ORM写入完成
    
    async def clear_cache(self):
        """
        异步清除 Redis 注册缓存(注册成功后调用)
        """
        try:
            await self.redis.delete(self.redis_key)
            logger.info(f"[用户注册] 用户:{self.email}注册信息缓存清除成功")
        except Exception as e:
            logger.warning(f"[用户注册] 清除用户: {self.email} 注册信息缓存失败: {e}")