"""
注册确认服务类: 校验验证码 + 写入数据库(接入 IdempotencyExecutor)
- 幂等性只用于 确认注册/落库 等强副作用步骤
"""
import json
from typing import Tuple, Dict, Any, Optional
from django.contrib.auth import get_user_model
from django.utils import timezone
from openai_chat.settings.utils.redis import get_redis_client # Redis客户端封装
from openai_chat.settings.utils.locks import build_lock # 引入Redlock分布式锁
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from openai_chat.settings.base import REDIS_DB_USERS_REGISTER_CACHE # 用户模块预注册缓存信息占用库
from openai_chat.settings.utils.redis.idempotency import ( # 幂等执行器
    IdempotencyExecutor,
    IdempotencyInProgressError,
    IdempotencyKeyConflictError
)


logger = get_logger("users")
User = get_user_model() # 获取自定义用户模型

class ConfirmRegisterService:
    """
    注册确认服务类:
    - 验证码一致性校验
    - 验证码错误计数(默认5次)
    - 用户注册信息落库
    - 注册成功后清除redis缓存
    - 接入幂等: 同一 Idempotency-key 只允许落库一次
    """
    def __init__(self, email: str, verify_code: str, idem_key: str):
        self.email = email.strip().lower() # 祛除空格 + 标准化邮箱
        self.verify_code = verify_code.strip() # 对传入验证码祛除空格
        self.idem_key = idem_key.strip()
        
        # 预注册缓存 key
        self.redis_key = f"register:{self.email}"
        self.redis = get_redis_client(db=REDIS_DB_USERS_REGISTER_CACHE)
        
        # 幂等执行器
        self.idem = IdempotencyExecutor()
    
    @staticmethod
    def _to_str(v: Any) -> str:
        """将 Redis 返回值安全转换为 str(redis-py 常返回 bytes)"""
        if v is None:
            return ""
        if isinstance(v, (bytes, bytearray)):
            return v.decode("utf-8", errors="replace")
        return str(v)
    
    def validate_code(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        校验验证码是否正确 + 限制错误次数
        - 验证码错误计数器
        - :return: 验证是否通过(True或False), 提示信息, Redis 中缓存的用户注册信息
        """
        # === 1.校验验证码是否已达失败限制 ===
        error_key = f"register:fail:{self.email}"
        MAX_ATTEMPTS = 5 # 验证码错误次数限制
        EXPIRE_SECONDS = 600 # 失败计数键过期时间(秒)
        
        raw_value = self.redis.get(error_key)
        try:
            # 获取当前验证码错误次数(如果键不存在则默认为0)
            failed_times = int(str(raw_value)) if raw_value else 0
            if failed_times >= MAX_ATTEMPTS:
                logger.warning(f"[用户注册] 用户{self.email}验证码输入错误次数过多, 需等待后重试!")
                return False, "验证码错误次数过多, 请稍后再试", {}
        except Exception as e:
            logger.error(f"[用户注册] 用户{self.email} 获取验证码失败次数异常: {e}")
        
        # === 2.获取用户在redis中的预注册缓存信息 ===
        try:
            raw = self.redis.get(self.redis_key)
            if not raw:
                return False, "注册信息不存在或验证码已过期", {}
            info = json.loads(self._to_str(raw)) # 解析JSON
        except UnicodeDecodeError as e:
            logger.error(f"[用户注册] Redis 缓存解码失败: {e}")
            return False, "缓存格式错误", {}
        except json.JSONDecodeError as e:
            logger.error(f"[用户注册] Redis JSON解析失败: {e}")
            return False, "缓存数据损坏", {}
        except Exception as e:
            logger.error(f"[用户注册] Redis 获取注册缓存失败: {e}")
            return False, "服务器异常, 请稍后重试", {}
        
        # === 3.验证码比对校验 ===
        if info.get("verify_code") != self.verify_code:
            try:
                # 在redis中对错误键执行自增(+1),如果该键不存在则自动创建并初始化为1
                self.redis.incr(error_key)
                # 设置验证码错误计数的过期时间为 10 分钟
                # 每次出错都刷新 TTL，相当于"连续出错 10 分钟内有效"
                # 10分钟内没有继续输错: Redis自动删除该键(即错误计数归零)
                self.redis.expire(error_key, EXPIRE_SECONDS) # 设置失败记录过期时间(10分钟)
            except Exception as e:
                logger.error(f"[用户注册] 增加失败次数异常: {e}")
            return False, "验证码错误, 请重试!", {}
        
        # === 4.验证通过清除当前用户错误记录缓存 ===
        try:
            self.redis.delete(error_key)
        except Exception as e:
            logger.error(f"[用户注册] 清除{self.email}验证码错误计数异常: {e}")
        
        return True, "验证通过", info
    
    def create_user(self, register_info: Dict[str, Any]) -> Tuple[bool, str, Optional[int]]:
        """
        创建用户(落库强副作用)
        - 分布式锁防止并发写入
        - DB 唯一约束仍存在(email unique)
        :return: (是否成功, 提示信息, user_id)
        """
        lock_key = f"lock:register:{self.email}"
        lock_ttl = 15000 # 锁超时时间(毫秒)
        lock = build_lock(lock_key, lock_ttl, strategy="safe") # 构建分布式锁实例
        
        with lock:
            try:
                if User.objects.filter(email=self.email).exists():
                    logger.warning(f"[用户注册] 注册失败: {self.email} 已存在")
                    return False, "该邮箱已被注册", None
                
                user = User.objects.create_user(
                    email=self.email,
                    username=self.email, # 用户名默认使用邮箱
                    phone=register_info.get("phone_number", ""),
                    password=register_info["password"], # 明文密码 -> 自定义 UserManager 自动加密
                    date_joined=timezone.now(),
                    is_active=True,
                )
                logger.info(f"[用户注册] 用户 {self.email} 注册成功 user_id={user.pk}")
                return True, "注册成功", int(user.pk)
            except Exception as e:
                logger.error(f"[用户注册] 创建用户失败: {e}")
                return False, "账户注册失败, 请稍后重试", None
    
    def clear_cache(self):
        """
        清除 Redis 注册缓存(注册成功后调用)
        """
        try:
            self.redis.delete(self.redis_key)
            logger.info(f"[用户注册] 用户:{self.email}注册信息缓存清除成功")
        except Exception as e:
            logger.warning(f"[用户注册] 清除用户: {self.email} 注册信息缓存失败: {e}")
            
    def process(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        对外入口: 确认注册
        - 接入幂等: 同一个 idem_key 只会成功执行一次 落库
        return: (是否成功, 提示信息, payload)
        """
        def _biz() -> Dict[str, Any]:
            # 1.校验验证码 + 取出预注册信息
            ok, msg, info = self.validate_code()
            if not ok:
                raise ValueError(msg)
            
            # 2.落库(强副作用)
            created, cmsg, user_id = self.create_user(info)
            if not created:
                raise ValueError(cmsg)
            
            # 3.清理预注册缓存
            self.clear_cache()
            
            # 4.返回可复用结果(重复请求直接返回该结果)
            return {
                "user_id": user_id,
                "email": self.email,
            }
        
        try:
            result = self.idem.execute(
                scope="register_confirm",
                idem_key=self.idem_key,
                ttl_seconds=30 * 60, # 30分钟
                func=_biz,
            )
            return True, "注册成功", result
        
        except IdempotencyInProgressError:
            # 同一幂等 key 正在处理中: 提示前端不要重复提交
            return False, "请求处理中, 请勿重复提交", {}
        
        except IdempotencyKeyConflictError:
            # 幂等 key 被污染/格式异常: 提示客户端更换 key
            return False, "请求冲突, 请刷新页面后重试", {}
        
        except ValueError as e:
            # 业务校验失败(验证码错误/邮箱已注册等)
            return False, str(e), {}
        
        except Exception as e:
            logger.error(f"[用户注册] 注册确认异常: {e}")
            return False, "服务器异常, 请稍后重试", {}