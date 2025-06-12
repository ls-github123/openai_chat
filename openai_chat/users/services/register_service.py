# 注册服务类
import json, random, time
from typing import Dict, Any, Tuple
from django.contrib.auth.hashers import make_password # 密码加密工具
from openai_chat.settings.utils.redis import get_redis_client # Redis客户端接口
from openai_chat.settings.utils.locks import build_lock # Lock锁
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from openai_chat.settings.utils.cloudflare_turnstile import verify_turnstile_token # Turnstile人机验证
from tasks.email_tasks import send_email_async_task # celery 异步发送邮件
from django.conf import settings # 全局配置访问
from openai_chat.settings.base import REDIS_DB_USERS_REGISTER_CACHE # 用户模块预注册缓存信息占用库

logger = get_logger("users")

class RegisterService:
    """
    预注册服务类, 封装注册逻辑, 用于 API 调用
    """
    def __init__(self, validated_data: Dict[str, Any], cf_token: str, remote_ip: str):
        self.validated_data = validated_data
        self.email = validated_data["email"]
        self.phone_number = validated_data.get("phone_number", "")
        self.password = validated_data["password"] # 获取用户明文密码
        self.cf_token = cf_token
        self.remote_ip = remote_ip
    
    def verify_human(self) -> bool:
        """
        校验 Cloudflare Turnstile 人机验证
        """
        secret_key = settings.TURNSTILE_USERS_SECRET_KEY
        return verify_turnstile_token(
            token=self.cf_token,
            secret_key=secret_key,
            remoteip=self.remote_ip,
        )
    
    def cache_register_info(self) -> Tuple[bool, str]:
        """
        缓存注册信息到 Redis(默认15分钟)
        - 成功: 返回True及生成的随机验证码
        - 失败: 返回False及空字符串
        """
        verify_code = f"{random.randint(100000, 999999)}"
        redis_key = f"register:{self.email}"
        redis_value = json.dumps({
            "email": self.email,
            "phone_number": self.phone_number,
            "password": self.password, # 直接明文写入
            "verify_code": verify_code,
        })
        
        users_register_redis = get_redis_client(db=REDIS_DB_USERS_REGISTER_CACHE)
        try:
            start = time.time()
            result = users_register_redis.set(redis_key, redis_value, ex=900, nx=True) # nx=True确保幂等性
            cost = int((time.time() - start) * 1000)
            logger.info(f"[用户注册] 用户注册信息Redis缓存写入耗时: {cost}ms")
        except Exception as e:
            logger.error(f"[用户注册] Redis写入用户注册缓存信息异常: {e}")
            return False, ""
        
        if not result:
            logger.info(f"[用户注册] {self.email} 已存在注册信息, 避免重复写入")
            return False, ""
        
        return True, verify_code
    
    def send_verify_email(self, verify_code: str):
        """
        调用Celery异步任务发送验证码邮件
        """
        subject = "【OpenAI Chat】注册验证码"
        html_content=f"""
            <p>您的注册验证码是: <strong>{verify_code}</strong></p>
            <P>验证码有效期 15 分钟, 如非本人操作请忽略此邮件。</P>
        """
        email_task: Any = send_email_async_task # 显式标注为 Any
        email_task.delay(to_email=self.email, subject=subject, html_content=html_content)
        
    def process(self) -> Tuple[bool, str]:
        """
        注册流程处理器, 封装:
        - 获取锁
        - 缓存数据
        - 发送邮件
        :return: (是否成功, 提示消息)
        """
        lock_key = f"lock:register:{self.email}"
        lock = build_lock(lock_key, ttl=5000, strategy="safe") # 使用Redlock分布式锁
        
        with lock:
            success, code = self.cache_register_info()
            if not success:
                return False, "验证码已发送, 请勿重复操作"
            self.send_verify_email(code)
            logger.info(f"[用户注册] {self.email} 注册流程完成, 验证码已发送")
            return True, "验证码邮件已发送, 请注意查收"