from __future__ import annotations
"""
用户预注册服务类

设计要点：
- 冷却窗口（防重复发送验证码）与预注册信息分离：
  - cooldown key：短 TTL（例 60s）
  - prereg key：长 TTL（例 15min）
- Redis 内不保存明文密码：保存 Django make_password() 生成的哈希
- service 层失败一律抛 AppException，view 层统一 serializer校验 + 成功 json_response
"""

# === 标准库导入: 时间 \ 安全随机数 \ JSON序列化 ===
import secrets, json, hashlib
from typing import Any, Dict, cast # 类型注解: 明确payload结构

#  === Django/DRF 相关导入 ===
from django.contrib.auth import get_user_model # 获取当前 User 模型
from django.contrib.auth.hashers import make_password # Django 标准密码哈希
from django.conf import settings # Django 全局配置: 读取 Turnstile 配置

# === 项目内封装导入 ===
from openai_chat.settings.utils.redis import get_redis_client # Redis客户端封装
from openai_chat.settings.utils.logging import get_logger # 日志记录器
from openai_chat.settings.utils.exceptions import AppException # 业务异常: 统一抛错(DRF异常处理器)
from openai_chat.settings.utils.error_codes import ErrorCodes # 错误码常量表(避免硬编码字符串)

# Turnstile 人机验证(保留接口位)
from openai_chat.settings.utils.cloudflare_turnstile import (
    verify_turnstile_token_async, # Turnstile校验(异步函数)
)

# Celery 邮件任务(Resend 发送链路)
from tasks.email_tasks import send_email_async_task # 异步发送邮件任务(Celery task)

logger = get_logger("users")
User = get_user_model()

class RegisterPreService:
    """  
    用户预注册服务类
    
    输入:
    - validated_data: serializer 已校验通过的数据
    - cf_token: Turnstile token(可选)
    - remote_ip: 客户端IP(Turnstile 可用; 风控)
    
    输出:
    - 成功: 返回 dict(给 view 的 json_response.data)
    - 失败: 抛 AppException(由DRF统一异常处理器输出五段式)
    """
    # TTL 配置
    COOLDOWN_TTL_SECONDS = 60 # 冷却窗口 TTL: 60秒内禁止重复发送
    PREREG_TTL_SECONDS = 900 # 预注册信息保留 TTL: (秒)
    
    # Redis Key 前缀
    KEY_PREFIX_PREREG = "register:prereg" # 预注册信息 key
    KEY_PREFIX_COOLDOWN = "register:cooldown" # 冷却窗口 key
    
    def __init__(self, validated_data: Dict[str, Any], cf_token: str, remote_ip: str):
        self.validated_data = validated_data
        self.email: str = validated_data["email"]
        self.phone_number: str = validated_data.get("phone_number", "")
        self.password_plain: str = validated_data["password"] # 明文仅在内存使用
        self.cf_token = cf_token
        self.remote_ip = remote_ip
        # Redis 客户端(同步): 注册缓存分库
        redis_db = getattr(settings, "REDIS_DB_USERS_REGISTER_CACHE", 0)
        self.redis = get_redis_client(db=redis_db)
    
    # Key 构造
    def _key_prereg(self) -> str:
        """预注册信息 key: 长期 TTL"""
        return f"{self.KEY_PREFIX_PREREG}:{self.email}"
    
    def _key_cooldown(self) -> str:
        """冷却窗口key: 短TTL"""
        return f"{self.KEY_PREFIX_COOLDOWN}:{self.email}"
    
    # === 工具方法 ===
    def _generate_verify_code(self) -> str:
        """
        生成 6 位数字验证码(安全随机)
        - 使用 secrets 避免 random 可预测性
        """
        return f"{secrets.randbelow(10**6):06d}"
    # - 验证码生成 / 哈希处理
    def _hash_verify_code(self, code: str) -> str:
        """SHA256(code)"""
        return hashlib.sha256(code.encode("utf-8")).hexdigest()
    
    # === 邮件 ===
    def _send_verify_email_async(self, verify_code: str, biz_key: str) -> None:
        """
        调用 Celery 任务发送验证码邮件
        - delay/apply_async
        - 若调度失败, 抛出业务异常(DRF统一异常处理器输出)
        """
        subject = "【OpenAI Chat】注册验证码"
        html_body = (
			f"<p>您的注册验证码是: <strong>{verify_code}</strong></p>"
            f"<p>验证码有效期 15 分钟，如非本人操作请忽略此邮件。</p>"
		)
        try:
            task = cast(Any, send_email_async_task)
            task.delay(
                biz_key=biz_key,
				to_email=self.email,
                subject=subject,
                html_content=html_body,
			)
        except Exception as e:
            logger.exception("[用户注册] 发送验证码邮件任务调度失败", extra={"email": self.email})
        
        # 删除 prereg + cooldown, 允许用户立即重试(避免发送失败但用户操作被锁)
            try:
                self.redis.delete(self._key_prereg())
                self.redis.delete(self._key_cooldown())
            except Exception:
                pass
            
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_ERROR,
                message="验证码发送失败, 请稍后重试",
            ) from e
    
    # Turnstile校验(测试阶段略过不开启)
    # async def _verify_human_async(self) -> bool:
    #     """
    #     Turnstile 人机验证(异步)
    #     - ⚠️ 代码保留
    #     - 测试阶段暂不启用
    #     """
    #     secret_key = getattr(settings, "TURNSTILE_USERS_SECRET_KEY", "")
    #     if not secret_key:
    #         # 未配置规则视为不启用(生产环境时配置)
    #         return True
        
    #     return await verify_turnstile_token_async(
    #         token=self.cf_token,
    #         secret_key=secret_key,
    #         remoteip=self.remote_ip,
    #     )
    
    # 核心流程
    def process(self) -> Dict[str, Any]:
        """
        预注册处理流程(同步入口):
        - 1.邮箱已注册 -> 409
        - 2.冷却窗口写入(NX + EX=60) 失败 -> 返回剩余时间提示(400)
        - 3.写入预注册信息(EX=900) + 覆盖写(允许刷新验证码但仍受 cooldown 控制)
        - 4.发送验证码邮件(Celery)
        """
        # 1. 邮箱重复性检查(避免重复注册)
        if User.objects.filter(email=self.email).exists():
            logger.warning("[用户注册] 预注册失败: 邮箱已存在 email=%s", self.email)
            raise AppException.conflict(
				code=ErrorCodes.REGISTER_EMAIL_EXISTS,
                message="该邮箱已注册, 请直接登录或使用密码重置功能",
			)
            
        # 2. 冷却窗口: 窗口时间内禁止重复发送验证码
        cooldown_key = self._key_cooldown()
        try:
            cooldown_ok = self.redis.set(
				cooldown_key,
                "1",
                nx=True,
                ex=self.COOLDOWN_TTL_SECONDS + secrets.randbelow(10), # TTL加抖动, 避免Redis雪崩
			)
        except Exception as e:
            logger.exception("[用户注册] Redis 写入冷却窗口异常", extra={"email": self.email})
            raise AppException.bad_request(
				code=ErrorCodes.COMMON_ERROR,
                message="系统繁忙, 请稍后重试",
			) from e
        
        if not cooldown_ok:
            # 冷却窗口未结束 -> 告知剩余时间
            ttl = -1
            try:
                ttl = self.redis.ttl(cooldown_key)
            except Exception:
                ttl = -1
            
            logger.info("[用户注册] 冷却命中 email=%s ttl=%s", self.email, ttl)
            
            if isinstance(ttl, int) and ttl > 0:
                raise AppException.bad_request(
					code=ErrorCodes.RATE_LIMIT_TOO_MANY_REQUESTS,
                    message=f"验证码已发送, 请勿重复操作(约 {ttl} 秒后可重新申请)",
                    data={"retry_after": ttl},
				)
            raise AppException.bad_request(
				code=ErrorCodes.RATE_LIMIT_TOO_MANY_REQUESTS,
                message="验证码已发送, 请勿重复操作",
			)
        
        # 3.写入预注册信息(密码/验证码 明文转为哈希后写入)
        verify_code = self._generate_verify_code()
        verify_code_hash = self._hash_verify_code(verify_code) # 验证码 SHA256
        password_hash = make_password(self.password_plain)
        
        prereg_key = self._key_prereg()
        prereg_value = json.dumps(
			{
				"email": self.email,
                "phone_number": self.phone_number,
                "password_hash": password_hash, # 只保存密码哈希
                "verify_code_hash": verify_code_hash, # 保存验证码SHA256后的字符串
			},
            ensure_ascii=False,
		)
        
        try:
            self.redis.set(
                prereg_key,
                prereg_value,
                ex=self.PREREG_TTL_SECONDS
            )
        except Exception as e:
            logger.exception("[用户注册] Redis 写入预注册信息异常", extra={"email": self.email})
            # 删除 cooldown key, 允许用户立刻重试("避免写缓存失败但用户请求被冷却锁死")
            try:
                self.redis.delete(cooldown_key)
            except Exception:
                pass
            
            raise AppException.bad_request(
				code=ErrorCodes.COMMON_ERROR,
                message="系统繁忙, 请稍后重试",
			) from e
        
        # 4.发送验证码邮件(只在 Redis 写入成功后执行)
        biz_key = f"register:email:verify:{self.email}:{verify_code_hash}"
        self._send_verify_email_async(
            verify_code=verify_code,
            biz_key=biz_key
        )
        logger.info("[用户注册] 预注册完成 email=%s", self.email)
        
        return {
			"email": self.email,
            "expire_in": self.PREREG_TTL_SECONDS,
            "cooldown_in": self.COOLDOWN_TTL_SECONDS,
		}