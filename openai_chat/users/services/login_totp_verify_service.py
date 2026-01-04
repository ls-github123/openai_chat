"""
用户登录服务类(二阶段TOTP验证)
"""
from __future__ import annotations # 延迟类型注解解析
import json
from typing import Any, Dict, cast
from users.models import User # 自定义用户模型

from openai_chat.settings.utils.jwt.jwt_token_service import TokenIssuerService
from openai_chat.settings.utils.redis import get_redis_client
from openai_chat.settings.base import REDIS_DB_USERS_LOGIN_PENDING
from openai_chat.settings.utils.logging import get_logger

from users.services.auth.guards import ensure_user_can_login # 二次验证前仍需校验账户状态
from users.services.user_state_service import UserStateService # 二次验证成功后可选同步用户状态事实源

from users.totp import verify_login_totp
from .login_service import LOGIN_PENDING_PREFIX # 预登录缓存Redis key
from users.services.user_info_service import UserInfoService # 用户信息服务类

logger = get_logger("users")

class LoginTOTPVerifyService:
    """
    用户登录服务类(二阶段)
    - 读取预登录 pending 缓存(challenge_id)
    - 校验 TOTP 6位验证码
    - 校验通过: 再次执行用户状态校验 + (可选) 同步用户状态事实源
    - 清除预登录 pending 缓存(防重放)
    - 签发 JWT access + refresh token
    - 返回 tokens + user_info
    """
    def __init__(self, challenge_id: str, totp_code: str):
        """
        初始化服务类
        :param challenge_id: 登录阶段一返回的 challenge_id (预登录缓存key)
        :param totp_code: 用户提交的6位TOTP验证码
        """
        self.challenge_id = str(challenge_id).strip()
        self.totp_code = str(totp_code).strip()
        self.redis = get_redis_client(db=REDIS_DB_USERS_LOGIN_PENDING)
        
    def verify_and_issue_token(self) -> Dict[str, Any]:
        """
        核心逻辑:
        - 读取用户预登录缓存
        - 获取 uid 并查询用户
        - 校验 TOTP 验证码
        - 校验用户状态(禁用/注销等)
        - 清除 pending 缓存
        - 签发 JWT (access/refresh token)
        """
        if not self.challenge_id:
            raise ValueError("登录状态无效, 请重新登录")
        
        cache_key = f"{LOGIN_PENDING_PREFIX}:{self.challenge_id}"
        cache_raw = self.redis.get(cache_key)
        
        if not cache_raw:
            logger.warning("[TOTPVerify] rejected: pending missing challenge_id=%s", self.challenge_id)
            raise ValueError("登录状态已过期, 请重新登录")
        
        # pending 内容在 LoginService 中用 json.dumps 序列化存储
        try:
            if isinstance(cache_raw, (bytes, bytearray)):
                cache_raw = cache_raw.decode("utf-8") # byted -> str
            elif not isinstance(cache_raw, str):
                # 防御: 类型异常直接视为无效缓存
                raise TypeError(f"缓存数据类型异常: {type(cache_raw)}")
            pending = cast(Dict[str, Any], json.loads(cache_raw))
        except Exception as e:
            logger.error("[TOTPVerify] pending parse failed challenge_id=%s err=%s", self.challenge_id, e)
            # 数据损坏, 直接删除缓存
            try:
                self.redis.delete(cache_key)
            except Exception as del_err:
                logger.error("[TOTPVerify] pending deleted failed challenge_id=%s err=%s", self.challenge_id, del_err)
            raise RuntimeError("系统内部错误, 请重新登录")
        
        uid = str(pending.get("uid", "")).strip() # 用户ID
        if not uid:
            logger.error("[TOTPVerify] pending invalid: missing uid challenge_id=%s", self.challenge_id)
            try:
                self.redis.delete(cache_key)
            except Exception as del_err:
                logger.error("[TOTPVerify] pending deleted failed challenge_id=%s err=%s", self.challenge_id, del_err)
            raise RuntimeError("系统内部错误, 请重新登录")
        
        # 查询用户
        try:
            user = cast(User, User.objects.get(id=uid))
        except User.DoesNotExist:
            logger.warning("[TOTPVerify] user missing uid=%s challenge_id=%s", uid, self.challenge_id)
            try:
                self.redis.delete(cache_key) # 删除无效缓存
            except Exception as del_err:
                logger.error("[TOTPVerify] pending deleted failed challenge_id=%s err=%s", self.challenge_id, del_err)
            raise ValueError("用户不存在或登录状态已失效")
        
        # TOTP校验(内部包含错误计数/锁定逻辑)
        if not verify_login_totp(user, self.totp_code):
            logger.warning("[TOTPVerify] rejected: bad totp uid=%s challenge_id=%s", user.id, self.challenge_id)
            raise ValueError("TOTP验证码错误或已超出最大尝试次数")
        
        # 二次验证通过后, 再次校验用户状态(防止两阶段间隙被禁用/注销)
        ensure_user_can_login(user, stage="totp")
        
        # (可选)同步用户状态事实源, 降低Redis状态陈旧概率
        UserStateService.sync_to_redis(user)
        
        # 清除 pending 缓存(签发前清除, 避免并发重放)
        try:
            self.redis.delete(cache_key)
        except Exception as del_err:
            # 非阻塞错误, 仅记录日志
            logger.error("[TOTPVerify] pending deleted failed challenge_id=%s err=%s", self.challenge_id, del_err)

        logger.info(
            "[TOTPVerify] ok uid=%s email=%s -> issue jwt",
            user.id,
            user.email,
        )
        
        # 签发 JWT
        token_service = TokenIssuerService(user)
        tokens = token_service.issue_tokens()
        
        # 返回用户快照(缓存命中则不查询DB, 未命中则回源并缓存)
        user_info = UserInfoService.get_user_info(str(user.id))
        return {
            **tokens, # 展开 access 和 refresh字段
            "user": user_info,
        }