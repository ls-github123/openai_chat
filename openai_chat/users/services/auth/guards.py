"""
Account Guard(账户级前置校验)

本模块用于【登录 / 令牌签发之前】的账户状态校验，确保当前用户在逻辑上
允许继续进入认证与令牌签发流程。

职责范围：
- 校验用户是否存在
- 校验账户是否已注销(is_deleted)
- 校验账户是否被禁用(is_active = False)

设计原则：
- 只读 User ORM 对象，不涉及 Redis / JWT / Session
- 不产生任何副作用(不写 DB、不写缓存)
- 校验失败统一通过抛出 AuthGuardError 子类异常中断流程
- 必须在以下场景调用：
  1. 密码登录成功后、签发 JWT 前
  2. TOTP 二次验证成功后、签发 JWT 前
  3. refresh_token 校验通过后、重新签发令牌前

不负责的内容：
- 多设备登录控制
- 会话(session)管理
- JWT / Redis 鉴权
- 权限(RBAC / Scope)判断

说明：
- 本 Guard 属于「账户级 Guard(AccountGuard)」
- 接口鉴权阶段将由 auth/guards 下的 Session / JWT Guard 接管
"""
from __future__ import annotations
from typing import Optional # 延迟类型注解解析
from users.models import User # 用户模型
from openai_chat.settings.utils.logging import get_logger
from users.exceptions import (
    AccountDeletedError,
    AccountDisabledError,
    InvalidUserError,
)

logger = get_logger("users")

def ensure_user_can_login(user: Optional[User], *, stage: str = "login") -> None:
    """
    统一登录/签发令牌前置校验(是否允许登录)
    - 必须在用户密码登录成功后 / TOTP验证成功后调用 / refresh_token刷新签发前调用
    - 失败:抛出 AuthGuardError 子类异常, 上级捕获并转标准响应
    :param user: User 实例(允许为None)
    :param stage: 调用阶段标识(login/totp/refresh), 用于日志定位
    """
    if user is None:
        logger.warning("[AuthGuard] reject: user is None stage=%s", stage)
        raise InvalidUserError("用户信息无效")
    
    # 防御式读取
    is_deleted = bool(getattr(user, "is_deleted", False))
    is_active = bool(getattr(user, "is_active", True))
    
    # 先判定删除状态
    if is_deleted:
        logger.warning(
            "[AuthGuard] reject: deleted stage=%s user_id=%s email=%s",
            stage, getattr(user, "id", None), getattr(user, "email", None),
        )
        raise AccountDeletedError("账户已被注销")
    
    # 再判定禁用状态
    if not is_active:
        logger.warning(
            "[AuthGuard] reject: disabled stage=%s user_id=%s email=%s",
            stage, getattr(user, "id", None), getattr(user, "email", None),
        )
        raise AccountDisabledError("账户已被禁用")