# === TOTP 模块统一接口 ===
# 对外暴露 TOTP 模块主要视图接口, 便于其他模块调用
from .totp_service import (
    init_totp, # 首次启用TOTP二次验证
    verify_and_bind_totp, # 绑定TOTP时, 验证TOTP动态验证码
    disabled_totp, # 解除TOTP绑定
    verify_login_totp, # 用户登录阶段二次验证 TOTP
)

__all__ = [
    "init_totp",
    "verify_and_bind_totp",
    "disabled_totp",
    "verify_login_totp",
]