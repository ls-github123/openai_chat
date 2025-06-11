# === TOTP 模块统一接口 ===
# 对外暴露 TOTP 模块主要视图接口, 便于其他模块调用
from .views import TOTPEnableView, TOTPVerifyView, TOTPDisableView

__all__ = [
    "TOTPEnableView", # 启用TOTP: 生成密钥 + 返回二维码
    "TOTPVerifyView", # 验证TOTP验证码, 首次启用则绑定启用状态,否则仅验证通过
    "TOTPDisableView", # 解绑TOTP: 清除secret和启用状态
]