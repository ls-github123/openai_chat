from django.urls import path
from users.views.register_pre_view import RegisterPreView # 用户预注册视图
from users.views.register_confirm_view import RegisterConfirmView # 用户注册确认视图
from users.views.login_view import LoginPreView # 用户登录阶段一视图(邮箱+密码, 校验是否启用TOTP)
from users.views.loginTOTPVerifyView import LoginTOTPVerifyView # 用户登录阶段二视图(校验TOTP验证码)
# 已登录用户TOTP管理视图: 初始化绑定、确认启用、解绑
from users.views.totp import TOTPInitView, TOTPConfirmView, TOTPDisableView
from users.views.user_info_view import UserInfoView # 当前登录用户信息获取视图
from users.views.token_refresh_view import TokenRefreshView # 用户令牌刷新视图
from users.views.logout_view import LogoutView # 用户退出登录状态视图(拉黑access_token + refresh_token)

urlpatterns = [
    # 用户注册
    path("register/pre/", RegisterPreView.as_view(), name="register_pre"), # 注册预处理：缓存注册信息 + 发送验证码
    path("register/confirm/", RegisterConfirmView.as_view(), name="register_confirm"), # 注册确认：验证码验证 + 注册落库
    
    # 登录
    path("login/", LoginPreView.as_view(), name="login"), # 登录阶段一：邮箱+密码+人机验证
    
    # TOTP 登录二次验证接口
    path("login/totp/", LoginTOTPVerifyView.as_view(), name="login_totp"), # 登录阶段二：TOTP 二次验证
    
    # 初始化TOTP 绑定
    path("totp/init/", TOTPInitView.as_view(), name="totp_init"),
    
    # 确认启用TOTP: 校验6位动态码, 成功后正式写入用户 TOTP secret
    path("totp/confirm/", TOTPConfirmView.as_view(), name="totp_confirm"),
    
    # 解绑TOTP: 校验当前动态码, 成功后清空TOTP secret并提升会话版本
    path("totp/disable/", TOTPDisableView.as_view(), name="totp_disable"),
    
    # 用户令牌刷新
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"), # 接收refresh token, 输出刷新的 access_token
    
    # 当前登录用户用户信息获取/查询(仅返回当前 access token 对应用户)
    path("userinfo/", UserInfoView.as_view(), name="userinfo"),
    
    # 密码重置
    # path("password/refresh",),
    
    # 退出
    path("logout/", LogoutView.as_view(), name="logout"), # 用户退出登录
]