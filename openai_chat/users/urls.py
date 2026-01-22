from django.urls import path
from users.views.register_pre_view import RegisterPreView # 用户预注册视图
from users.views.register_confirm import RegisterConfirmView # 用户注册确认视图
from users.views.login_pre import LoginPreView # 用户登录阶段一视图(邮箱+密码, 校验是否启用TOTP)
from users.views.loginTOTPVerifyView import LoginTOTPVerifyView # 用户登录阶段二视图(校验TOTP验证码)
# from users.views.userinfo_view import 
from users.views.token_refresh_view import TokenRefreshView # 用户令牌刷新视图
from users.views.logout_view import LogoutView # 用户退出登录状态视图(拉黑access_token + refresh_token)

urlpatterns = [
    # 用户注册
    path("register/pre/", RegisterPreView.as_view(), name="register_pre"), # 注册预处理：缓存注册信息 + 发送验证码
    path("register/confirm/", RegisterConfirmView.as_view(), name="register_confirm"), # 注册确认：验证码验证 + 注册落库
    
    # 登录
    path("login/", LoginPreView.as_view(), name="login"), # 登录阶段一：邮箱+密码+人机验证
    
    # TOTP二次验证接口
    path("login/totp/", LoginTOTPVerifyView.as_view(), name="login_totp"), # 登录阶段二：TOTP 二次验证
    
    # 用户令牌刷新
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"), # 刷新 access_token 和 refresh_token
    
    # 用户信息获取/查询
    # path("userinfo/", ),
    
    # 密码重置
    # path("password/refresh",),
    
    # 退出
    path("logout/", LogoutView.as_view(), name="logout"), # 用户退出登录
]