"""
SimpleUI 配置模块
- 后台界面、菜单、主题、权限菜单等相关配置
- 后台面向生产运维使用, 菜单必须显式、可审计、按权限过滤
"""
# === Django Admin 标题配置 ===
ADMIN_SITE_HEADER = "OpenAI Chat 系统管理后台"
ADMIN_SITE_TITLE = "OpenAI Chat 管理后台"
ADMIN_INDEX_TITLE = "身份与安全控制台"

# === SimpleUI 基础界面配置 ===
SIMPLEUI_INDEX = "/admin/"
SIMPLEUI_LOGO = "/static/admin/simpleui-x/img/logo.png"
SIMPLEUI_HOME_TITLE = "OpenAI Chat 安全运营台"
SIMPLEUI_HOME_ICON = "fa fa-shield-halved"
SIMPLEUI_ANALYSIS = False
SIMPLEUI_DEFAULT_THEME = "e-black-pro.css"
SIMPLEUI_LOGIN_PARTICLES = False
SIMPLEUI_HOME_INFO = False
SIMPLEUI_HOME_ACTION = True
SIMPLEUI_HOME_QUICK = True

# SimpleUI 未显式配置图标的模型兜底图标
SIMPLEUI_DEFAULT_ICON = "fa fa-circle"

SIMPLEUI_ICON = {
    "用户": "fa fa-user-shield",
    "用户表": "fa fa-user-shield",
    "登录记录": "fa fa-clock-rotate-left",
    "Groups": "fa fa-users-gear",
    "组": "fa fa-users-gear",
    "Permissions": "fa fa-key",
    "权限": "fa fa-key",
    "Outstanding tokens": "fa fa-key",
    "有效刷新令牌": "fa fa-key",
    "Blacklisted tokens": "fa fa-ban",
    "黑名单令牌": "fa fa-ban",
    "OpenAI Provider 配置": "fa fa-plug",
    "OpenAI 模型配置": "fa fa-microchip",
    "OpenAI API 调用日志": "fa fa-chart-line",
}

# === SimpleUI 自定义菜单 ===
SIMPLEUI_CONFIG = {
    # 生产后台采用显式菜单, 防止第三方模型被自动暴露在侧边栏
    "system_keep": False,
    
    # 一级菜单显示内容与顺序
    "menu_display": [
        "首页",
        "身份与用户",
        "安全与令牌",
        "权限治理",
        "OpenAI API",
    ],
    
    "menus": [
        {
            "name": "身份与用户",
            "icon": "fa fa-user-shield",
            "models": [
                {
                    "name": "用户列表",
                    "icon": "fa fa-users",
                    "url": "users/user/",
                    "permission": "users.view_user",
                },
                {
                    "name": "登录记录",
                    "icon": "fa fa-clock-rotate-left",
                    "url": "users/userloginrecord/",
                    "permission": "users.view_userloginrecord",
                },
            ],
        },
        {
            "name": "安全与令牌",
            "icon": "fa fa-shield",
            "models": [
                {
                    "name": "有效刷新令牌",
                    "icon": "fa fa-key",
                    "url": "token_blacklist/outstandingtoken/",
                    "permission": "token_blacklist.view_outstandingtoken",
                },
                {
                    "name": "黑名单令牌",
                    "icon": "fa fa-ban",
                    "url": "token_blacklist/blacklistedtoken/",
                    "permission": "token_blacklist.view_blacklistedtoken",
                },
            ],
        },
        {
            "name": "权限治理",
            "icon": "fa fa-users-gear",
            "models": [
                {
                    "name": "用户组",
                    "icon": "fa fa-users-gear",
                    "url": "auth/group/",
                    "permission": "auth.view_group",
                },
            ],
        },
        {
            "name": "OpenAI API",
            "icon": "fa fa-robot",
            "models": [
                {
                    "name": "Provider 配置",
                    "icon": "fa fa-plug",
                    "url": "openai_api/openaiproviderconfig/",
                    "permission": "openai_api.view_openaiproviderconfig",
                },
                {
                    "name": "模型配置",
                    "icon": "fa fa-microchip",
                    "url": "openai_api/openaimodelconfig/",
                    "permission": "openai_api.view_openaimodelconfig",
                },
                {
                    "name": "调用日志",
                    "icon": "fa fa-chart-line",
                    "url": "openai_api/openaiusagelog/",
                    "permission": "openai_api.view_openaiusagelog",
                },
            ],
        },
    ],
}
