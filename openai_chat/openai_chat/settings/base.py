# base.py
"""
项目核心配置文件
- 管理数据库连接(Mysql、MongoDB)
- 配置缓存服务(Redis)
- 配置安全设置和中间件
- 日志配置统一
"""
import json
from pathlib import Path # 导入路径处理工具
from openai_chat.settings.utils.logging import build_logging # 日志构建器
from openai_chat.settings.utils import path_utils # 导入路径工具模块
from .config import get_config, SecretConfig, VaultClient # 从config.py导入配置项
# from pymongo import MongoClient # MongoDB客户端
from openai_chat.settings.utils.mysql_config import get_mysql_config # 导入Mysql数据库连接池


# 基础目录
BASE_DIR = path_utils.BASE_DIR # 项目根路径

# === Azure Key Vault 配置 ===
AZURE_VAULT_URL = get_config("AZURE_VAULT_URL", default="https://openai-chat-key.vault.azure.net/")
JWT_KEY = get_config("JWT_RSA_SECRET_KEY_NAME", default="JWT-RSA_SECRET-KEY")


# 安全配置
SECRET_KEY = SecretConfig.DJANGO_SECRET_KEY # Django密钥
# DEBUG = config("DEBUG", cast=bool, default=True)
# ENVIRONMENT = config("ENVIRONMENT", default="dev") # 当前运行环境类型
# 允许的主机列表 Csv()用于将逗号分隔的字符串转换为列表
# ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv(), default="*")

# --- 应用注册 ---
INSTALLED_APPS = [
    # === Django 官方内置应用 ===
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles', # 静态文件处理
    
    # === 第三方库 ===
    'rest_framework', # DRF核心
    'rest_framework_simplejwt.token_blacklist', # JWT黑名单支持
    'corsheaders', # 跨域支持组件
    
    # === 本地业务应用 ===
    'interface_test', # 接口测试模块
    'users', # 用户管理模块
    'system.apps.SystemConfig', # 系统初始化模块
]

# === REST Framework配置(适用生产环境) ===
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES':( # 默认认证方式配置(用于识别用户身份)
        # 使用自定义的JWT认证类
        'openai_chat.settings.utils.jwt.jwt_auth.JWTAuthentication',
        
        # 支持后台管理页面使用使用 Cookie 登录
        'rest_framework.authentication.SessionAuthentication', 
    ),
    'DEFAULT_PERMISSION_CLASSES':(
        # 默认权限控制类:
        # - 默认所有 API 仅允许“已认证用户”访问
        # - 未认证请求通常返回 401 Unauthorized
        # - 已认证但无权限的请求返回 403 Forbidden
        # 注: 最终对前端返回的错误结构与错误码
        #   由统一异常处理器进行规范化封装
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer', # 只返回 JSON，禁用 Browsable API
    ),
    'DEFAULT_PARSER_CLASSES': (
        'rest_framework.parsers.JSONParser', # 限制只接受 JSON 请求体
    ),
    # 统一异常处理器
    'EXCEPTION_HANDLER': 'openai_chat.settings.utils.drf_exception_handler.custom_exception_handler',
}

# === JWT 模块配置 ===
# JWT认证配置
SIMPLE_JWT = {
    "ALGORITHM": "RS256", # 非对称加密算法
    "SIGNING_KEY": None, # 不使用本地私钥, 改为外部公钥验证
    "VERIFYING_KEY": None, # 公钥验证由自定义验证器(verifier)完成
    "AUTH_HEADER_TYPES": ("Bearer",), # Token前缀
    "USER_ID_FIELD": "id", # Django用户模型主键字段(识别用户身份)
    "USER_ID_CLAIM": "sub", # JWT payload 中用户身份识别字段(sub)
    "TOKEN_TYPE_CLAIM": "typ", # 标记 token 类型(如 access/refresh)
    "JTI_CLAIM": "jti", # JWT ID, 唯一标识, 用于 token 黑名单或撤销机制
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",), # 指定解析的 Token 类型
    "TOKEN_USER_CLASS": "users.models.User", # 自定义用户模型路径
}

# JWT 扩展配置(jwt_payload.py使用)
JWT_ISSUER = "openai-chat.xyz" # JWT 签发方标识
JWT_AUDIENCE = "openai_chat_user" # JWT接收方标识
JWT_SCOPE_DEFAULT = "user" # 默认权限范围
# JWT 令牌生命周期配置
JWT_ACCESS_TOKEN_LIFETIME = 60 * 60 # Access Token默认有效期(60分钟)
JWT_REFRESH_TOKEN_LIFETIME = 60 * 60 * 24 * 7 # Refresh Token默认有效期(7天)


# === 配置Django AUTH用户认证系统所需用户模型 ===
# 格式: 子应用名.模型名 -- 数据第一次迁移时配置完成
AUTH_USER_MODEL = "users.User"

# === 密码加密策略配置 ===
PASSWORD_HASHERS = [
    # 优先使用 bcrypt + sha256 加密密码
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    # 兼容其他可能存在的旧加密方式（可选但建议保留）
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.ScryptPasswordHasher',
]

# === 用户认证后端配置 ===
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',  # 默认数据库用户模型认证方式
]


# --- 中间件配置 ---
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware', # 安全中间件
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware', # 处理跨域请求
    'openai_chat.middlewares.request_id.RequestIdMiddleware', # 规范化 request(host, slash等)
    'corsheaders.middleware.CorsMiddleware', # 跨域配置中间件-cors处理
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# === URL 与 WSGI ===
ROOT_URLCONF = 'openai_chat.urls' # 根URL配置
WSGI_APPLICATION = 'openai_chat.wsgi.application'

# === 模板配置 ===
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.csrf',
            ],
        },
    },
]

# === 跨域配置(开发阶段允许所有) ===
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True # 允许携带cookie

# === Mysql数据库配置 ===
DATABASES = {
    'default': get_mysql_config('default'), # 默认单台mysql实例(预留分布式部署模式)
}

# === Redis缓存配置 ===
REDIS_HOST = get_config('REDIS_HOST', default='127.0.0.1') # Redis主机地址
REDIS_PORT = get_config('REDIS_PORT', default='6379') # Redis主机端口号
REDIS_PASSWORD = SecretConfig.REDIS_PASSWORD # Redis连接密码

# === Redlock 分布式锁节点配置 ===
_redlock_servers_json = get_config(
    "REDLOCK_SERVERS_JSON",
    default="",
)

_redlock_servers_json = str(_redlock_servers_json).strip()
if _redlock_servers_json:
    # 如果显式配置 redlock 节点列表
    REDLOCK_SERVERS = json.loads(_redlock_servers_json)
    if not isinstance(REDLOCK_SERVERS, list) or not REDLOCK_SERVERS:
        raise ValueError("REDLOCK_SERVERS_JSON 必须解析为非空 list")
else:
    # 如果未配置,则默认使用当前单节点 Redis
    REDLOCK_SERVERS = [
        {
            "host": REDIS_HOST,
            "PORT": int(REDIS_PORT),
            "db": 0, # 锁专用DB
            "password": REDIS_PASSWORD,
        }
    ]

# === Redis DB 编号映射 ===
# REDIS_DB_LOCK = 0 # RedLock锁(Redis锁)占用库/已默认配置
REDIS_DB_CELERY_BROKER = 1 # Celery任务传递系统占用库
REDIS_DB_CELERY_RESULT = 2 # Celery任务执行结果存储占用库
REDIS_DB_JWT_CACHE = 3 # JWT模块签名结果缓存占用库
REDIS_DB_JWT_BLACKLIST = 4 # JWT黑名单模块存储占用库
REDIS_DB_TOTP_QR_CACHE = 5 # TOTP二维码及secret缓存占用库
REDIS_DB_USERS_REGISTER_CACHE = 6 # 用户模块预注册缓存信息占用库
REDIS_DB_USERS_INFO_CACHE = 7 # 用户信息缓存占用库
REDIS_DB_USERS_STATE = 8 # 用户状态事实源占用库
REDIS_DB_USERS_LOGIN_PENDING = 9 # 用户登录预登录缓存占用库
REDIS_DB_IDEMPOTENCY = 10 # 接口幂等性占用库
REDIS_DB_MAIL = 11 # 邮件通道: done/lock/cooldown/rate等
REDIS_DB_DJANGO_CACHE = 14 # DJANGO 框架缓存占用库
REDIS_DB_SNOWFLAKE = 15 # 雪花ID节点信息存储占用库

# Redis URL 基础前缀
REDIS_BASE_URL = (
    f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}"
    if REDIS_PASSWORD else
    f"redis://{REDIS_HOST}:{REDIS_PORT}"
)

CACHES = { # Django缓存配置
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache', # 使用django-redis作为缓存后端
        'LOCATION': f"{REDIS_BASE_URL}/{REDIS_DB_DJANGO_CACHE}", # Redis连接地址(Django CACHE使用db-14库)
        'OPTIONS': { # 连接池配置
            'CLIENT_CLASS': 'django_redis.client.DefaultClient', # 使用默认客户端
            'decode_responses': True, # 自动字符串解码
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50, # 最大连接数
                'timeout': 5, # 连接超时时间
            }
        }
    }
}


# === Celery 任务队列模块配置 ===
# - Celey 核心配置
CELERY_BROKER_URL = f"{REDIS_BASE_URL}/{REDIS_DB_CELERY_BROKER}" # Celery 中间人(任务传递系统)/使用db-1库
CELERY_RESULT_BACKEND = f"{REDIS_BASE_URL}/{REDIS_DB_CELERY_RESULT}" # Celery 任务结果存储 使用db-2库

# - 安全和兼容性建议配置
CELERY_ACCEPT_CONTENT = ['json'] # 仅允许接收 JSON 格式
CELERY_TASK_SERIALIZER = 'json' # 任务序列化方式
CELERY_RESULT_SERIALIZER = 'json' # 结果序列化方式

# - 时区设置(与 Django 保持一致)
CELERY_TIMEZONE = 'Asia/Shanghai'
CELERY_ENABLE_UTC = True # UTC 时间兼容

# 远端 Redis + 代理链路稳定性
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_BROKER_CONNECTION_MAX_RETRIES = None # dev/test 连接无限重试
CELERY_BROKER_CONNECTION_TIMEOUT = 10 # 连接超时时间(秒)

# 心跳(降低代理/ NAT idle timeout 导致的断联概率)
CELERY_BROKER_HEARTBEAT = 10 # 秒

# 降低断线后 "恢复未 ACK 消息" 的混乱度
CELERY_WORKER_PREFETCH_MULTIPLIER = 1

# 显式保持 Celery 5.X 默认行为, 避免升级默认值变化引发错误
CELERY_WORKER_CANCEL_LONG_RUNNING_TASKS_ON_CONNECTION_LOSS = False

# --- 任务结果策略 ---
# - 任务结果过期时间(单位:秒), 防止 Redis 堆满内存
CELERY_TASK_IGNORE_RESULT = False
CELERY_TASK_RESULT_EXPIRES = 3600 # 1小时


# === MongoDB配置 ===
# MONGO_DB_NAME = get_config('MONGO_DB_NAME', default='openai_chat_db')
# MONGO_USER = get_config('MONGO_USER', default='root') # MongoDB用户名
# MONGO_HOST = get_config('MONGO_HOST', default='localhost') # MongoDB主机地址
# MONGO_PORT = get_config('MONGO_PORT', default='27017') # MongoDB主机端口号
# MONGO_PASSWORD = SecretConfig.MONGO_PASSWORD # MongoDB密码

# MONGO_CONFIG = { # retryWrites=false 单机部署关闭写操作自动重试
#     'URI': f'mongodb://{MONGO_USER}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB_NAME}?authSource={MONGO_DB_NAME}&retryWrites=false', # MongoDB连接地址
# }

# mongo_client = MongoClient(
#     MONGO_CONFIG['URI'],
#     maxPoolSize=20, # 最大连接数
#     minPoolSize=5, # 最小连接数
#     serverSelectionTimeoutMS=2000, # 服务器选择超时时间
# )
# mongo_db = mongo_client.get_database(MONGO_DB_NAME) # type: ignore # 获取MongoDB数据库实例

# === Cloudflare Turnstile 人机验证模块配置 ===
TURNSTILE_ADMIN_SECRET_KEY = SecretConfig.TURNSTILE_ADMIN_SECRET_KEY # admin管理模块后端密钥
TURNSTILE_USERS_SECRET_KEY = SecretConfig.TURNSTILE_USERS_SECRET_KEY # 用户登录/注册模块后端密钥

# === 密码强度验证器配置 ===
AUTH_PASSWORD_VALIDATORS = [
    {
        # 1.防止密码与用户信息过于相似(如用户名/邮箱)
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
        'OPTIONS': {
            'user_attributes': ('email', 'phone_number') # 自定义字段
        }  
    },
    {
        # 2.最小长度限制
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 8}, # 密码长度不得少于8位
    },
    {
        # 3.屏蔽常见弱密码
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        # 4.禁止纯数字密码
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',  
    },
]

# === 邮件发送服务(Resend) ===
RESEND_EMAIL = {
    "API_KEY": SecretConfig.RESEND_API_KEY, # RESEND服务API key
    "API_URL": "https://api.resend.com/emails", # Resend服务 Email API地址
    "FROM_NAME": "OpenAI_Chat",
    "FROM_EMAIL": "support@openai-chat.xyz", # 在 Resend 验证的发信域名
    "TIMEOUT": 10, # 请求超时时间(秒)
    "RETRY": 2, # 失败重试次数(扩展)
}

# === 静态与媒体资源路径 ===
STATIC_URL = '/static/' # 静态文件URL前缀
STATIC_ROOT = BASE_DIR / 'static' # 静态文件存放目录
MEDIA_URL = '/media/' # 媒体文件URL前缀
MEDIA_ROOT = BASE_DIR / 'media' # 媒体文件存放目录

# === 本地化与国际化配置 ===
LANGUAGE_CODE = 'zh-hans' # 语言设置
TIME_ZONE = 'Asia/Shanghai' # 时区设置
USE_I18N = True # 启用Django国际化支持
USE_TZ = True # 使用Django时区支持

# 机器唯一ID
MACHINE_UNIQUE_ID = get_config("MACHINE_UNIQUE_ID", default=None) # 机器唯一标识,用于分布式ID生成

# === 日志处理器配置 ===

LOGGING_CONF = {
    # 日志目录
    "LOG_DIR": Path(BASE_DIR / "logs").resolve(),
    
    # base.py 安全默认
    "ENABLE_CONSOLE": False, # 默认不启用控制台输出
    "PREFER_JSON": True, # 默认启用JSON格式日志
    
    # 文件滚动策略
    "MAX_BYTES": 10 * 1024 * 1024, # 单个日志文件最大10MB
    "BACKUP_COUNT": 5, # 保留最近5个滚动日志文件
    
    # root 默认级别
    "ROOT_LEVEL": "INFO",
    
    # 各模块默认级别
    "LEVELS": {
        # Django 框架层
        "django": "INFO",
        "django.request": "ERROR",
        "django.security": "WARNING",
        "system": "INFO", # 系统启动 / 初始化
        "users": "DEBUG", # 用户业务域
        # 项目内部基础设施
        "project": "INFO", 
        "project.redlock": "DEBUG",
        "project.lock": "DEBUG",
        "project.snowflake": "INFO",
        "project.jwt": "INFO",
        "project.jwt.singer": "DEBUG",
        # Redis 客户端与登录态控制
        "project.redis": "INFO",
        "project.redis.allow": "INFO",
        # celery异步任务队列
        "celery": "INFO",
        # 外部服务调用
        "clients": "WARNING",
        "clients.resend": "INFO", # 邮件发送接口
    },
    # 关键: logger -> 文件名映射(未映射则使用 root 配置)
    "FILES": {
        "system": "system.log", # 系统启动/护栏/初始化(apps ready 启动检查等)
        "users": "users.log",  # 用户模块(注册/登录/JWT/风控/验证码)
        "project": "project.log", # redis / locks / jwt / snowflake等
        "celery": "celery.log", # Celery 异步任务队列
        "clients": "clients.log", # 外部服务调用 / API / SDK等
        "django": "django.log", # Django 框架日志
    },
}

# 构建 LOGGING dict
LOGGING = build_logging(LOGGING_CONF)