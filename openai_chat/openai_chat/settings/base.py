# base.py
"""
项目核心配置文件
- 管理数据库连接(Mysql、MongoDB)
- 配置缓存服务(Redis)
- 配置安全设置和中间件
- 日志配置统一
"""
import os
from openai_chat.settings.utils import path_utils # 导入路径工具模块
from .config import get_config, SecretConfig, VaultClient # 从config.py导入配置项
from pymongo import MongoClient # MongoDB客户端
from openai_chat.settings.utils.mysql_config import get_mysql_config # 导入Mysql数据库连接池
from . import LOGGING # 导入日志配置

# 基础目录
BASE_DIR = path_utils.BASE_DIR # 项目根路径

# 安全配置
SECRET_KEY = SecretConfig.DJANGO_SECRET_KEY # Django密钥
# DEBUG = config("DEBUG", cast=bool, default=True)
# ENVIRONMENT = config("ENVIRONMENT", default="dev") # 当前运行环境类型
# 允许的主机列表 Csv()用于将逗号分隔的字符串转换为列表
# ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv(), default="*")

# --- 应用注册 ---
INSTALLED_APPS = [
    'corsheaders', # 跨域支持组件
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles', # 静态文件处理
    'users', # 用户管理模块
    'interface_test', # 接口测试模块
    'system.apps.SystemConfig', # 系统初始化模块
]

# --- 中间件配置 ---
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware', # 安全中间件
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware', # 处理跨域请求
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

# Redis URL 基础前缀
REDIS_BASE_URL = (
    f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}"
    if REDIS_PASSWORD else
    f"redis://{REDIS_HOST}:{REDIS_PORT}"
)

CACHES = { # Django缓存配置
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache', # 使用django-redis作为缓存后端
        'LOCATION': f"{REDIS_BASE_URL}/4", # Redis连接地址(Django CACHE使用db-4库)
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
CELERY_BROKER_URL = f"{REDIS_BASE_URL}/1" # Celery 中间人(任务传递系统)/使用db-1库
CELERY_RESULT_BACKEND = f"{REDIS_BASE_URL}/2" # Celery 任务结果存储 使用db-2库

# - 安全和兼容性建议配置
CELERY_ACCEPT_CONTENT = ['json'] # 仅允许接收 JSON 格式
CELERY_TASK_SERIALIZER = 'json' # 任务序列化方式
CELERY_RESULT_SERIALIZER = 'json' # 结果序列化方式

# - 时区设置(与 Django 保持一致)
CELERY_TIMEZONE = 'Asia/shanghai'
CELERY_ENABLE_UTC = False

# - 任务结果过期时间(单位:秒), 防止 Redis 堆满内存
CELERY_TASK_RESULT_EXPIRES = 3600 # 1小时


# === MongoDB配置 ===
MONGO_DB_NAME = get_config('MONGO_DB_NAME', default='openai_chat_db')
MONGO_USER = get_config('MONGO_USER', default='root') # MongoDB用户名
MONGO_HOST = get_config('MONGO_HOST', default='localhost') # MongoDB主机地址
MONGO_PORT = get_config('MONGO_PORT', default='27017') # MongoDB主机端口号
MONGO_PASSWORD = SecretConfig.MONGO_PASSWORD # MongoDB密码

MONGO_CONFIG = { # retryWrites=false 单机部署关闭写操作自动重试
    'URI': f'mongodb://{MONGO_USER}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB_NAME}?authSource={MONGO_DB_NAME}&retryWrites=false', # MongoDB连接地址
}

mongo_client = MongoClient(
    MONGO_CONFIG['URI'],
    maxPoolSize=20, # 最大连接数
    minPoolSize=5, # 最小连接数
    serverSelectionTimeoutMS=2000, # 服务器选择超时时间
)
mongo_db = mongo_client.get_database(MONGO_DB_NAME) # type: ignore # 获取MongoDB数据库实例

# === Cloudflare Turnstile 人机验证模块配置 ===
TURNSTILE_ADMIN_SECRET_KEY = SecretConfig.TURNSTILE_ADMIN_SECRET_KEY # admin管理模块后端密钥
TURNSTILE_USERS_SECRET_KEY = SecretConfig.TURNSTILE_USERS_SECRET_KEY # 用户登录/注册模块后端密钥

# === 密码强度验证器配置 ===
AUTH_PASSWORD_VALIDATORS = [
    {
        # 密码最小长度限制
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 8},
    },
    {
        # 常见弱密码库
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
]

# === 自定义认证后端配置 ===
AUTHENTICATION_BACKENDS = [
    
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
TIME_ZONE = 'Asia/shanghai' # 时区设置
USE_I18N = True # 启用Django国际化支持
USE_TZ = True # 使用Django时区支持

# 机器唯一ID
MACHINE_UNIQUE_ID = get_config("MACHINE_UNIQUE_ID", default=None) # 机器唯一标识,用于分布式ID生成