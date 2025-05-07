# base.py
"""
项目核心配置文件(数据库、缓存、安全、Vault集成等)
"""
from pathlib import Path
from decouple import config, Csv
from openai_chat.azure_key_vault_client import AzureKeyVaultClient # 自定义的Azure Key Vault 客户端
from pymongo import MongoClient # MongoDB客户端

# 基础目录
BASE_DIR = Path(__file__).resolve().parent.parent.parent # 项目根路径

# Azure key vault配置
VAULT_URL = config('VAULT_URL') # Azure Key Vault URL
vault = AzureKeyVaultClient(VAULT_URL) # 实例化Azure Key Vault客户端

# 安全配置
SECRET_KEY = vault.get_secret(config("DJANGO-SECRET-KEY-NAME"))
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
    # 'users' # 用户管理模块
]

# --- 中间件配置 ---
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware', # 跨域配置中间件-cors处理
    'django.middleware.security.SecurityMiddleware', # 安全中间件
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware', # 处理跨域请求
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'openai_chat.urls' # 根URL配置

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

WSGI_APPLICATION = 'openai_chat.wsgi.application'

# 跨域配置
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True # 允许携带cookie

# Mysql数据库配置
DATABASES = {
    'default': {
        "ENGINE": 'django.db.backends.mysql', # 数据库引擎
        "NAME": config('DB_NAME', default='openai_chat_db'), # 数据库名称
        "USER": config('DB_USER', default='root'), # 数据库用户名
        "PASSWORD": vault.get_secret(config('DB_PASSWORD_NAME')), # 数据库密码
        "HOST": config('DB_HOST', default='localhost'), # 数据库主机地址
        "PORT": config('DB_PORT', default='3306'), # 数据库连接端口号
        "OPTIONS": {
            'init_command':"SET sql_mode='STRICT_TRANS_TABLES'", # 初始化命令,设置SQL模式
            'charset': 'utf8mb4', # 字符集设置
            'connect_timeout': 10, # 连接超时时间
            'read_timeout': 20, # 读取超时时间
            'write_timeout': 20, # 写入超时时间
            'ssl': {'ssl-mode': 'DISABLED'},  # 禁用 SSL 验证
        },
    }
}

# Redis缓存配置
REDIS_HOST = config('REDIS_HOST', default='localhost') # Redis主机地址
REDIS_PORT = config('REDIS_PORT', default='6379') # Redis主机端口号
REDIS_PASSWORD = vault.get_secret(config('REDIS_PASSWORD_NAME')) # Redis密码

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache', # 使用django-redis作为缓存后端
        'LOCATION': f'redis://{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/1', # Redis连接地址
        'OPTIONS': { # 连接池配置
            'CLIENT_CLASS': 'django_redis.client.DefaultClient', # 使用默认客户端
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50, # 最大连接数
                'timeout': 5, # 连接超时时间
            }
        }
    }
}

# MongoDB配置
MONGO_DB_NAME = config('MONGO_DB_NAME')
MONGO_USER = config('MONGO_USER', default='root') # MongoDB用户名
MONGO_HOST = config('MONGO_HOST', default='localhost') # MongoDB主机地址
MONGO_PORT = config('MONGO_PORT', default='27017') # MongoDB主机端口号
MONGO_PASSWORD = vault.get_secret(config('MONGO_PASSWORD_NAME')) # MongoDB密码

MONGO_CONFIG = {
    'URI': f'mongodb://{MONGO_USER}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB_NAME}?authSource={MONGO_DB_NAME}', # MongoDB连接地址
}

mongo_client = MongoClient(
    MONGO_CONFIG['URI'],
    maxPoolSize=20, # 最大连接数
    minPoolSize=5, # 最小连接数
    serverSelectionTimeoutMS=2000, # 服务器选择超时时间
)

mongo_db = mongo_client.get_database(MONGO_DB_NAME) # 获取MongoDB数据库实例

# 密码强度验证器配置
AUTH_PASSWORD_VALIDATORS = [] # 使用Authentik服务进行校验,不在此处配置

# 静态与媒体资源
STATIC_URL = '/static/' # 静态文件URL前缀
STATIC_ROOT = BASE_DIR / 'static' # 静态文件存放目录
MEDIA_URL = '/media/' # 媒体文件URL前缀
MEDIA_ROOT = BASE_DIR / 'media' # 媒体文件存放目录

# 本地化
LANGUAGE_CODE = 'zh-hans' # 语言设置
TIME_ZONE = 'Asia/shanghai' # 时区设置
USE_I18N = True # 启用Django国际化支持
USE_TZ = True # 使用Django时区支持