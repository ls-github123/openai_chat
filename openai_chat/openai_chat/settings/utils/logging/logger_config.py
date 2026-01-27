"""
日志模块封装：构建多级别日志系统，支持控制台输出、文件输出、多模块分级管理
支持：并发安全、滚动日志、多数据库/业务/锁模块分离、自定义格式器、开发/生产环境切换
"""
import os, logging
from openai_chat.settings.utils.path_utils import BASE_DIR
from concurrent_log_handler import ConcurrentRotatingFileHandler # 并发日志处理模块-多进程安全写入日志

# 日志目录路径
LOG_DIR = (BASE_DIR / 'logs').resolve() # 确保路径为绝对路径
LOG_DIR.mkdir(parents=True, exist_ok=True) # 创建日志目录(如果不存在)

# === 环境判定与格式器策略 ===
DJANGO_SETTINGS_MODULE = os.getenv('DJANGO_SETTINGS_MODULE', 'openai_chat.settings.dev') # 获取当前环境变量
IS_DEV = "dev" in DJANGO_SETTINGS_MODULE.lower() # 判断是否为开发环境
# 开发环境使用详细化格式器, 生产环境使用 JSON 格式器
FORMATTER_STYLE = 'verbose' if IS_DEV else 'json'
ENABLE_CONSOLE_LOGGING = IS_DEV # 开发环境下启用控制台日志

def build_logging():
    """
    返回符合 Django Logging 配置规范的字典结构
    (日志处理器-handlers、日志格式化器-formatters、日志生成器-loggers)
    - 日志配置说明:
    - 控制台输出(仅开发环境)
    - 文件输出(general/info/error/critical/django)
    - 各类日志按级别分类持久化
    - 日志分级(从低到高依次向下):
    - -(DEBUG-故障排查低级别系统信息)
    - -(INFO-一般系统信息)
    - -(WARNING-系统小问题信息)
    - -(ERROR-系统较大错误问题信息)
    - -(CRITICAL-系统致命错误问题信息)
    """
    # 检查缓存是否存在
    if hasattr(build_logging, "_cache"):
        return build_logging._cache # type: ignore

    # 文件日志处理器生成函数
    def file_handler(name, level):
        return {
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler', # 支持自动轮转的文件日志处理器
            'filename': os.path.join(LOG_DIR, f'{name}.log'), # 输出文件路径
            'maxBytes': 5 * 1024 * 1024, # 单个日志文件最大容量
            'backupCount': 3, # 最多保留3个轮转文件
            'formatter': FORMATTER_STYLE, # 格式化器选择
            'level': level, # 日志级别
            'encoding': 'utf-8', # 文件编码
        }
    
    # === 日志处理器 ===
    # 将日志输出到指定位置
    handlers = {
        'file_project': file_handler('project', 'DEBUG'), # 项目通用日志
        'file_project_config': file_handler('project_config', 'INFO'), # 项目配置 日志
        'file_azure_key_vault': file_handler('azure_key_vault', 'WARNING'), # Azure Key Vault 日志
        'file_db_mysql': file_handler('db_mysql', 'INFO'), # Mysql数据库 日志
        'file_db_redis': file_handler('db_redis', 'INFO'), # Redis缓存数据库 日志
        'file_db_mongo': file_handler('db_mongo', 'INFO'), # MongoDB数据库 日志
        'file_lock': file_handler('lock', 'DEBUG'), # Redis锁 日志
        'file_django': file_handler('django', 'INFO'), # Django框架本体 日志
        'file_snowflake': file_handler('snowflake', 'DEBUG'), # snowflake分布式ID生成 日志
        'file_api': file_handler('api', 'WARNING'), # API模块 日志
        'file_users': file_handler('users', 'DEBUG'), # 用户模块 日志
        'file_chat': file_handler('chat', 'WARNING'), # chat聊天模块 日志
        'file_celery': file_handler('celery', "INFO"), # Celery 任务队列 日志
        'file_email': file_handler('email', 'INFO'), # Resend 邮件发送服务API模块 日志
	}
    
    # 控制台输出处理器(仅开发环境启用)
    if ENABLE_CONSOLE_LOGGING:
        print("[Logger]开启开发环境控制台日志输出")
        handlers['console'] = {
            # StreamHandler-python标准日志库内置处理器,用于开发调试阶段
            'class': 'logging.StreamHandler',
            'formatter': 'simple', # 输出简单格式
            'level': 'DEBUG',
		}
    # fallback logger 收集所有输出器
    logger_handlers = list(handlers.keys())
    
    # === 日志返回结构体配置 ===
    config = {
        'version': 1,
        'disable_existing_loggers': False,  # 保留已有模块日志
        
        # === 日志格式化器 ===
        # verbose 文本格式、simple 简单文本格式、json JSON格式
        'formatters': {
            'verbose': { # 详细格式: 时间、级别、模块名、日志内容
                'format': '[{asctime}] [{levelname}] [{name}] {message}',
                'style': '{', # 格式化标记
            },
            'simple': { # 简单格式: 只显示日志等级和内容,主要用于控制台输出
                'format': '{levelname}: {message}',
                'style': '{',
            },
            'json': { # JSON格式: 适用于生产环境,便于日志分析
                # 使用 jsonlogger 库格式化日志为 JSON
                '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
                'format': '%(asctime)s %(levelname)s %(name)s %(process)d %(threadName)s %(message)s',
                'rename_fields': { # 重命名字段以符合 JSON 格式
                    'levelname': 'level',
                    'asctime': 'timestamp',
                    'name': 'logger',
                },
            },
        },
        # 日志处理器集合(输出位置 -> 格式化器选择)
        'handlers': handlers,
        
        # 各模块日志记录器配置(按模块分配日志处理器)
        'loggers': {
            'django': { # # Django框架日志
                # 控制台和错误日志处理器
                'handlers': ['file_django'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
                'level': 'INFO', # 级别过滤(低于该级别的日志将被排除)
                'propagate': True, # 是否向父 logger 传播日志
            },
            'system.apps': {
                'handlers': ['file_django'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
                'level': 'INFO',
                'propagate': False,
            },
            'system.init': {
                'handlers': ['file_django'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
                'level': 'INFO',
                'propagate': False,
            },
            'openai_chat': { # 主业务日志
                'handlers': logger_handlers,
                'level': 'DEBUG',
                'propagate': False,
            },
           'openai_chat.settings.config': { # 配置模块日志
                'handlers': ['file_project_config'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
                'level': 'INFO',
                'propagate': False,
            },
           'openai_chat.users': { # 用户模块日志(注册、登录等操作)
               'handlers': ['file_users'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'DEBUG',
               'propagate': False,
		   },
           'jwt': { # JWT 模块日志(签名/验证等)
               'handlers': ['file_users'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'DEBUG',
               'propagate': False,
           },
           'openai_chat.settings.azure_key_vault_client': { # Azure key vault 模块日志
               'handlers': ['file_azure_key_vault'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'WARNING',
               'propagate': False,
		   },
           'openai_chat.chat': { # chat聊天模块日志
               'handlers': ['file_chat'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'WARNING',
               'propagate': False,
           },
           'openai.api': { # OPENAI-API模块日志
               'handlers': ['file_api'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'DEBUG',
               'propagate': False,
           },
           'project.api': { # 项目API模块日志
               'handlers': ['file_api'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'DEBUG',
               'propagate': False,
            },
           'project.redis': { # Djano-Redis缓存后端 日志
               'handlers': ['file_db_redis'],
               'level': 'WARNING',
               'propagate': False,
            },
           'project.redlock': { # Redlock分布式锁 日志
               'handlers': ['file_lock'],
               'level': 'DEBUG',
               'propagate': False,
            },
           'project.lock_factory': { # 锁工厂函数接口模块 日志
               'handlers': ['file_lock'],
               'level': 'DEBUG',
               'propagate': False,
            },
           'project.redis_lock': { # Redis单节点锁 日志
               'handlers': ['file_lock'],
               'level': 'DEBUG',
               'propagate': False,
            },
           'idempotency': { # 接口幂等性模块 日志
               'handlers': ['file_lock'],
               'level': 'DEBUG',
               'propagate': False,
            },
           'project.redis_config': { # Redis客户端、连接池、连接状态 日志
               'handlers': ['file_db_redis'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'INFO',
               'propagate': False,
            },
           'project.snowflake.register': { # Snowflake分布式节点ID注册 日志
               'handlers': ['file_snowflake'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'DEBUG',
               'propagate': False,
            },
           'project.snowflake.guard': { # Snowflake分布式节点续约 日志
               'handlers': ['file_snowflake'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'DEBUG',
               'propagate': False,
            },
           'project.mongo': { # MongoDB数据模块日志
               'handlers': ['file_db_mongo'],
               'level': 'INFO',
               'propagate': False,
            },
           'pymongo': { # MongoDB ORM 日志
               'handlers': ['file_db_mongo'],
               'level': 'INFO',
               'propagate': False,
            },
           'mysql_client': { # Mysql数据库业务日志(连接失败、事务异常等)
               'handlers': ['file_db_mysql'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'INFO',
               'propagate': False,
            },
           'mysql_orm': { # Mysql ORM 日志
                'handlers': ['file_db_mysql'],
                'level': 'INFO',
                'propagate': False,
            },
           'users': { # 用户模块日志(注册、登录等操作)
               'handlers': ['file_users'],
               'level': 'DEBUG',
               'propagate': False,
            },
           'users.totp': { # 用户模块-TOTP验证 日志
               'handlers': ['file_users'],
               'level': 'DEBUG',
               'propagate': False,
            },
        #   'tasks': {
        #       'handlers': []
        #   },
           'email_resend_client': { # Resend 邮件服务API封装 日志
               'handlers': ['file_email'],
               'level': 'INFO',
               'propagate': False,
            },
           'celery': {
               # celery 主日志
               'handlers': ['file_celery'],
               'level': 'INFO',
               'propagate': False,
            },
           'celery.worker': {
               # celery worker模块日志
               'handlers': ['file_celery'],
               'level': 'INFO',
               'propagate': False,
            },
           'celery.tasks': {
               # celery task模块日志
               'handlers': ['file_celery'],
               'level': 'INFO',
               'propagate': False,
            },
           'task_email': { # Celery 任务队列异步发送邮件 日志
               'handlers': ['file_email'],
               'level': 'INFO',
               'propagate': False,
            },
           '': { # fallback 根 logger(通用日志)
                'handlers': ['file_project'],
                'level': 'INFO',
                'propagate': False,
           },
        },
    }
    # 缓存写入(避免重复初始化)
    build_logging._cache = config  # type: ignore
    return config

# === 通用日志获取函数 ===
def get_logger(name: str) -> logging.Logger:
    """
    获取指定名称的日志记录器(loggers)
    示例: mysql_logger = get_logger("project.mysql")
    注:若未注册则使用 fallback 配置
    """
    logger = logging.getLogger(name) # 获取指定名称的日志记录器
    if not logger.handlers: # 如果没有处理器,则使用默认处理器
        logger.handlers = logging.getLogger('').handlers
    return logger