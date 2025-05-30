# 日志模块封装
# 封装为 get_logging() 方法供 base.py 调用
import os, logging
from openai_chat.settings.utils.path_utils import BASE_DIR
from concurrent_log_handler import ConcurrentRotatingFileHandler # 并发日志处理模块-多进程安全写入日志

# 日志目录路径
LOG_DIR = BASE_DIR / 'logs'
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
    # === 日志处理器 ===
    # 将日志输出到指定位置
    handlers = {
        'file_debug': { # DEBUG 级别日志:记录调试细节
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler', # 支持自动轮转的文件日志处理器
            'filename': os.path.join(LOG_DIR, 'debug.log'), # 输出文件路径
            'maxBytes': 5 * 1024 * 1024, # 单个日志文件最大为5MB
            'backupCount': 3, # 最多保留3个轮转文件 
            'formatter': FORMATTER_STYLE, # 格式化器选择
            'level': 'DEBUG',
            'encoding': 'utf-8',
		},
        'file_info': { # INFO 级别日志:记录正常流程信息(用户登录、接口访问成功等)
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler', 
            'filename': os.path.join(LOG_DIR, 'info.log'), 
            'maxBytes': 5 * 1024 *1024,
            'backupCount': 3, 
            'formatter': FORMATTER_STYLE,
            'level': 'INFO',
            'encoding': 'utf-8',
		},
        'file_warning': { # WARNING 级别日志:记录可恢复问题、潜在风险(如参数不合法、网络重试)
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler', 
            'filename': os.path.join(LOG_DIR, 'warning.log'), 
            'maxBytes': 5 * 1024 *1024, 
            'backupCount': 3, 
            'formatter': FORMATTER_STYLE,
            'level': 'WARNING',
            'encoding': 'utf-8',
		},
        'file_error': { # ERROR 级别日志:记录错误异常(如数据库连接失败、调用异常)
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'errors.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': FORMATTER_STYLE,
            'level': 'ERROR',
            'encoding': 'utf-8',
		},
        'file_critical': { # CRITICAL 级别日志: 记录系统致命错误(如主线程崩溃、密钥加载失败等)
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'critical.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': FORMATTER_STYLE,
            'level': 'CRITICAL',
            'encoding': 'utf-8',
		},
        'file_db_mysql': { # Mysql数据库 日志
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'db_mysql.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': FORMATTER_STYLE,
            'level': 'DEBUG', # DEBUG 记录SQL查询, INFO 记录业务层日志
            'encoding': 'utf-8',
        },
        'file_db_redis': { # Redis缓存数据库 日志
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'db_redis.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': FORMATTER_STYLE,
            'level': 'INFO',
            'encoding': 'utf-8',
        },
        'file_db_mongo': { # MongoDB数据库 日志
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'db_mongo.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': FORMATTER_STYLE,
            'level': 'INFO',
            'encoding': 'utf-8',
        },
        'file_lock_redlock': { # Redlock分布式锁 日志
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'lock_redlock.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': FORMATTER_STYLE,
            'level': 'INFO',
            'encoding': 'utf-8',
        },
        'file_lock_redis': { # Redis单节点锁 日志
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'lock_redis.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': FORMATTER_STYLE,
            'level': 'INFO',
            'encoding': 'utf-8',
        },
        'file_lock_redis_config': { # Redis锁模块客户端配置 日志
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'lock_redis_config.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': FORMATTER_STYLE,
            'level': 'INFO',
            'encoding': 'utf-8',
        },
        'file_django': { # Django框架本体 日志
            'class': 'concurrent_log_handler.ConcurrentRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'django.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': FORMATTER_STYLE,
            'level': 'INFO',
            'encoding': 'utf-8',
		},
	}
    
    # 控制台输出处理器(仅开发环境启用)
    if ENABLE_CONSOLE_LOGGING:
        handlers['console'] = {
            # StreamHandler-python标准日志库内置处理器,用于开发调试阶段
            'class': 'logging.StreamHandler',
            'formatter': 'simple', # 输出简单格式
            'level': 'DEBUG',
		}
    # fallback logger 收集所有输出器
    logger_handlers = list(handlers.keys())
    
    # === 日志返回结构体配置 ===
    return {
        'version': 1,
        'disable_existing_loggers': False,  # 禁用现有日志记录器(避免重复配置)
        
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
                'format': '%(asctime)s %(levelname)s %(name)s %(message)s',
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
           'openai_chat': { # 主业务日志
                'handlers': logger_handlers,
                'level': 'DEBUG',
                'propagate': False,
           },
           'openai_chat.users': { # 用户模块日志(注册、登录等操作)
               'handlers': ['file_debug', 'file_info', 'file_error', 'file_critical'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'DEBUG',
               'propagate': False,
		   },
           'openai_chat.settings.azure_key_vault_client': { # Azure key vault 模块日志
               'handlers': ['file_info', 'file_error', 'file_critical'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'WARNING',
               'propagate': False,
		   },
           'openai_chat.chat': { # chat聊天模块日志
               'handlers': ['file_info', 'file_error', 'file_critical'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'INFO',
               'propagate': False,
           },
           'openai_chat.api': { # API模块日志
               'handlers': ['file_debug', 'file_warning', 'file_error'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
               'level': 'DEBUG',
               'propagate': False,
           },
           'project.redis': { # Redis缓存数据库日志
               'handlers': ['file_db_redis'],
               'level': 'INFO',
               'propagate': False,
            },
           'project.mongo': { # MongoDB数据模块日志
               'handlers': ['file_db_mongo'],
               'level': 'INFO',
               'propagate': False,
            },
           'project.mysql': { # Mysql数据库业务日志(连接失败、事务异常等)
               'handlers': ['file_db_mysql'],
               'level': 'INFO',
               'propagate': False,
            },
           'django.db.backends': { # Mysql ORM 日志
                'handlers': ['file_db_mysql'],
                'level': 'DEBUG',
                'propagate': False,
            },
           'project.redlock': { # Redlock分布式锁 日志
               'handlers': ['file_lock_redlock'],
               'level': 'INFO',
               'propagate': False,
            },
           'project.redis_lock': { # Redis单节点锁 日志
               'handlers': ['file_lock_redis'],
               'level': 'INFO',
               'propagate': False,
            },
           'project.lock.redis_config': { # Redis锁模块客户端配置 日志
               'handlers': ['file_lock_redis_config'],
               'level': 'INFO',
               'propagate': False,
            },
           '': { # fallback 根 logger(通用日志)
                'handlers': ['file_info', 'file_warning'],
                'level': 'INFO',
                'propagate': False,
           },
        },
    }
    
# === 通用日志获取函数 ===
def get_logger(name: str) -> logging.Logger:
    """
    获取指定名称的日志记录器(loggers)
    示例: mysql_logger = get_logger("project.mysql")
    """
    return logging.getLogger(name)