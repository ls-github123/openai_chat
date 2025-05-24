# 日志模块封装
# 封装为 get_logging() 方法供 base.py 调用
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler # 日志文件轮换处理器

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# 日志目录路径
LOG_DIR = os.path.join(BASE_DIR, 'logs') # 日志目录
os.makedirs(LOG_DIR, exist_ok=True) # 创建日志目录(如果不存在)

# 判断是否启用控制台日志输出
DJANGO_SETTINGS_MODULE = os.getenv('DJANGO_SETTINGS_MODULE', 'openai_chat.settings.dev') # 获取当前环境变量
ENABLE_CONSOLE_LOGGING = "dev" in DJANGO_SETTINGS_MODULE.lower() # 开发环境下启用控制台输出

def build_logging():
    """
    返回符合 Django Logging 配置规范的字典结构
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
        'file_debug': { # DEBUG 日志:记录调试细节
            'class': 'logging.handlers.RotatingFileHandler', # 支持自动轮转的文件日志处理器
            'filename': os.path.join(LOG_DIR, 'debug.log'), # 输出文件路径
            'maxBytes': 5 * 1024 * 1024, # 单个日志文件最大为5MB
            'backupCount': 3, # 最多保留3个轮转文件 
            'formatter': 'verbose', # 使用详细格式化器
            'level': 'DEBUG',
            'encoding': 'utf-8',
		},
        'file_info': { # INFO 日志:记录正常流程信息(用户登录、接口访问成功等)
            'class': 'logging.handlers.RotatingFileHandler', 
            'filename': os.path.join(LOG_DIR, 'info.log'), 
            'maxBytes': 5 * 1024 *1024, 
            'backupCount': 3, 
            'formatter': 'verbose', 
            'level': 'INFO',
            'encoding': 'utf-8',
		},
        'file_warning': { # WARNING 日志:记录可恢复问题、潜在风险(如参数不合法、网络重试)
            'class': 'logging.handlers.RotatingFileHandler', 
            'filename': os.path.join(LOG_DIR, 'warning.log'), 
            'maxBytes': 5 * 1024 *1024, 
            'backupCount': 3, 
            'formatter': 'verbose', 
            'level': 'WARNING',
            'encoding': 'utf-8',
		},
        'file_error': { # ERROR 日志:记录错误异常(如数据库连接失败、调用异常)
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'errors.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'verbose',
            'level': 'ERROR',
            'encoding': 'utf-8',
		},
        'file_critical': { # CRITICAL 日志: 记录系统致命错误(如主线程崩溃、密钥加载失败等)
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'critical.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'verbose',
            'level': 'CRITICAL',
            'encoding': 'utf-8',
		},
        'file_django': { # DJANGO框架 日志
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'django.log'),
            'maxBytes': 5 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'verbose',
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
    
    # 汇总所有 handler
    logger_handlers = list(handlers.keys())
    
    return {
        'version': 1,
        'disable_existing_loggers': False,  # 保留 Django 默认日志器
        
        # === 日志格式化器 ===
        'formatters': {
            'verbose': { # 详细格式: 时间、级别、模块名、日志内容
                'format': '[{asctime}] [{levelname}] [{name}] {message}',
                'style': '{', # 格式化标记
            },
            'simple': { # 简单格式: 只显示日志等级和内容,主要用于控制台输出
                'format': '{levelname}: {message}',
                'style': '{',
            },
        },
        
        'handlers': handlers, # 日志处理器(输出方式)
        
        # 日志生成器配置(模块 -> 处理器选择 -> 日志等级)
        'loggers': {
            'django': { # # Django框架日志
                # 控制台和错误日志处理器
                'handlers': ['file_django'] + (['console'] if ENABLE_CONSOLE_LOGGING else []),
                'level': 'INFO', # 级别过滤(低于该级别的日志将被排除)
                'propagate': True,
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
           '': { # fallback 根 logger(通用日志)
                'handlers': logger_handlers,
                'level': 'INFO',
                'propagate': False,
           },
        },
    }