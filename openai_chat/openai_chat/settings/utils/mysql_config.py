"""
Mysql 数据库连接配置封装模块(支持连接池、多数据库、多主机分布式部署)
- 使用 mysqlclient 驱动
- 使用django-db-geventpool 实现连接池
- 支持多数据库配置(主写、从读、日志等), 通过 alias参数动态选择
- 敏感信息(如密码)统一通过 SecretConfig 加载, 符合安全规范
- 密码通过 Azure Key Vault 管理(通过 SecretConfig 安全加载)
- 加入日志记录器，方便调试配置加载状态
"""
from openai_chat.settings.config import get_config
from openai_chat.settings.config import SecretConfig # 导入(Azure key vault)密钥获取接口
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器

logger = get_logger("project.mysql")

def get_mysql_config(alias: str = 'default') -> dict:
    """
    多主机多库(分布式部署mysql)统一配置入口
    返回指定 alias (数据库别名) 对应的 Mysql 配置字典
    :param alias: 数据库别名, 例如 'default', 'read_replica', 'log'
    :return: Django ORM 可识别的数据库配置字典 dict
    """
    prefix_map = { # 获取指定 alias 的 Mysql 数据库配置
        'default': 'DB', # 当前默认配置1个mysql数据库主库实例
        # 根据需求可继续添加其他数据库配置别名
    }
    
    if alias not in prefix_map:
        logger.error(f"[Mysql连接池]不支持的数据库别名:{alias}")
        raise ValueError(f"[Mysql连接池]不支持的数据库别名:{alias}")
    
    prefix = prefix_map[alias]
    
    try:
        config_dict = {
            'ENGINE': 'django.db.backends.mysql',
            'NAME': get_config(f"{prefix}_NAME", default="root"),
            'USER': get_config(f"{prefix}_USER"),
            'PASSWORD': getattr(SecretConfig, f"{prefix}_PASSWORD"),
            'HOST': get_config(f"{prefix}_HOST",default="127.0.0.1"),
            'PORT': get_config(f"{prefix}_PORT", default="3306"),
            
            'OPTIONS': {
                'init_command': "SET sql_mode='STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ENGINE_SUBSTITUTION'",  # 严格模式 + 禁止无引擎 + 禁止零日期,
                'charset': 'utf8mb4',
                'connect_timeout': 10,
                'read_timeout': 20,
                'write_timeout': 20,
                'ssl': {'ssl-mode': 'DISABLED'}, # 禁用SSL加密
            },
            
            'POOL_OPTIONS': {
                'POOL_SIZE': 10, # 最大连接池数量
                'MAX_OVERFLOW': 5, # 超过连接池最大临时连接数
                'RECYCLE': 3600, # 回收空闲连接时间(秒)
            },
        }
        
        logger.info(f"[MySQL配置] 成功加载数据库连接配置: alias={alias}, host={config_dict['HOST']}, db={config_dict['NAME']}")
        return config_dict
    
    except Exception as e:
        logger.error(f"[MySQL配置] 加载数据库配置失败: alias={alias}, 错误原因: {e}")
        raise