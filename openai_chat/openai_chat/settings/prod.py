from .base import *

DEBUG = False # 生产环境关闭DEBUG模式
ENVIRONMENT = "prod" # 当前运行环境类型
ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv())