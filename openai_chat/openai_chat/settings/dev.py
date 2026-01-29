from .base import *
from openai_chat.settings.utils.logging import build_logging

DEBUG = True
ENVIRONMENT = "dev" # 当前运行环境类型
ALLOWED_HOSTS = ["*"] # 允许的主机列表，*表示允许所有主机访问

LOGGING_CONF = dict(LOGGING_CONF)
LOGGING_CONF.update({
    "ENABLE_CONSOLE": True,
    "PREFER_JSON": False,
    "ROOT_LEVEL": "DEBUG",
})

LOGGING = build_logging(LOGGING_CONF)