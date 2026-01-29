from .base import *
from decouple import config, Csv
from openai_chat.settings.utils.logging import build_logging

DEBUG = False
ENVIRONMENT = "prod"

ALLOWED_HOSTS = config(
    "ALLOWED_HOSTS",
    default="localhost, 127.0.0.1",
    cast=Csv(),
)

LOGGING_CONF = dict(LOGGING_CONF)
LOGGING_CONF.update({
    "ENABLE_CONSOLE": False,
    "PREFER_JSON": True,
    "ROOT_LEVEL": "INFO",
})
LOGGING = build_logging(LOGGING_CONF)