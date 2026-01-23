from .base import *
from decouple import config, Csv

DEBUG = False
ENVIRONMENT = "prod"

ALLOWED_HOSTS = config(
    "ALLOWED_HOSTS",
    default="localhost, 127.0.0.1",
    cast=Csv(),
)