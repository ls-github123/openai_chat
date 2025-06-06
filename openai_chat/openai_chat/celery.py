import os
from celery import Celery # 导入celery模块

# 设置Django默认配置模块
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "openai_chat.settings.dev")

# 创建celery应用实例
app = Celery("openai_chat")

# 加载 Django 配置中的 CELERY 配置项, 以CELERY_为前缀
app.config_from_object("django.conf:settings", namespace="CELERY")

# 自动发现 tasks 中定义的任务
app.autodiscover_tasks()