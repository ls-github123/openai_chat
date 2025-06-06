# 从同级目录中的 celery.py 文件中导入 Celery 实例 app
# 命名为 celery_app,供其他模块或工具调用
from .celery import app as celery_app

__all__ = ("celery_app",)