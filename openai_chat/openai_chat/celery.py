import os
from celery import Celery # 导入celery模块

def _ensure_django_settings_module() -> None:
    """
    确保 DJANGO_SETTINGS_MODULE 存在：
    - 1) 外部环境变量优先（永不覆盖）
    - 2) 否则从 .env 读取（python-decouple）
    - 3) 最后兜底 base
    """
    if os.environ.get("DJANGO_SETTINGS_MODULE"):
        return
    
    # 尝试从.env 读取
    try:
        from decouple import config # 延迟导入, 避免非必须依赖
        val = config(
            "DJANGO_SETTINGS_MODULE",
            default="openai_chat.settings.base",
            cast=str,
        )
        if isinstance(val, str) and val.strip():
            os.environ["DJANGO_SETTINGS_MODULE"] = val.strip()
            return
    except ImportError:
        # 未安装 decouple -> 兜底
        pass
    except Exception:
        # .env 解析异常等 -> 兜底
        pass
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "openai_chat.settings.base")
    
_ensure_django_settings_module()

# 创建celery应用实例
app = Celery("openai_chat")

# 加载 Django 配置中的 CELERY 配置项, 以 CELERY_ 为前缀
app.config_from_object("django.conf:settings", namespace="CELERY")

# 自动发现 tasks 中定义的任务
app.autodiscover_tasks()