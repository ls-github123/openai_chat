from django.apps import AppConfig
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("system.apps")

class SystemConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'system'
    
    def ready(self):
        """
        仅做信号注册 / 轻量 hook
        """
        logger.info("[System] apps ready (no guard started)")