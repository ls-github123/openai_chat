#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

def main() -> None:
    """
    运行入口(生产级规则)
    - 1.外部环境变量(部署/CI)优先,永不覆盖
    - 2.若外部未设置, 则从.env读取
    - 3.若仍无配置值, 兜底使用 base
    """
    # 1. 如果外部已经设置（PowerShell / Docker / systemd），绝不覆盖
    if "DJANGO_SETTINGS_MODULE" not in os.environ or not os.environ["DJANGO_SETTINGS_MODULE"]:
        # 2.延迟导入: 避免入口阶段 import 项目包产生错误
        from openai_chat.settings.config import get_config
        
        settings_module = get_config(
            "DJANGO_SETTINGS_MODULE",
            default="openai_chat.settings.base",
        )
        os.environ["DJANGO_SETTINGS_MODULE"] = settings_module
        
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    
    execute_from_command_line(sys.argv)
    
if __name__ == "__main__":
    main()