#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

def main() -> None:
    """
    运行入口(生产级规则)
    - 1.外部环境变量(PowerShell / Docker / systemd)优先,永不覆盖
    - 2.若外部未设置, 则从.env / config读取
    - 3.若仍无配置值, 兜底使用 base
    """
    if not os.environ.get("DJANGO_SETTINGS_MODULE"):
        # 延迟导入, 避免 Django / Celery 提前初始化
        from openai_chat.settings.config import get_config
        
        settings_module = get_config(
            "DJANGO_SETTINGS_MODULE",
            default="openai_chat.settings.base",
        )
        
        # 必须为 str
        if not isinstance(settings_module, str) or not settings_module.strip():
            raise RuntimeError(
                f"DJANGO_SETTINGS_MODULE must be str, got {type(settings_module)}"
            )
        
        os.environ["DJANGO_SETTINGS_MODULE"] = settings_module.strip()
        
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)            

if __name__ == "__main__":
    main()