#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from openai_chat.settings.config import get_config

def main():
    """Run administrative tasks."""
    # 动态设置Django配置模块,默认加载dev环境配置
    os.environ.setdefault(
        'DJANGO_SETTINGS_MODULE',
        get_config('DJANGO_SETTINGS_MODULE', default='openai_chat.settings.dev')
    )
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
