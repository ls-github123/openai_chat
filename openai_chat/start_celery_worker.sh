#!/bin/bash
# 启动 Celery Worker(适用 Bash 环境)

echo "启动 Celery Worker..."
celery -A openai_chat worker --loglevel=info --pool=solo