from __future__ import annotations
import os
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("system.init")

# 仅用于"本进程内"防重复调用
# - 防止同一进程内多次调用 init_system()
_system_initialized = False # 进程内幂等标志

def init_system() -> None:
    """
    系统级初始化入口(显式调用)
    - import 阶段禁止触发任何 I/O
    - 必须通过环境变量显式开启(防止 runserver/migrate/celery 误触发)
    - 重依赖延迟导入，避免启动期导入链膨胀
    """
    global _system_initialized
    
    # 1.进程内幂等: 同一进程重复调用直接跳过
    if _system_initialized:
        logger.info("[SystemInit] skipped (already initialized in-process)")
        return
    
    # 显式开关: 未开启则不执行任何系统初始化逻辑
    if os.getenv("SYSTEM_INIT_ENABLED", "").strip() != "1":
        logger.info("[SystemInit] disabled (SYSTEM_INIT_ENABLED!=1)")
        return
    
    try:
        # 当前阶段: 不做任何 I/O 初始化
        logger.info("[SystemInit] enabled (no-op): no runtime init required")
        _system_initialized = True
    except Exception:
        # exception 自带 traceback, 便于排障
        logger.exception("[SystemInit] failed")
        raise