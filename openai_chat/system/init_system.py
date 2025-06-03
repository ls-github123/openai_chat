from openai_chat.settings.utils.snowflake.snowflake_guard import start_snowflake_guard # snowflake后台线程运行
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("project.snowflake.guard")

_system_initialized = False # 控制幂等性,防止重复初始化

def init_system():
    global _system_initialized
    if _system_initialized:
        logger.info("[SystemInit] 已跳过重复初始化")
        return
    
    try:
        start_snowflake_guard() # 启动snowflake守护线程
        logger.info("[SystemInit] 启动 Snowflake 分布式节点 ID 守护线程")
        print("[SystemInit] 初始化流程已完成")
        _system_initialized = True # 设置初始化标志为True
    except Exception as e:
        logger.error(f"[SystemInit] 初始化失败: {e}")
        raise