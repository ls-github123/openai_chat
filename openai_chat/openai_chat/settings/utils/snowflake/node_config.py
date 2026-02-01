from __future__ import annotations
import os
import platform
from django.conf import settings
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client
from .redis_register import RedisNodeRegister
from . import snowflake_const

logger = get_logger("project.snowflake")

# 进程内缓存: 避免每次调用都访问 Redis
_NODE_IDS_CACHE: tuple[int, int] | None = None

def _is_dev() -> bool:
    """
    判断是否为开发环境:
    - 用于决定是否允许使用 hostname 作为兜底 unique_key
    """
    return "dev" in os.getenv("DJANGO_SETTINGS_MODULE", "").lower()

def get_machine_unique_key() -> str:
    """
    获取机器唯一标识(用于纯持久绑定模型)
    - 生产环境: 必须配置
    - 开发环境: 自动兜底hostname(稳定)
    """
    value = getattr(settings, "MACHINE_UNIQUE_ID", None)
    if value:
        key = str(value).strip()
        if key:
            return key
    
    # 开发环境兜底
    if _is_dev():
        # Windows: COMPUTERNAME
        # Linux / Docker / WSL: HOSTNAME
        hostname = (
            os.getenv("COMPUTERNAME")
            or os.getenv("HOSTNAME")
            or platform.node() # 返回当前机器的主机名
        )
        hostname = (hostname or "").strip()
        if hostname:
            return f"dev-{hostname}"
    
    # 生产环境不允许继续
    raise RuntimeError("MACHINE_UNIQUE_ID未配置")


def get_node_ids() -> tuple[int, int]:
    """
    获取当前实例(datacenter_id, machine_id)
    
    纯持久绑定模型：
    - 依赖 unique_key（机器唯一标识）来建立永久绑定
    - 不使用 TTL / 不需要守护线程
    - 使用 Redis db=SNOWFLAKE_REDIS_DB 作为绑定信息存储

    进程内缓存：
    - 同一进程内只分配一次，避免重复访问 Redis
    """
    global _NODE_IDS_CACHE
    
    if _NODE_IDS_CACHE is not None:
        return _NODE_IDS_CACHE
    
    unique_key = get_machine_unique_key()
    
    # Redis客户端(db=15) - snowflake 专用库
    redis_instance = get_redis_client(db=snowflake_const.SNOWFLAKE_REDIS_DB)
    
    # 注册器: unique_key必须非空
    register = RedisNodeRegister(redis_instance, unique_key=unique_key)
    
    _NODE_IDS_CACHE = register.register()
    logger.info(f"[SnowflakeNode] unique_key={unique_key}, node_ids={_NODE_IDS_CACHE}")
    return _NODE_IDS_CACHE