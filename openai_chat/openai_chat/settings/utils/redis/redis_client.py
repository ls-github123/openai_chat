"""
Redis 客户端连接池模块封装
- 支持多 DB 连接池复用
- 导入阶段零 I/O(不创建连接池)
- 运行期按需懒加载
- 配置统一从 django.conf.settings 读取
"""
from __future__ import annotations
from typing import Dict, Optional
from redis import Redis, ConnectionPool
from django.conf import settings
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("project.redis_config")

# 不同 DB 使用不同连接池(进程内缓存)
_REDIS_POOLS: Dict[int, ConnectionPool] = {}

def _get_redis_config() -> dict:
    """
    统一读取 Redis 配置
    """
    host = getattr(settings, "REDIS_HOST", "127.0.0.1")
    port = int(getattr(settings, "REDIS_PORT", 6379))
    password = getattr(settings, "REDIS_PASSWORD", None)
    
    max_connections = int(getattr(settings, "REDIS_MAX_CONNECTIONS", 50))
    socket_connect_timeout = int(getattr(settings, "REDIS_SOCKET_CONNECT_TIMEOUT", 5))
    decode_responses = bool(getattr(settings, "REDIS_DECODE_RESPONSES", False))
    
    return {
        "host": host,
        "port": port,
        "password": password,
        "max_connections": max_connections,
        "socket_connect_timeout": socket_connect_timeout,
        "decode_responses": decode_responses,
    }

def get_redis_pool(db: int = 0) -> ConnectionPool:
    """
    获取指定 Redis DB 的连接池（懒加载 + 复用）
    - 导入阶段不会触发任何网络 I/O
    """
    if db in _REDIS_POOLS:
        return _REDIS_POOLS[db]
    
    cfg = _get_redis_config()
    
    try:
        pool = ConnectionPool(
            host=cfg["host"],
            port=cfg["port"],
            password=cfg["password"],
            db=db,
            decode_responses=cfg["decode_responses"],
            max_connections=cfg["max_connections"],
            socket_connect_timeout=cfg["socket_connect_timeout"],
        )
        _REDIS_POOLS[db] = pool
        logger.info(f"[redis_client] Redis连接池已创建(db={db})")
        return pool
    except Exception:
        logger.exception(f"[redis_client] Redis连接池创建失败(db={db})")
        raise
    
def get_redis_client(db: int = 0, *, health_check: bool = False) -> Redis:
    """
    获取 Redis 客户端(使用连接池)
    - 默认不 ping, 避免高频 I/O
    - health_check=True 时发起 ping(诊断/启动探针)
    """
    pool = get_redis_pool(db=db)
    client = Redis(connection_pool=pool)
    
    if health_check:
        try:
            client.ping()
            logger.debug(f"[redis_client] Redis ping 成功(db={db})")
        except Exception:
            logger.exception(f"[redis_client] Redis ping 失败(db={db})")
            raise
    
    return client