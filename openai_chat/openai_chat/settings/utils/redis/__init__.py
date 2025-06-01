"""
Redis 模块封装统一接口暴露
用于外部模块统一导入和使用:Redis客户端/连接池工厂函数等
"""
from .redis_client import (
    get_redis_pool, # 获取连接池实例
    get_redis_client, # 获取Redis客户端实例
    REDIS_POOL, # 默认连接池实例
    REDIS_CLIENT, # 默认Redis客户端实例
)

__all__ = [
    "get_redis_pool",
    "get_redis_client",
    "REDIS_POOL",
    "REDIS_CLIENT",
]