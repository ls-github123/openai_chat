"""
Redis客户端与 Redlock分布式锁配置模块(锁模块专用)
- 使用统一封装的Redis连接池机制
- 专用于锁模块(Redis db=0)
注:锁模块专属Redis实例配置,独立于Django缓存系统(CACHES)
"""
from __future__ import annotations
from typing import Optional, Any
from django.conf import settings
from openai_chat.settings.utils.logging import get_logger # 导入日志处理器模块封装

logger = get_logger("project.redlock") # 日志记录器

# 进程内单例缓存(非分布式唯一)
# 多进程部署时, 每进程均保留自己的缓存
_LOCK_REDIS_CLIENT: Optional[Any] = None
_REDLOCK_INSTANCE: Optional[Any] = None

def get_lock_redis_client():
    """
    获取锁模块专用 Redis 客户端(db=0)
    - 懒加载: 首次调用时创建
    - 进程内复用: 同一进程内只创建一次
    """
    global _LOCK_REDIS_CLIENT
    
    # 若进程已创建, 直接复用(避免重复初始化)
    if _LOCK_REDIS_CLIENT is not None:
        return _LOCK_REDIS_CLIENT
    
    # 延迟导入
    from openai_chat.settings.utils.redis import get_redis_client
    
    # 创建锁专用 Redis client(db=0)
    _LOCK_REDIS_CLIENT = get_redis_client(db=0)
    
    logger.info("[Redis_lock_Config] Redis 客户端初始化成功(用于单节点锁)")
    return _LOCK_REDIS_CLIENT

def get_redlock_instance():
    """
    获取 Redlock 实例(懒加载)
    - 只读取 settings.REDLOCK_SERVERS
    - 若节点数 < 3：提示退化(不阻断运行)
    - 进程内单例复用：同一进程只创建一次 Redlock 实例
    """
    global _REDLOCK_INSTANCE
    
    # 若已创建, 直接复用
    if _REDLOCK_INSTANCE is not None:
        return _REDLOCK_INSTANCE
    
    # 从 Django settings 读取 Redlock 节点列表
    servers = getattr(settings, "REDLOCK_SERVERS", None)
    if not servers or not isinstance(servers, list):
        raise RuntimeError("REDLOCK_SERVERS 未配置或格式错误")
    
    # 单节点/少节点提示
    if len(servers) < 3:
        logger.warning(f"[Redlock_Config] 当前 Redlock 节点数={len(servers)}, 处于单点/弱容灾模式")
    
    from redlock import Redlock
    
    # 创建并缓存 Redlock 实例
    _REDLOCK_INSTANCE = Redlock(list(servers))
    logger.info("[Redlock_Config] Redlock 实例初始化成功")
    return _REDLOCK_INSTANCE