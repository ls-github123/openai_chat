# __init__.py - 分布式锁模块初始化文件
# 暴露锁接口和实现类

from .lock_factory import build_lock # 导入锁工厂函数
from .interface_lock import BaseLock # 导入锁接口定义

__all__ = [
    'build_lock', # 锁工厂函数
    'BaseLock', # 锁接口定义
]