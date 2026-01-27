"""
Snowflake 全局常量配置模块(纯持久绑定模型)
- 采用 bind + used 永久键模型
- 不使用 TTL 租约，不需要守护线程续约
- Redis 仅用于持久化节点绑定关系（db=REDIS_DB_SNOWFLAKE）
"""
from __future__ import annotations
from django.conf import settings

# Redis DB 配置
SNOWFLAKE_REDIS_DB: int = int(getattr(settings, "REDIS_DB_SNOWFLAKE", 15)) # Redis 数据库编号(db=15), 用于存储 snowflake 节点注册信息

# 系统初始化全局锁配置
SYSTEM_INIT_LOCK_KEY = "system:init:lock" # Redis锁键
SYSTEM_INIT_LOCK_EXPIRE = 10 # 锁过期时间(单位:秒)

# Redis 键前缀
SNOWFLAKE_BIND_KEY_PREFIX = "snowflake:nodes:bind" # 绑定唯一标识的键前缀
SNOWFLAKE_USED_KEY_PREFIX = "snowflake:nodes:used" # 永久占用键前缀

# 雪花算法配置
SNOWFLAKE_EPOCH = 1704067200000 # 自定义 epoch 时间戳(毫秒) 默认:2024-01-01 00:00:00
SNOWFLAKE_TIMESTAMP_BITS = 41 # 时间戳位宽(41位)
SNOWFLAKE_DATACENTER_BITS = 5 # 数据中心ID位宽(5位,0-31)
SNOWFLAKE_MACHINE_BITS = 5 # 机器ID位宽(5位, 0-31)
SNOWFLAKE_SEQUENCE_BITS = 12 # 序列号位宽(12位, 0-4095)

SNOWFLAKE_MAX_DATACENTER_ID = (1 << SNOWFLAKE_DATACENTER_BITS) - 1 # 31
SNOWFLAKE_MAX_MACHINE_ID = (1 << SNOWFLAKE_MACHINE_BITS) - 1 # 31
SNOWFLAKE_MAX_SEQUENCE = (1 << SNOWFLAKE_SEQUENCE_BITS) - 1 # 4095

# Bit shift 偏移量
SNOWFLAKE_MACHINE_SHIFT = SNOWFLAKE_SEQUENCE_BITS # 12
SNOWFLAKE_DATACENTER_SHIFT = SNOWFLAKE_MACHINE_SHIFT + SNOWFLAKE_MACHINE_BITS # 17
SNOWFLAKE_TIMESTAMP_SHIFT = SNOWFLAKE_DATACENTER_SHIFT + SNOWFLAKE_DATACENTER_BITS # 22