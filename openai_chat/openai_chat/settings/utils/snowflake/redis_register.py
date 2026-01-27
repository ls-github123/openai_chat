from __future__ import annotations
import os
from typing import Optional # 可选类型提示
from openai_chat.settings.utils.logging import get_logger # 日志记录器
from . import snowflake_const # 导入 Snowflake 全局常量配置 
logger = get_logger("project.snowflake.register")

# 自动检测是否为开发环境(开发环境启用容错模式)
IS_DEV = "dev" in os.getenv("DJANGO_SETTINGS_MODULE", "").lower() # 返回True或False
ALLOW_CLOCK_BACKWARD = IS_DEV # 开发环境返回True,运行时允许时钟回拨(容错模式)

class RedisNodeRegister:
    """
    Snowflake 节点分配器(纯持久绑定模型)
    - 每台实例(unique_key) 永久绑定一个(datacenter_id, machine_id)
    - 不使用 TTL 租约(不需要守护线程 / Celery 续约)
    - 使用永久占用键 used:<dc>:<machine> 确保全局唯一分配
    """
    def __init__(self, redis_instance, unique_key: Optional[str] = None):
        self.redis = redis_instance # Redis连接实例
        self.unique_key = unique_key # 唯一标识,持久化绑定节点编号
        self.bind_key_prefix = snowflake_const.SNOWFLAKE_BIND_KEY_PREFIX # 唯一标识键前缀
        self.used_key_prefix = snowflake_const.SNOWFLAKE_USED_KEY_PREFIX # 永久占用键前缀
        self.max_dc_id = snowflake_const.SNOWFLAKE_MAX_DATACENTER_ID
        self.max_machine_id = snowflake_const.SNOWFLAKE_MAX_MACHINE_ID
        
    def register(self) -> tuple[int, int]:
        """
        获取/分配本机(datacenter_id, machine_id)
        - 若 bind 存在: 直接返回(稳定)
        - 否则扫描 (dc,machine)，尝试原子占用 used 键（永久）
        - 占用成功后写入 bind（永久），返回
        """
        if not self.unique_key:
            raise RuntimeError("unique_key 不能为空(纯持久绑定模型必须提供机器唯一标识)")
        
        bind_key = f"{self.bind_key_prefix}:{self.unique_key}"
        
        # 优先读取永久绑定
        value = self.redis.get(bind_key)
        if value:
            try:
                if isinstance(value, bytes):
                    value = value.decode()
                datacenter_id, machine_id = map(int, str(value).split(":"))
                logger.info(f"检测到持久绑定节点: datacenter={datacenter_id}, machine={machine_id}")
                return datacenter_id, machine_id
            except Exception as e:
                logger.error(f"绑定值解析失败: {value}, error: {e}")
                raise RuntimeError("Redis 中绑定记录格式错误")
            
        # 扫描并永久占用一个(dc,machine)
        for datacenter_id in range(self.max_dc_id + 1):
            for machine_id in range(self.max_machine_id + 1):
                used_key = f"{self.used_key_prefix}:{datacenter_id}:{machine_id}"
                
                # 原子占用: 当 used_key 不存在时才写入(永久)
                ok = self.redis.set(used_key, self.unique_key, nx=True)
                if not ok:
                    continue
                
                # 写入永久绑定
                self.redis.set(bind_key, f"{datacenter_id}:{machine_id}")
                
                logger.info(
                    f"注册并绑定节点成功 unique_key={self.unique_key} -> datacenter={datacenter_id}, machine={machine_id}"
                )
                return datacenter_id, machine_id
            
        logger.error("无法分配可用节点ID, 请检查 Redis 或增加ID空间")
        raise RuntimeError("无法分配可用节点ID, 请检查 Redis 或增加ID空间")