from openai_chat.settings.utils.logging import get_logger # 日志记录器
import os
from typing import Optional # 可选类型提示
from . import snowflake_const # 导入 Snowflake 全局常量配置 
logger = get_logger("project.snowflake.register")

# 自动检测是否为开发环境(开发环境启用容错模式)
IS_DEV = "dev" in os.getenv("DJANGO_SETTINGS_MODULE", "").lower() # 返回True或False
ALLOW_CLOCK_BACKWARD = IS_DEV # 开发环境返回True,运行时允许时钟回拨(容错模式)

class RedisNodeRegister:
    """
    使用Redis自动注册并分配 datacenter_id 和 machine_id
    避免多个实例 ID冲突, 每次注册有效期1小时
    支持基于唯一标识(MACHINE_UNIQUE_ID)持久化绑定节点编号
    """
    def __init__(self, redis_instance, unique_key: Optional[str] = None):
        self.redis = redis_instance # Redis连接实例
        self.unique_key = unique_key # 唯一标识,持久化绑定节点编号
        self.node_key_prefix = snowflake_const.SNOWFLAKE_NODE_KEY_PREFIX # 节点注册键前缀
        self.bind_key_prefix = snowflake_const.SNOWFLAKE_BIND_KEY_PREFIX # 绑定唯一标识键前缀
        self.max_dc_id = snowflake_const.SNOWFLAKE_MAX_DATACENTER_ID # 最大数据中心ID(31)
        self.max_machine_id = snowflake_const.SNOWFLAKE_MAX_MACHINE_ID # 最大机器ID(31)
        self.ttl = snowflake_const.SNOWFLAKE_REGISTER_TTL_SECONDS # 注册键有效期(单位:秒)
        
    def register(self) -> tuple[int, int]:
        """
        在 Redis 中尝试注册一个未被使用的节点组合
        若提供唯一标识, 则优先尝试使用该标识进行注册
        """
        # 优先查找绑定记录
        if self.unique_key: # 如果有唯一标识, 则尝试获取绑定的节点编号
            bind_key = f"{self.bind_key_prefix}:{self.unique_key}" # 生成绑定键
            value = self.redis.get(bind_key) # 尝试获取绑定的节点编号
            if value:
                try:
                    if isinstance(value, bytes):
                        value = value.decode()
                    datacenter_id, machine_id = map(int, value.split(":")) # 解析数据中心ID和机器ID
                    logger.info(f"检测到持久绑定节点: datacenter={datacenter_id}, machine={machine_id}")
                    return datacenter_id, machine_id # 如果绑定记录已存在, 直接返回绑定的节点编号        
                except Exception as e:
                    logger.error(f"绑定值解析失败: {value}, 错误: {e}")
                    raise RuntimeError("Redis 中绑定记录格式错误")
                
        # 如果没有绑定记录, 则开始扫描可用节点进行注册
        for datacenter_id in range(self.max_dc_id + 1): # 遍历数据中心ID范围(0-31)
            for machine_id in range(self.max_machine_id + 1): # 遍历机器ID范围(0-31)
                # 生成注册键, 格式为 "snowflake:nodes:datacenter_id:machine_id"
                reg_key = f"{self.node_key_prefix}:{datacenter_id}:{machine_id}"
                # 尝试设置键值, nx=True表示仅当键不存在时设置成功, ex过期时间(单位:秒)
                if self.redis.set(reg_key, "1", nx=True, ex=self.ttl):
                    logger.info(f"注册节点成功 datacenter={datacenter_id}, machine={machine_id}")
                    # 如果有唯一标识, 则绑定节点编号
                    if self.unique_key:
                        bind_key = f"{self.bind_key_prefix}:{self.unique_key}" # 生成绑定键
                        self.redis.set(bind_key, f"{datacenter_id}:{machine_id}") # 保存绑定关系
                        logger.info(f"绑定唯一标识{self.unique_key}到节点: datacenter={datacenter_id}, machine={machine_id}")
                    # 返回注册的节点编号
                    return datacenter_id, machine_id
        logger.error("无法分配可用节点ID, 请检查 Redis 或增加ID空间") # 如果没有可用节点, 记录错误日志
        raise RuntimeError("无法分配可用节点ID, 请检查 Redis 或增加ID空间")