from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from openai_chat.settings.base import MACHINE_UNIQUE_ID # 导入机器唯一标识
from openai_chat.settings.utils.redis import get_redis_client # 导入Redis客户端获取接口
from .redis_register import RedisNodeRegister # 导入Redis注册器
from .snowflake_const import SNOWFLAKE_REDIS_DB # 导入Snowflake Redis DB配置

logger = get_logger("project.snowflake.register")

def get_machine_hash_key() -> str:
    """
    如果配置了机器唯一标识(MACHINE_UNIQUE_ID), 则返回该标识作为Redis注册键
    否则返回空字符串, 进入自动注册流程
    """
    return MACHINE_UNIQUE_ID if MACHINE_UNIQUE_ID else ""

def get_node_ids() -> tuple[int, int]:
    """
    获取当前实例的数据中心ID和机器ID
    使用封装的 Redis 客户端注册器分配
    注: snowflake 注册使用 db=15 隔离环境, 避免与锁逻辑混用
    :return: (datacenter_id, machine_id)
    """
    # 获取Redis客户端实例, 使用db=15隔离环境
    redis_instance = get_redis_client(db=SNOWFLAKE_REDIS_DB)
    machine_hash = get_machine_hash_key() # 获取机器唯一标识作为注册键
    # 创建Redis节点注册器实例, 如果有唯一机器标识则传入, 否则为None
    register = RedisNodeRegister(redis_instance, unique_key=machine_hash or None)
    return register.register() # 返回注册的节点ID元组