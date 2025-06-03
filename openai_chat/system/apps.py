from django.apps import AppConfig
from openai_chat.settings.utils.locks import build_lock # 获取分布式锁
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.snowflake import snowflake_const
from openai_chat.settings.utils.snowflake.snowflake_guard import start_snowflake_guard, ensure_snowflake_guard

logger = get_logger("project.snowflake.guard")

class SystemConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'system'
    
    def ready(self):
        """
        系统启动时初始化 Snowflake 守护进程，使用分布式锁确保全局唯一。
        主进程负责注册续约任务，其他进程可进入降级续约模式。
        """
        lock_key = snowflake_const.SYSTEM_INIT_LOCK_KEY # 系统初始化锁键
        lock_ttl = snowflake_const.SYSTEM_INIT_LOCK_EXPIRE * 1000 # 锁的过期时间(单位:毫秒)
        try:
            # 尝试使用 Redlock 分布式锁,确保仅一个实例初始化 Snowflake 守护进程
            with build_lock(key=lock_key, ttl=lock_ttl, strategy='safe') as acquired: # safe模式获取redlock分布式锁
                if acquired: # 如果成功获取锁
                    logger.info("[SystemInit] 获取 RedLock 分布式锁成功，开始初始化守护进程")
                    start_snowflake_guard() # 启动 Snowflake 守护线程
                    logger.info("[SystemInit] Snowflake 分布式节点ID守护进程启动完成")
                else:
                    logger.warning("[SystemInit] 未能获取锁(acquired=False),跳过初始化")
                    # 降级策略：仅尝试续约
                    ensure_snowflake_guard() # 确保注册键存在
                    start_snowflake_guard() # 启动续约线程
                    logger.info("[SystemInit] 降级模式：已启动续约线程以确保节点注册有效")
        except RuntimeError:
            # RedLock 封装层抛出 RuntimeError 表示锁获取失败
            logger.info("[SystemInit] 已由其他进程初始化, 当前进程跳过初始化")
            ensure_snowflake_guard()
            start_snowflake_guard()
            logger.info("[SystemInit] 降级模式：已启动续约线程以确保节点注册有效")
        except Exception as e:
            logger.error(f"[SystemInit] 初始化异常: {e}")