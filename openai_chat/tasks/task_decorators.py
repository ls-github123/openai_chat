import hashlib
from openai_chat.settings.utils.logging import get_logger
from functools import wraps
from openai_chat.settings.utils.locks import build_lock # 引入锁工厂函数

logger = get_logger("task_email")

def generate_idempotent_key(task_name: str, args: tuple, kwargs: dict) -> str:
    """
    生成唯一幂等性key (用于Redis锁标识)
    """
    raw = f"{task_name}:{args}:{kwargs}"
    return f"idempotent:{hashlib.sha256(raw.encode()).hexdigest()}"

def resilient_task(lock_ttl_ms: int = 1000, max_retries: int = 3, retry_delay: int = 5, strategy: str = 'safe'):
    """
    Celery 任务装饰器:支持自动重试 + 幂等性控制(分布式或单节点锁)
    
    参数: 
    - lock_ttl_ms: 锁生存期(单位:毫秒-默认10秒)
    - max_retries: 最大重试次数
    - retry_delay: 每次失败后等待时间(单位:秒)
    - strategy: 锁策略('safe'=RedLock, 'fast'=单节点Redis)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            task_name = func.__name__
            lock_key = generate_idempotent_key(task_name, args, kwargs)
            lock = build_lock(key=lock_key, ttl=lock_ttl_ms, strategy=strategy)
            
            if not lock.acquire():
                return None
            
            try:
                return func(self, *args, **kwargs)
            except Exception as e:
                logger.error(f"[任务异常] {task_name}重试中: {e}")
                raise self.retry(exc=e, countdown=retry_delay, max_retries=max_retries)
            finally:
                lock.release()
                logger.info(f"[任务解锁] key={lock_key}")
        return wrapper
    return decorator