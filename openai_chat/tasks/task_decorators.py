import hashlib
from openai_chat.settings.utils.logging import get_logger
from functools import wraps
from openai_chat.settings.utils.locks import build_lock # 引入锁工厂函数

logger = get_logger("task_email")

def generate_idempotent_key(task_name: str, args: tuple, kwargs: dict) -> str:
    """
    生成唯一幂等性key (用于Redis锁标识)
    使用 SHA256 哈希摘要防止参数泄露和避免 key 冲突
    参数:
    - task_name: 任务函数名
    - args: 位置参数
    - kwargs: 关键字参数
    
    返回:
    - Redis 中用于加锁的唯一 key 字符串
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
        @wraps(func) # 保留被装饰函数的元信息（如函数名、注释、签名等）
        def wrapper(self, *args, **kwargs):
            task_name = func.__name__ # 获取任务函数名称
            lock_key = generate_idempotent_key(task_name, args, kwargs) # 生成幂等性key
            lock = build_lock(key=lock_key, ttl=lock_ttl_ms, strategy=strategy) # 构建锁实例
            
            if not lock.acquire():
                # 如果未获取锁(其他任务正在执行), 跳过任务执行
                logger.warning(f"[跳过任务] 未获取锁:{lock_key}")
                return None
            
            try:
                return func(self, *args, **kwargs) # 正常执行任务逻辑
            except Exception as e:
                # 异常时记录日志并触发自动重试(由Celery自带retry机制处理)
                logger.error(f"[任务异常] {task_name}重试中: {e}")
                raise self.retry(exc=e, countdown=retry_delay, max_retries=max_retries)
            finally:
                # 无论是否成功,都释放锁
                lock.release()
                logger.info(f"[任务解锁] key={lock_key}")
        return wrapper
    return decorator