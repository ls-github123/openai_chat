import hashlib, json
from functools import wraps
from typing import Any, Callable, Dict, Tuple

# 本地导入
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.locks import build_lock # 引入锁工厂函数

logger = get_logger("celery.tasks")

def _stable_dumps(obj: Any) -> str:
    """
    将参数稳定序列化为 JSON 字符串
    
    参数解释：
    - sort_keys=True：
        对 dict 的 key 排序，保证同一内容（不同构造顺序）的输出一致。
    - separators=(",", ":")：
        去掉默认 JSON 的空格，输出更紧凑（最终会 hash，不需要可读空格）。
    - ensure_ascii=False：
        允许中文直接输出（最终 hash，不会泄露内容）。
    - default=str：
        遇到 JSON 不支持的类型（如 datetime、Decimal、自定义对象）时，
        兜底用 str(obj) 转为字符串，避免 dumps 直接报错。
        ⚠️ 注意：若 str(obj) 不稳定（包含动态信息），幂等 key 仍可能漂移。
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

def generate_idempotent_key(task_name: str, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> str:
    """
    生成 Celery 任务幂等 key:
    
    目标:
    - 同一任务 + 同一参数（args/kwargs） -> 得到相同 key
    - 通过对 key 加锁，避免同一任务参数被并发/重复执行
    
    - 使用稳定序列化, 避免 kwargs 顺序问题
    - 使用 SHA256 防止参数泄露并减少 Redis key 长度
    """
    payload = {
        "task": task_name, # 任务标识
        "args": args, # 位置参数
        "kwargs": kwargs, # 关键字参数(sort_keys 保存)
    }
    
    # 稳定序列化
    raw = _stable_dumps(payload).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    return f"idempotent:task:{task_name}:{digest}"

def resilient_task(
    *,
    lock_ttl_ms: int = 30_000,
    max_retries: int = 3,
    retry_delay: int = 5,
    strategy: str = "safe",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Celery 任务装饰器:
    - 幂等锁(避免重复/并发执行)
    - 自动重试(失败后按策略重试)
    
    使用方式:
    - @shared_task(bind=True)
    - @resilient_task(lock_ttl_ms=30000, max_retries=3, retry_delay=5, strategy="safe")
    - def my_task(self, ...):
    
    参数说明：
    - lock_ttl_ms:
        锁的 TTL（毫秒），用于 worker 异常退出时的兜底释放。
        ⚠️ 若任务执行时间可能超过 TTL，会导致锁过期后被再次抢占 -> 幂等失效。
        未来长任务需要“续期”机制。
    - max_retries:
        最大重试次数。超过次数 Celery 将标记任务失败。
    - retry_delay:
        每次重试延迟（秒）。可后续改为指数退避 + 抖动避免雪崩。
    - strategy:
        锁策略：由 build_lock() 解释。例如：
        - "safe"：RedLock（分布式更安全）
        - "fast"：单节点 Redis 锁（更快）
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        """
        decorator 接收被装饰函数 func，返回真正执行的 wrapper
        """
        @wraps(func)
        def wrapper(self, *args: Any, **kwargs: Any) -> Any:
            # 强约束: 必须是 celery Task 实例(具备 retry 属性)
            if not hasattr(self, "retry"):
                raise RuntimeError(
                    f"{func.__name__} 使用了 resilient_task，但任务未启用 bind=True，无法调用 self.retry()"
                )
            
            task_name = getattr(self, "name", func.__name__) # 优先使用 celery 注册名
            
            # 生成幂等 key(同任务同参数 -> 相同 key)
            lock_key = generate_idempotent_key(task_name, args, kwargs)
            
            # 构建锁实例(Redlock / 单节点锁)
            lock = build_lock(key=lock_key, ttl=lock_ttl_ms, strategy=strategy)
            
            # 尝试获取锁:
            # - 成功: 执行任务
            # - 失败: 相同key的任务正在执行(锁未过期)
            if not lock.acquire():
                logger.warning(f"[task-skip] lock not acquired key={lock_key}")
                return None
            
            try:
                # 正常执行任务逻辑
                return func(self, *args, **kwargs)
            except Exception as e:
                # 捕获异常：
                # 1) 记录 traceback
                # 2) 触发 Celery retry（任务重新入队）
                logger.exception(f"[task-error] {task_name} retrying: {e}")
                raise self.retry(exc=e, countdown=retry_delay, max_retries=max_retries)
            finally:
                # finally 必须释放锁:
                # - 无论成功/失败/重试，都需要释放（否则 lock_ttl_ms 内无法再次执行）
                try:
                    lock.release()
                except Exception:
                    logger.exception(f"[task-unlock-failed] key={lock_key}")
                else:
                    logger.info(f"[task-unlock] key={lock_key}")
            
        return wrapper
    
    return decorator