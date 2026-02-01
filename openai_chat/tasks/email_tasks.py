"""
邮件发送 Celery 任务
"""
import hashlib # 生成稳定 biz_key digest, 避免Redis key-space污染
import secrets # 生成锁 token, 避免误删
from typing import Optional, Any, Dict
from celery import shared_task # Celery 任务装饰器
from django.conf import settings # 运行时读取 settings, 避免 import base.py 直接触发
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client
from openai_chat.settings.utils.email.resend_client import (
    send_email_sync, # 同步发送
    EmailTransientError, # 瞬时错误(可重试)
    EmailPermanentError, # 永久错误(不重试)
    EmailSendError, # 其他错误(默认不重试)
)

logger = get_logger("celery.tasks_email")

REDIS_DB_MAIL = getattr(settings, "REDIS_DB_MAIL", 11)

# === Redis Key 规范 ===
def _done_key(biz_key: str) -> str:
    """邮件已发送幂等标记"""
    return f"mail:done:{biz_key}"

def _lock_key(biz_key: str) -> str:
    """邮件发送互斥锁(并发屏障)"""
    return f"mail:lock:{biz_key}"

def _normalize_biz_key(biz_key: str) -> str:
    """
    固化/规范化 biz_key:
    - 避免 biz_key 过长/包含特殊字符污染 Redis key-space
    - 避免将敏感业务参数直接暴露在 Redis key 名中
    - digest 仅用于 Redis key；原 biz_key 仍可用于日志与排障
    """
    return hashlib.sha256(biz_key.encode("utf-8")).hexdigest()

# === 锁: 安全获取与释放 ===
_RELEASE_LUA = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
"""

def _acquire_lock(r: Any, lk: str, lock_ttl_ms: int) -> Optional[str]:
    """
    获取互斥锁并返回 token(用于安全释放)
    - set NX PX: 只在锁不存在时设置, 并设置过期时间
    - 成功-返回 token; 失败-返回 None
    """
    token = secrets.token_hex(16)
    ok = r.set(lk, token.encode("utf-8"), nx=True, px=lock_ttl_ms)
    return token if ok else None

def _release_lock(r: Any, lk: str, token: str) -> None:
    """
    安全释放锁:
    - 当前值 == token 时删除
    - 防止：锁过期后被其他任务重新获取，旧任务 finally 误删新锁
    """
    r.eval(_RELEASE_LUA, 1, lk, token)


# === Celery task ===
@shared_task(
    bind=True,
    name="send_email_async_task",
    ignore_result=True, # 不存储任务结果
    acks_late=False, # 降低断连导致 redeliver 后重复执行的概率
)
def send_email_async_task(
    self,
    *,
    biz_key: str,
    to_email: str,
    subject: str,
    html_content: str,
    from_email: Optional[str] = None,
    done_ttl_seconds: int = 3600, # 成功屏障 TTL
    lock_ttl_ms: int = 60_000, # 锁TTL
    retry_max: int = 2
) -> Dict[str, Any]:
    """
    邮件发送 Celery 任务
    - biz_key: 业务幂等键(由上层生成, 例 register:{email}:{request_id})
    - done_key: 发送成功后写入, 构建成功幂等屏障
    - lock_key: 执行互斥锁, 避免并发执行
    - 仅对瞬时错误 retry (超时/断连/429/5XX)
    """
    # 获取邮件专用 Redis DB 客户端
    r = get_redis_client(db=REDIS_DB_MAIL)
    
    # 固化 biz_key, 用于Redis Key(原 biz_key 用于日志)
    biz_digest = _normalize_biz_key(biz_key)
    
    dk = _done_key(biz_digest) # 成功幂等 Key
    lk = _lock_key(biz_digest) # 互斥锁 key
    
    token: Optional[str] = None # 防止 finally 未定义
    
    # 成功幂等: 已发送则直接跳过(避免重复投递/重试/redeliver)
    if r.exists(dk):
        logger.info(f"[mail-skip] already done biz_key={biz_key} to_email={to_email}")
        return {"ok": True, "skipped": True, "reason": "done"}
    
    # 互斥锁: 避免并发执行(包括同一任务重复入队)
    token = _acquire_lock(r, lk, lock_ttl_ms)
    if not token:
        logger.warning(f"[mail-skip] lock not acquired biz_key={biz_key} to={to_email}")
        return {"ok": True, "skipped": True, "reason": "locked"}
    
    try:
        # 调用同步发送
        res = send_email_sync(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            from_email=from_email,
        )
        
        # 成功屏障: 写 done_key (NX + EX)
        # - NX: 避免极端并发场景下覆盖
        # - EX: TTL 防止堆积
        r.set(dk, b"1", nx=True, ex=done_ttl_seconds)
        logger.info(
            f"[mail-sent] biz_key={biz_key} to={to_email} status={getattr(res, 'status_code', None)}"
        )
        return {"ok": True, "skipped": False, "status": getattr(res, "status_code", None)}
    
    except EmailTransientError as e:
        # 瞬时错误: 允许重试(指数退避)
        # retries: 第 0 次失败 -> 15s，第 1 次 -> 30s，第 2 次 -> 60s ...
        retries = getattr(self.request, "retries", 0)
        countdown = 15 * (2 ** retries)
        
        logger.warning(
            f"[mail-retry] biz_key={biz_key} to_email={to_email} retries={retries} countdown={countdown}s err={e}"
        )
        raise self.retry(exc=e, countdown=countdown, max_retries=retry_max)
    
    except EmailPermanentError as e:
        # 永久错误: 不重试
        logger.error(f"[mail-fail] permanent biz_key={biz_key} to={to_email} err={e}")
        return {"ok": False, "error": str(e)}
    
    except EmailSendError as e:
        # 未分类错误: 保守处理-不重试
        logger.exception(f"[mail-fail] unknown biz_key={biz_key} to={to_email} err={e}")
        return {"ok": False, "error": str(e)}
    
    finally:
        # 安全释放锁(CAS)
        if token: # 仅在 token 存在时释放
            try:
                _release_lock(r, lk, token)
            except Exception:
                logger.exception(f"[mail-unlock-failed] biz_key={biz_key} to_email={to_email}")