"""
Resend邮件服务 HTTP 客户端封装(底层)
- 只负责构造并发送 HTTP 请求
- 不处理: 幂等性 / 锁 / 频率控制
- 提供：sync 调用方式，避免 Celery 中使用 asyncio.run()

设计原则:
- 1. 统一从 django.conf.settings 读取 RESEND_EMAIL
- 2. 明确区分：可重试（瞬时）与不可重试（永久）错误

注:
- 所有邮件统一通过 Celery 发送
- Celery worker 内仅使用 send_email_sync()
- 不在 Celery 中使用 asyncio / async 版本
"""

from dataclasses import dataclass
from typing import Optional, Any, Dict
import httpx # 同时支持 sync/async 请求

from django.conf import settings # 运行时读取 RESEND_EMAIL（避免导入 base.py）
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("clients.resend")

# ===错误类型(上层据此决定 retry)===
class EmailSendError(Exception):
    """
    邮件发送失败(通用)
    - 上层根据类型判断是否重试
    """
    pass

class EmailTransientError(EmailSendError):
    """
    瞬时错误（建议重试）
    - 网络超时
    - 连接断开
    - 429 限流
    - 5xx 服务端错误
    """
    pass

class EmailPermanentError(EmailSendError):
    """
    永久错误（不建议重试）
    - 4xx 参数错误
    - 鉴权错误（401/403）
    - payload 格式不合法等
    """
    pass

# === 统一返回结构 ===
@dataclass(frozen=True)
class EmailSendResult:
    ok: bool
    status_code: Optional[int] = None
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
def _get_resend_config() -> Dict[str, Any]:
    """
    运行时获取 RESEND_EMAIL 配置
    - 依赖 Django 已正确加载 settings
    """
    cfg: Dict[str, Any] = getattr(settings, "RESEND_EMAIL", {})
    if not cfg:
        raise RuntimeError("settings.RESEND_EMAIL 未配置或为空")
    if not cfg.get("API_KEY"):
        raise RuntimeError("settings.RESEND_EMAIL['API_KEY'] 未配置")
    return cfg

def _build_headers(api_key: str) -> Dict[str, Any]:
    """
    构造 Resend 请求头
    """
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

def _build_payload(
    *,
    to_email: str,
    subject: str,
    html_content: str,
    from_email: Optional[str],
    default_from: str,
) -> Dict[str, Any]:
    """
    构造 Resend API 所需 payload
    """
    return {
        "from": from_email or default_from,
        "to": [to_email],
        "subject": subject,
        "html": html_content,
    }

def _classify_and_raise(response: httpx.Response) -> None:
    """
    根据 HTTP 状态码，抛出可重试/不可重试异常（供上层 retry 策略使用）
    """
    status = response.status_code
    body = response.text[:500] # 防止日志过大
    
    # 429/5XX 一般可重试
    if status == 429 or 500 <= status <= 599:
        raise EmailTransientError(f"Resend transient error: status={status}, body={body}")
    
    # 4XX 永久错误(参数/鉴权/格式问题)
    if 400 <= status <= 499:
        raise EmailPermanentError(f"Resend permanent error: status={status}, body={body}")
    
    # 其他不常见状态, 归为通用错误
    raise EmailSendError(f"Resend error: status={status}, body={body}")

def send_email_sync(
    *,
    to_email: str,
    subject: str,
    html_content: str,
    from_email: Optional[str] = None,
) -> EmailSendResult:
    """
    同步发送邮件(Celery worker 内调用)
    
    返回:
    - EmailSendResult(ok=True, ...)
    异常:
    - EmailTransientError: 上层可 retry
    - EmailPermanentError: 上层不应 retry
    - EmailSendError: 未分类错误，上层保守不 retry
    """
    cfg = _get_resend_config()
    
    api_url = cfg.get("API_URL", "https://api.resend.com/emails")
    api_key = cfg["API_KEY"]
    timeout = cfg.get("TIMEOUT", 10)
    
    # 默认发件人格式
    default_from = f"{cfg.get('FROM_NAME', 'OpenAI_Chat')} <{cfg.get('FROM_EMAIL', 'support@openai-chat.xyz')}>"
    
    headers = _build_headers(api_key)
    payload = _build_payload(
        to_email=to_email,
        subject=subject,
        html_content=html_content,
        from_email=from_email,
        default_from=default_from,
    )
    
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(api_url, headers=headers, json=payload)
            
            # 非 2xx: 分类处理
            if resp.status_code < 200 or resp.status_code >= 300:
                _classify_and_raise(resp)
            
            # 2xx: 尝试解析 JSON
            data = resp.json() if resp.content else {}
            
            message_id = data.get("id")
            logger.info(f"[Resend] sent ok -> {to_email}, status={resp.status_code}, id={message_id}")
            return EmailSendResult(ok=True, status_code=resp.status_code, data=data)
    
    # 网络层异常: 一律按瞬时错误处理
    except httpx.TimeoutException as e:
        logger.exception(f"[Resend] timeout -> {to_email}: {e}")
        raise EmailTransientError(str(e)) from e
    
    except httpx.RequestError as e:
        # RequestError 为 httpx 网络异常父类（包含 ConnectError、ReadError 等）
        logger.exception(f"[Resend]  transient request error -> {to_email}: {e}")
        raise EmailTransientError(str(e)) from e