import asyncio
from typing import Optional
from celery import shared_task
from openai_chat.settings.utils.email import send_email # 邮件异步发送API接口函数
from openai_chat.settings.utils.logging import get_logger
from .task_decorators import resilient_task

logger = get_logger("task_email")

@shared_task(bind=True, name="send_email_async_task")
@resilient_task(lock_ttl_ms=15000, max_retries=3, retry_delay=5, strategy='safe')
def send_email_async_task(self, to_email: str, subject: str, html_content: str, from_email: Optional[str] = None):
    """
    Celery 同步任务包装器,调用async的send_email()发送邮件
    注: 任务在后台执行,调用时无需等待
    参数:
    - to_email: 收件人地址
    - subject: 邮件标题
    - html_content: HTML邮件正文
    - from_email: 可选自定义发件人(若为空则使用默认)
    
    日志:
    - 成功记录 info
    - 失败或异常记录 warning/error
    """
    result = asyncio.run(send_email(to_email, subject, html_content, from_email))
    if result:
        logger.info(f"[任务] ✅邮件已发送给 {to_email}")
    else:
        logger.warning(f"[任务] ❌ 邮件发送失败 -> {to_email}")
    return result