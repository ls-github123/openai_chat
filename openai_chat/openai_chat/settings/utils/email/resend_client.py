"""
Resend邮件服务API封装
- 构造 HTTP 请求并提交,不处理幂等性、锁或频率控制
- 上层逻辑控制由下一级 email_sender.py模块完成
"""

import httpx
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from typing import Optional
from openai_chat.settings.base import RESEND_EMAIL # 导入邮件发送模块配置

logger = get_logger("email_resend_client")

# 发送参数提取
API_URL = RESEND_EMAIL.get("API_URL", "https://api.resend.com/emails") # API接口地址
API_KEY = RESEND_EMAIL["API_KEY"] # API 密钥(使用列表强制获取,缺失即报错)
TIMEOUT = RESEND_EMAIL.get("TIMEOUT", 10) # 超时时间
FROM_EMAIL = f"{RESEND_EMAIL['FROM_NAME']} <{RESEND_EMAIL['FROM_EMAIL']}>"

# Resend 请求头格式
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}

async def send_email(
    to_email: str,
    subject: str,
    html_content: str,
    from_email: Optional[str] = None
) -> bool:
    """
    调用 Resend API 异步发送邮件
    
    参数:
    - to_email: 收件人邮箱地址
    - subject: 邮件主题
    - html_content: HTML 格式邮件正文
    - from_email: 可选自定义发件人,默认使用 settings 中配置的FROM_EMAIL
    
    返回:
    - True: 发送成功
    - False: 请求异常或被拒绝
    """
    payload = {
        "from": from_email or FROM_EMAIL, # 发件人名称<地址>
        "to": [to_email], # 支持多个收件人
        "subject": subject,
        "html": html_content,
    }
    
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(API_URL, headers=HEADERS, json=payload)
            response.raise_for_status()
            logger.info(f"[Resend] ✅邮件发送成功 -> {to_email}")
            return True
    except httpx.HTTPStatusError as e:
        logger.error(f"[Resend] ❌HTTP错误:{e.response.status_code} - {e.response.text}")
    except Exception as e:
        logger.error(f"[Resend] ❌发送异常:{str(e)}")
    return False