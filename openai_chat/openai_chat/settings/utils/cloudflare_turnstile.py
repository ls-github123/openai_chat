import requests
from openai_chat.settings.utils.logging import get_logger
from typing import Optional
from functools import wraps # python标准库装饰器工具
from django.http import HttpResponseBadRequest # 400错误响应类

logger = get_logger("project.api")

def verify_turnstile_token(token: str, secret_key: str, remoteip: Optional[str] = None) -> bool:
    """
    校验 Cloudflare Turnstile Token 有效性
    参数:
    - param token: 前端提交的 cf-turnstile-response(用户在前端页面通过验证后,由Turnstile自动生成)
    - param secret_key: 后端密钥(不可暴露), 从Azure key Vault中获取
    - param remoteip: 可选, 用户IP, 增强安全验证(推荐)
    - return: bool 验证是否通过(布尔值), True表示验证通过, False表示验证失败或请求异常
    """
    # Cloudflare Turnstile 的验证接口地址
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    
    # 构造请求数据(包含密钥、Token及可选的用户IP)
    data = {
        "secret": secret_key,
        "response": token,
    }
    
    if remoteip:
        data["remoteip"] = remoteip
    
    try:
        # 向Cloudflare发起POST请求,发送验证数据,超时5秒
        resp = requests.post(url, data=data, timeout=5)
        resp.raise_for_status() # 返回状态码非2xx, 抛出HTTPError异常
        result = resp.json() # 解析返回结果为JSON格式
        success = result.get("success", False) # 获取验证结果,默认为False
        
        if not success: # 如果验证未通过,记录警告日志
            logger.warning(f"[Cloudflare_turnstile]请求验证失败:{result}")
        return success
    
    except requests.RequestException as e: # 网络请求异常捕获
        logger.error(f"[Cloudflare_Turnstil] 请求异常:{e}")
        return False
    

def turnstile_required(secret_key: str):
    """
    装饰器:用于保护需要 Turnstile 人机验证的视图函数
    参数:
    - param secret_key: 对应Cloudflare 小组件的Secret_key(从Azure key vault获取)
    用法:
    @turnstile_required(secret_key=settings.TURNSTILE_SECRET_KEY_REGISTER)
    def register_view(request): ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # === 提取前端提交的 Token ===
            # Turnstile 在前端将验证结果作为 'cf-turnstile-response' 提交
            token = request.POST.get("cf-turnstile-response")
            
            if not token:
                return HttpResponseBadRequest("缺少人机验证 Token")
            
            # === 获取客户端IP(推荐传递,提升验证准确性) ===
            # Cloudflare 使用此IP与行为模型匹配, 防止token被滥用
            remote_ip = request.META.get("REMOTE_ADDR")
            
            # === 调用后端验证函数, 提交 token + IP + 密钥 ===
            success = verify_turnstile_token(
                token = token,
                secret_key=secret_key,
                remoteip=remote_ip
            )
            
            # === 处理验证失败情况 ===
            if not success:
                return HttpResponseBadRequest("人机验证未通过, 请刷新后重试")
            
            # === 验证成功, 执行原始视图函数 ===
            return view_func(request, *args, **kwargs)
        
        return _wrapped_view # 返回包装后的视图函数(带验证功能)
    return decorator # 返回装饰器本体(接收视图函数)