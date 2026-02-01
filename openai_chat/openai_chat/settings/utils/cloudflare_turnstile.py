import httpx
from openai_chat.settings.utils.logging import get_logger
from typing import Optional, Callable, Awaitable, TypeVar, cast, Any
from functools import wraps # python标准库装饰器工具
from django.http import JsonResponse, HttpRequest, HttpResponse

logger = get_logger("clients")

# 泛型类型变量，用于装饰器类型注解
F = TypeVar("F", bound=Callable[..., Awaitable[HttpResponse]])

async def verify_turnstile_token_async(token: str, secret_key: str, remoteip: Optional[str] = None) -> bool:
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
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(url, data=data)
            response.raise_for_status()
            result = await response.json()
            success = result.get("success", False)
            if not success:
                logger.warning(f"[Turnstile] 验证失败: {result}")
            return success
    except httpx.RequestError as e:
        logger.error(f"[Turnstile] 网络请求异常: {e}")
    except httpx.HTTPStatusError as e:
        logger.warning(f"[Turnstile] 状态码异常: {e.response.status_code}")
    except Exception as e:
        logger.error(f"[Turnstile] 请求异常: {e}")
    return False
    

def async_turnstile_required(secret_key: str) -> Callable[[F], F]:
    """
    异步视图装饰器:强制进行 Turnstile 验证
    参数:
    - param secret_key: 对应Cloudflare 小组件的Secret_key(从Azure key vault获取)
    用法:
    @async_turnstile_required(secret_key=settings.TURNSTILE_SECRET_KEY_REGISTER)
    async def post(self, request): ...
    """
    def decorator(view_func: F) -> F:
        @wraps(view_func)
        async def _wrapped_view(*args: Any, **kwargs: Any) -> HttpResponse:
            # === 提取前端提交的 Token ===
            # Turnstile 在前端将验证结果作为 'cf-turnstile-response' 提交
            request: Optional[HttpRequest] = None
            for arg in args:
                if isinstance(arg, HttpRequest):
                    request = arg
                    break
            
            if request is None:
                logger.error("[Turnstile] 无法提取 HttpRequest 对象")
                return JsonResponse({"code": 500, "msg": "内部错误"}, status=500)
            
            token = request.POST.get("cf-turnstile-response")
            if not token or token.strip() == "":
                return JsonResponse({"code": 400, "msg": "人机验证 Token 无效"}, status=400)
            
            remote_ip = request.META.get("REMOTE_ADDR")
            verified = await verify_turnstile_token_async(
                token=token,
                secret_key=secret_key,
                remoteip=remote_ip,
            )
            if not verified:
                return JsonResponse({"code": 403, "msg": "人机验证未通过, 请刷新后重试"}, status=403)
            
            return await view_func(*args, **kwargs)
        
        return cast(F, _wrapped_view) # 返回包装后的视图函数(带验证功能)
    
    return decorator # 返回装饰器本体(接收视图函数)