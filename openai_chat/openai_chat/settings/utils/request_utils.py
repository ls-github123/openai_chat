from django.http import HttpRequest

def get_client_ip(request: HttpRequest) -> str:
    """
    获取客户端真实IP地址:
    - 优先从 X-Forwarded-For 获取 (支持多级代理，取首个)
    - 若不存在，则退回使用 REMOTE_ADDR
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # X-Forwarded-For 可能是多个 IP 地址组成的逗号分隔字符串
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR", "")
    return ip