from typing import Any


def get_client_ip(request: Any) -> str:
    """
    获取客户端真实IP地址:
    - 优先从 X-Forwarded-For 获取 (支持多级代理，取首个)
    - 若不存在，则退回使用 REMOTE_ADDR
    """
    meta = getattr(request, "META", None)
    if meta is None:
        django_request = getattr(request, "_request", None)
        meta = getattr(django_request, "META", {})

    x_forwarded_for = meta.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # X-Forwarded-For 可能是多个 IP 地址组成的逗号分隔字符串
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = meta.get("REMOTE_ADDR", "")
    return ip
