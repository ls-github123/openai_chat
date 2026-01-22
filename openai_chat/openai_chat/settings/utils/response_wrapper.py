from __future__ import annotations
from typing import Any, Dict, Optional # 类型注解: 明确data结构
from rest_framework.response import Response # DRF标准响应

def json_response(
    *,
    success: bool,
    code: str,
    message: str,
    data: Optional[Dict[str, Any]] = None,
    http_status: int = 200,
    request=None,
    request_id: Optional[str] = None,
) -> Response:
    """
    统一响应封装
    - success / code / message / data / request_id 五段式固定结构
    - 优先使用显式 request_id
    - 否则尝试从 request.request_id 获取(由中间件注入)
    - 后续接口只从此处输出 Response
    """
    rid = request_id
    if rid is None and request is not None:
        rid = getattr(request, "request_id", None)
    
    payload: Dict[str, Any] = {
        "success": success,
        "code": code,
        "message": message,
        "data": data or {},
        "request_id": rid,
    }
    return Response(payload, status=http_status)