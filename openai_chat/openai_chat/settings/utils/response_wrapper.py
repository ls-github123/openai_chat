from __future__ import annotations
from typing import Any, Dict, Optional, Mapping # 类型注解: 明确data结构
from rest_framework.request import Request
from rest_framework.response import Response # DRF标准响应

def json_response(
    *,
    success: bool,
    code: str,
    message: str,
    data: Optional[Mapping[str, Any]] = None,
    http_status: int = 200,
    request: Optional[Request] = None,
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
    
    # 边界收口: 保证最终为 dict
    safe_data: Dict[str, Any]
    if data is None:
        safe_data = {}
    else:
        safe_data = dict(data)
    
    payload: Dict[str, Any] = {
        "success": success,
        "code": code,
        "message": message,
        "data": safe_data,
        "request_id": rid,
    }
    return Response(payload, status=http_status)