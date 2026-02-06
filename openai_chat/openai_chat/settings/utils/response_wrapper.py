from __future__ import annotations
from typing import Any, Optional, Mapping # 类型注解: 明确data结构
from rest_framework.response import Response # DRF标准响应
from rest_framework import status

def _normalize_data(data: Any) -> dict:
    # 统一把 data 变成 dict，避免出现 list/str 导致响应结构不稳定
    if data is None:
        return {}
    if isinstance(data, Mapping):
        return dict(data)
    return {"detail": data}

def json_response(
    *,
    success: bool,
    code: str,
    message: str,
    data: Any = None,
    http_status: int = status.HTTP_200_OK,
    request_id: Optional[str] = None,
) -> Response:
    """
    统一响应封装
    - success / code / message / data / request_id 五段式固定结构
    - 优先使用显式 request_id
    - 否则尝试从 request.request_id 获取(由中间件注入)
    - 后续接口只从此处输出 Response
    """
    payload = {
        "success": bool(success),
        "code": str(code),
        "message": str(message),
        "data": _normalize_data(data),
        "request_id": request_id,
    }
    return Response(payload, status=http_status)