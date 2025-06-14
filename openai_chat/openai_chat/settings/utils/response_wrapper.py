from typing import Optional, Any, Dict
from rest_framework.response import Response

def json_response(code: int, msg: str, data: Optional[Dict[str, Any]] = None, status_code: int = 200) -> Response:
    """
    标准统一格式响应封装
    参数:
    - :param code: 业务状态码(如:200成功, 400参数错误等)
    - :param msg 返回的提示信息(前端展示)
    - :param data: 返回主体数据内容(默认空对象)
    - :param status_code: HTTP状态码(默认200)
    - :return DRF Response对象
    """
    return Response({
        "code": code,
        "msg": msg,
        "data": data or {}
    }, status=status_code)