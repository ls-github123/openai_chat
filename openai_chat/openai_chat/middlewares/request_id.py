from __future__ import annotations # 未来注解: 便于后续类型扩展
import uuid # 生成全局唯一 request_id
from django.utils.deprecation import MiddlewareMixin # Django兼容式中间件基类

class RequestIdMiddleware(MiddlewareMixin):
    """
    request_id 中间件
    - 优先使用上游传入的 X-Request-Id(用于网关/反代链路追踪)
    - 否则自动生成 uuid4.hex
    - 写入 request.request_id, 供日志与响应体使用
    - 在响应头回写 X-Request-Id, 便于客户端排查
    """
    # Djano 把请求头 X-Request-Id 映射为 META 的 HTTP_X_REQUEST_ID
    inbound_header_meta_key = "HTTP_X_REQUEST_ID"
    outbound_header_name = "x-Request-Id"
    
    def process_request(self, request):
        rid = request.META.get(self.inbound_header_meta_key) or uuid.uuid4().hex
        request.request_id = rid
        
    def process_response(self, request, response):
        rid = getattr(request, "request_id", None)
        if rid:
            response[self.outbound_header_name] = rid
        return response