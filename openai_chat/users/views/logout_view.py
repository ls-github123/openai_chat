from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from openai_chat.settings.utils.response_wrapper import json_response
from users.services.logout_service import LogoutService # 退出登录服务类
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("users")

class LogoutView(APIView):
    """
    用户退出登录视图:
    - 用户必须为已登录用户
    - 自动获取access_token(来自 Authorization)
    - refresh_token来自post请求体手动提交
    - 退出时强制双 token 同时加入JWT黑名单
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            # 获取 DRF 认证注入的access_token
            access_token = request.auth
            if not access_token:
                return json_response(code=400, msg="未检测到有效access_token")
            
            # 获取请求体中的 refresh_token
            refresh_token = request.data.get("refresh_token", "").strip()
            if not refresh_token:
                return json_response(code=400, msg="缺少 refresh_token")
            if not isinstance(refresh_token, str):
                return json_response(code=400, msg="refresh_token格式非法")
            
            # 拉黑 access_token
            LogoutService(token=access_token, token_type="access").execute()
            
            # 拉黑 refresh_token
            LogoutService(token=refresh_token, token_type="refresh").execute()
            
        except Exception as e:
            logger.warning(f"[LogoutView] 退出登录失败: {e}")
            return json_response(
                code=500,
                msg="退出登录失败",
                data={"detail": str(e)}
            )