from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from openai_chat.settings.utils.response_wrapper import json_response
from users.services.logout_service import LogoutService # 退出登录服务类
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("users")

class LogoutView(APIView):
    """
    用户退出登录视图:
    - 接收当前登录 access_token + refresh_token, 加入黑名单
    - 要求用户已登录(IsAuthenticated)
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            # 获取 Authorization 头部
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return json_response(
                    code=400,
                    msg="无效的Token格式"
                )
            
            access_token = auth_header.replace("Bearer ", "").strip()
            refresh_token = request.data.get("refresh_token", "").strip()
            
            
            # 拉黑access token
            LogoutService(token=access_token, token_type="access").execute()
            # 若存在 refresh_token 也拉黑
            if refresh_token:
                LogoutService(token=refresh_token, token_type="refresh").execute()
            
            return json_response(code=200, msg="退出登录成功")
        
        except Exception as e:
            logger.warning(f"[LogoutView] 退出登录失败: {e}")
            return json_response(
                code=500,
                msg="退出登录失败",
                data={"detail": str(e)}
            )