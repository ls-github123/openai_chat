from __future__ import annotations
from typing import Any, Dict, cast
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from openai_chat.settings.utils.error_codes import ErrorCodes
from openai_chat.settings.utils.exceptions import AppException
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.response_wrapper import json_response

from users.models import User
from users.serializers.user_info_serializer import UserInfoResponseSerializer
from users.services.user_info_service import UserInfoService

logger = get_logger("users")

class UserInfoView(APIView):
    """
    当前登录用户信息获取视图
    
    接口:
    - GET /users/userinfo/
    
    边界:
    - View 层只负责读取当前认证用户、调用 service、返回统一响应
    - UserInfoService 负责缓存读取、DB 回源、字段构造
    - UserInfoResponseSerializer 负责输出字段白名单和响应结构校验
    """
    # 显式声明需要登录
    permission_classes = [IsAuthenticated]
    
    def get(self, request: Request) -> Response:
        """
        获取当前登录用户的基础信息
        
        用户身份来源:
        - JWTAuthentication 成功后注入 request.user
        - 不从 query/body 接收 user_id，避免越权查询其他用户信息
        """
        user = cast(User, request.user)
        user_id = getattr(user, "id", None)
        
        if not user_id:
            logger.warning("[UserInfoView] missing authenticated user_id")
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_USER,
                message="用户身份无效，请重新登录",
            )
        
        # 只查询当前认证用户信息
        # enforce_db_filters=True 过滤 is_active=False / is_deleted=True 用户
        # 启用普通用户信息缓存
        raw_user_info: Dict[str, Any] = UserInfoService.get_user_info(
            user_id,
            enforce_db_filters=True,
        )
        
        if not raw_user_info:
            logger.warning("[UserInfoView] user info unavailable user_id=%s", user_id)
            raise AppException.unauthorized(
                code=ErrorCodes.AUTH_INVALID_USER,
                message="用户不存在或状态已失效",
            )
        
        # service/cache 中即使混入额外字段，也会在 serializer 中被白名单过滤
        # serializer 同时会校验响应结构，避免脏数据返回给前端
        user_info = UserInfoResponseSerializer.from_service(raw_user_info)
        
        logger.debug("[UserInfoView] user info returned user_id=%s", user_id)
        
        return json_response(
            success=True,
            code=ErrorCodes.SUCCESS,
            message="获取用户信息成功",
            data=user_info,
            http_status=status.HTTP_200_OK,
        )