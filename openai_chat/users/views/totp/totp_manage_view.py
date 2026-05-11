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
from users.totp import disabled_totp, init_totp, verify_and_bind_totp
from users.totp.totp_serializers import TOTPEnableSerializer, TOTPVerifySerializer

logger = get_logger("users.totp")

def _get_current_user(request: Request) -> User:
    """
    根据当前认证上下文获取真实 User ORM 对象
    - TOTP service 需要真实 User ORM 对象, View 层必须按 id 回表查询
    """
    raw_user = getattr(request, "user", None)
    user_id = getattr(raw_user, "id", None) or getattr(request, "user_id", None)
    
    if not user_id:
        logger.warning("[TOTPView] missing authenticated user_id")
        raise AppException.unauthorized(
           code=ErrorCodes.AUTH_INVALID_USER,
           message="用户身份无效，请重新登录",
        )
    try:
        uid = int(user_id)
    except Exception as exc:
        logger.warning("[TOTPView] invalid authenticated user_id=%r", user_id)
        raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_USER,
            message="用户身份无效，请重新登录",
        ) from exc
    user = (
        User.objects.only(
            "id",
            "email",
            "is_active",
            "is_deleted",
            "totp_enabled",
            "totp_secret",
        )
        .filter(id=uid, is_active=True, is_deleted=False)
        .first()
    )
    if not user:
        logger.warning("[TOTPView] user missing or disabled user_id=%s", uid)
        raise AppException.unauthorized(
            code=ErrorCodes.AUTH_INVALID_USER,
            message="用户不存在或状态已失效",
        )
    return cast(User, user)

class TOTPInitView(APIView):
    """
    初始化 TOTP 绑定流程
    
    使用场景:
    - 已登录用户进入“开启二次验证”页面
    - 后端生成临时 TOTP secret 和二维码
    - secret 暂存在 Redis，暂不写入 MySQL
    - 用户后续必须调用 TOTPConfirmView 并输入验证码，验证通过后才正式启用
    
    边界:
    - 必须为已登录用户
    - 返回二维码 base64
    - 返回 manual_secret, 供无法扫码的用户手动录入认证器
    - manual_secret 属于敏感信息，前端只临时展示，不写入本地存储或日志
    - 二维码/secret 由 service 层写入短 TTL Redis 缓存
    """
    # 仅允许已通过 JWT / Session 认证的用户访问
    # 不允许匿名用户调用
    permission_classes = [IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """
        请求体:
        - 无需字段, 用户身份信息来自 access token
        
        响应:
        - qrcode: base64 PNG, 不带 data:image/png;base64, 前缀
        - manual_secret: 手动录入认证器时使用的 TOTP secret，仅允许前端临时展示
        """
        serializer = TOTPEnableSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # 必须获取真实 User ORM 对象，不能直接使用 request.user
        user = _get_current_user(request)
        
        result: Dict[str, str] = init_totp(user)
        
        error = result.get("error")
        if error:
            logger.warning(
                "[TOTPInitView] rejected user_id=%s reason=%s",
                user.id,
                error,
            )
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message=error,
            )
        
        qrcode = result.get("qrcode")
        manual_secret = result.get("manual_secret")
        if not qrcode or not manual_secret:
            logger.error(
                "[TOTPInitView] init returned incomplete data user_id=%s",
                getattr(user, "id", None),
            )
            raise AppException.internal_error(
                code=ErrorCodes.SYSTEM_INTERNAL_ERROR,
                message="TOTP初始化失败, 请稍后重试",
            )
        
        logger.info("[TOTPInitView] qrcode issued user_id=%s", user.id)
        
        return json_response(
            success=True,
            code=ErrorCodes.SUCCESS,
            message="TOTP初始化成功",
            data={
                "qrcode": qrcode,
                "manual_secret": manual_secret,
            },
            http_status=status.HTTP_200_OK,
        )
    
class TOTPConfirmView(APIView):
    """
    确认绑定TOTP
    
    使用场景:
    - 用户扫描 TOTPInitView 返回的二维码后
    - 输入认证器 App 生成的 6 位验证码
    - 验证通过后，service 层正式写入 user.totp_secret / user.totp_enabled
    - 启用成功后提升 sess_ver，使旧 token 立即失效
    
    安全边界:
    - 必须为已登录用户
    - 写操作由 service 层使用用户级分布式锁保护
    - 数据库写入和 sess_ver 提升由 service 层事务保护
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """
        请求体:
        - token: 6位 TOTP 动态验证码
        """
        serializer = TOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        validated_data = cast(Dict[str, Any], serializer.validated_data)
        token = str(validated_data["token"]).strip()
        user = _get_current_user(request)
        
        ok = verify_and_bind_totp(user, token)
        if not ok:
            logger.warning("[TOTPConfirmView] rejected user_id=%s", user.id)
            raise AppException.bad_request(
                code=ErrorCodes.AUTH_TOTP_INVALID,
                message="TOTP验证码错误、已过期或初始化状态失效",
            )
        
        logger.info("[TOTPConfirmView] enabled user_id=%s", user.id)
        
        return json_response(
            success=True,
            code=ErrorCodes.SUCCESS,
            message="TOTP验证启用成功",
            data={
                "totp_enabled": True,
            },
            http_status=status.HTTP_200_OK,
        )

class TOTPDisableView(APIView):
    """
    解绑TOTP
    
    使用场景:
    - 已登录用户在账户安全设置中关闭 TOTP
    - 用户必须提供当前已绑定 secret 对应的 6 位动态验证码
    - 验证通过后，service 层清空 user.totp_secret 并关闭 user.totp_enabled
    - 解绑成功后提升 sess_ver，使旧 token 立即失效
    
    安全边界:
    - 必须为已登录用户
    - 不允许只凭 access token 直接解绑，必须再次验证 TOTP
    - 写操作由 service 层使用用户级分布式锁保护
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request: Request) -> Response:
        """
        请求体:
        - token: 6 位 TOTP 动态验证码
        """
        serializer = TOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        validated_data = cast(Dict[str, Any], serializer.validated_data)
        token = str(validated_data["token"]).strip()
        user = _get_current_user(request)

        ok = disabled_totp(user, token)
        if not ok:
            logger.warning("[TOTPDisableView] rejected user_id=%s", user.id)
            raise AppException.bad_request(
                code=ErrorCodes.AUTH_TOTP_INVALID,
                message="TOTP验证码错误、已超出最大尝试次数或当前未启用TOTP",
            )

        logger.info("[TOTPDisableView] disabled user_id=%s", user.id)

        return json_response(
            success=True,
            code=ErrorCodes.SUCCESS,
            message="TOTP解绑成功",
            data={
                "totp_enabled": False,
            },
            http_status=status.HTTP_200_OK,
        )