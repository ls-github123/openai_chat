"""
JWT 鉴权认证模块: 自定义DRF认证器(Redis-only 状态校验版本)
- 1. 从 HTTP Header 中解析 JWT（Authorization: Bearer <token>）
- 2. 使用 Azure Key Vault 提供的 RS256 公钥验证 Token 签名与有效期
- 3. 校验 Token 基本字段（typ / jti / sub）
- 4. 基于 Redis 用户状态事实源(user:state:{uid})进行实时校验
- 5. 不查询数据库（Redis-only，高性能、低耦合）
- 6. 校验通过后，将用户上下文写入 request 对象供后续使用

=== 关键设计原则 ===
- JWT 认证阶段不访问数据库
- 用户是否"允许访问"由 Redis 事实源决定, 而非ORM状态
- Redis 中状态缺失视为不可信，直接拒绝访问（安全优先）
- 本模块只负责“是否允许访问”，不负责：
    - 登录 / 注册 / TOTP 校验
    - Token 签发 / 续签
    - 用户信息查询

=== request 上下文约定 ===
认证成功后，本认证器会向 request 注入以下属性：
- request.user_id      : int，当前用户ID（来自 JWT sub）
- request.user_state   : dict，Redis 中的用户状态快照
- request.jwt_payload  : dict，JWT 解码后的完整 payload
- request.jwt_token    : str，原始 access token

注意：
- request.user 返回 AnonymousUser（不查 DB）
- 接口权限应基于 request.user_id / request.user_state 判断
- 不应在 view 中再通过 request.user 访问 ORM User

=== 适用场景 ===
- 所有需要登录态的 API 接口
- 支持动态封禁 / 注销即时生效
- 支持后续多设备会话控制（sid/session）

=== 非目标 ===
- 本模块不处理 refresh token
- 不做 session/sid 校验（后续单独模块处理）
- 不做错误码语义细分（后续统一）
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional, Tuple, Any, Dict, cast
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from openai_chat.settings.utils.logging import get_logger
from .jwt_verifier import AzureRS256Verifier

from users.services.auth.state_guards import UserStateGuard
# Redis-only 用户状态校验:
# - 校验 is_active / is_deleted
# - Redis 缺失即拒绝
# - 不回源 DB

logger = get_logger("project.jwt")

@dataclass
class AuthenticatedUser:
    """
    轻量"已认证用户"对象(Redis-only 场景专用)
    - 不查询DB
    """
    id: int
    @property
    def is_authenticated(self) -> bool:
        return True

class JWTAuthentication(BaseAuthentication):
    """
    自定义 JWT 认证器(DRF)
    - access token 验签 + payload 校验
    - Redis-only 用户状态事实源校验
    - 不查询数据库
    """
    def authenticate(self, request) -> Optional[Tuple[Any, str]]:
        """
        DRF 认证入口:
        - Header 无 Bearer token: 返回 None
        - Bearer token 存在: 验签 + 校验 + 写入 request 上下文
        - 失败: 抛 AuthenticationFailed (DRF返回401)
        """
        auth_header = request.headers.get("Authorization", "")
        match = re.match(r"^Bearer\s+(.+)$", auth_header)
        if not match:
            return None
        
        token = match.group(1).strip()
        if not token:
            return None
        
        try:
            # 1.验签并获取 payload(AzureRS256Verifier 内部已处理签名/过期黑名单等)
            verifier = AzureRS256Verifier.get_instance()
            payload = cast(Dict[str, Any], verifier.verify(token))
            
            # 2.强制校验 token 类型: 仅允许 access
            if payload.get("typ") != "access":
                raise AuthenticationFailed("Token类型非法, 必须为 access 类型")
            
            # 3.校验 jti: 要求存在(黑名单逻辑通常在 verifier 内做, 这里仅做字段完整性检查)
            jti = payload.get("jti")
            if not jti:
                raise AuthenticationFailed("无效Token: 缺少jti字段")
            
            # 4.从 payload 提取 sub(用户ID)
            user_id = payload.get("sub")
            if not user_id:
                raise AuthenticationFailed("无效Token: 缺少sub字段")
            
            # 5.sub类型校验(必须为 int 可解析)
            try:
                uid_int = int(user_id)
            except Exception:
                raise AuthenticationFailed("无效Token: sub字段非法")
            
            # 6.Redis-only 用户状态校验(缺失/禁用/注销: 直接拒绝访问)
            state = UserStateGuard.ensure_user_state_allowed(uid_int, stage="jwt_auth")
            
            # 7.写入 request 上下文(供后续权限/业务层使用)
            request.user_id = uid_int # 当前请求的用户ID
            request.user_state = state # Redis 用户状态事实源
            request.jwt_payload = payload # JWT原始载荷
            request.jwt_token = token # access token原文
            
            # 8.不查询DB, 返回“已认证用户”占位对象
            return AuthenticatedUser(uid_int), token
        
        except AuthenticationFailed:
            # 已是 DRF 认可的认证异常, 直接抛出
            raise
        except Exception:
            # 其他异常统一记录 traceback, 避免泄露内部细节
            logger.exception("[JWTAuthentication] auth failed")
            raise AuthenticationFailed("认证失败")