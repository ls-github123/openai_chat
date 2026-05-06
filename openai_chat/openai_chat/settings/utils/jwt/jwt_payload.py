"""
JWT payload 构造模块

目标:
- 1. 统一 access / refresh 的 payload 结构，减少散落逻辑
- 2. 与项目现有能力对齐：黑名单(jti)、全局会话失效(sv)、TOTP 风控(amr)
- 3. 最小暴露：只放认证/授权必需字段，不放 PII（如 email/phone）
- 4. 保持可扩展：支持 sid（单会话粒度）、rti（refresh 链路标识）等

注:
- 时间均使用 UTC Unix秒时间戳(int)
"""
from __future__ import annotations
import time, uuid
from typing import Any, Dict, Iterable, Optional, Sequence
from django.conf import settings

# === 辅助: 统一读取配置 ===
def _cfg_str(name: str, default: str) -> str:
    """读取字符串配置并兜底"""
    v = getattr(settings, name, default)
    return str(v).strip() or default

def _cfg_int(name: str, default: int) -> int:
    """读取整型配置并兜底"""
    try:
        return int(getattr(settings, name, default))
    except Exception:
        return int(default)

# === 辅助: 字段规范化 ===
def _normalize_scope(scope: Optional[str], token_type: str) -> str:
    """
    规范化 scope:
    - refresh token 固定 scope=refresh（避免权限语义混淆）
    - access token 默认走配置 JWT_SCOPE_DEFAULT
    """
    if token_type == "refresh":
        return "refresh"
    return (scope or _cfg_str("JWT_SCOPE_DEFAULT", "user")).strip()

def _normalize_amr(amr: Optional[Sequence[str]]) -> list[str]:
    """
    规范化 amr(认证方法):
    - 去空白
    - 去重且保持顺序
    """
    if not amr:
        return ["pwd"]
    
    seen = set()
    out: list[str] = []
    for item in amr:
        s = str(item).strip().lower()
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    
    return out or ["pwd"]

def _normalize_sid(sid: Optional[str]) -> str:
    """
    规范化 sid(会话ID):
    - 若外部未提供, 则自动生成一个 UUID 字符串
    """
    s = (sid or "").strip()
    return s if s else str(uuid.uuid4())

def _normalize_rti(rti: Optional[str], token_type: str) -> Optional[str]:
    """
    规范化 rti(refresh token chain id):
    - 仅 refresh token 有意义
    - 若 refresh 且未提供，则自动生成
    """
    if token_type != "refresh":
        return None
    s = (rti or "").strip()
    return s if s else str(uuid.uuid4())

def _validate_token_type(token_type: str) -> None:
    """校验 token_type 合法值。"""
    if token_type not in {"access", "refresh"}:
        raise ValueError("token_type must be 'access' or 'refresh'")


def _validate_lifetime(lifetime: int) -> None:
    """校验生命周期为正整数。"""
    if not isinstance(lifetime, int) or lifetime <= 0:
        raise ValueError("lifetime must be a positive int (seconds)")


def _to_int_or_default(value: Any, default: int) -> int:
    """尽量转 int，失败回默认值。"""
    try:
        return int(value)
    except Exception:
        return int(default)

# === 对外主函数 ===
def build_jwt_payload(
    *,
    user_id: str,
    token_type: str = "access",
    scope: Optional[str] = None,
    lifetime: Optional[int] = None,
    sess_ver: Optional[int] = None,
    sid: Optional[str] = None,
    amr: Optional[Sequence[str]] = None,
    rti: Optional[str] = None,
    # 预留：可覆盖时间（测试/回放场景）
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """
    构造 JWT payload 主函数
    
    参数:
    - user_id: 用户ID（会被转为字符串写入 sub）
    - token_type: access / refresh
    - scope: access token 的权限范围；refresh 会被固定为 refresh
    - lifetime: 有效期（秒）；若不传按 token_type 读取配置
    - sess_ver: 会话版本号（sv），用于全局失效；默认至少为1
    - sid: 会话ID；不传自动生成 UUID
    - amr: 认证方式列表；不传默认 ["pwd"]
    - rti: refresh链路ID；仅 refresh 使用，不传则自动生成
    - now_ts: 可选，外部指定当前时间戳（便于测试）
    
    返回:
    - 标准化 payload dict
    """
    _validate_token_type(token_type)
    
    # 1. 时间基准(秒)
    now = int(now_ts if now_ts is not None else time.time())
    
    # 2. 动态确定 lifetime
    if lifetime is None:
        if token_type == "access":
            lifetime = _cfg_int("JWT_ACCESS_TOKEN_LIFETIME", 900) # 默认15分钟
        else:
            lifetime = _cfg_int("JWT_REFRESH_TOKEN_LIFETIME", 7 * 24 * 3600) # 默认7天
    
    if lifetime is None:
        raise ValueError("lifetime cannot be None")
    
    lifetime = int(lifetime)
    _validate_lifetime(lifetime)
    
    # 3. 核心字段规范化
    sub = str(user_id).strip()
    if not sub:
        raise ValueError("user_id must not be empty")
    
    sv = _to_int_or_default(sess_ver, 1)
    if sv < 1:
        sv = 1
    
    normalize_scope = _normalize_scope(scope, token_type)
    normalize_sid = _normalize_sid(sid)
    normalize_amr = _normalize_amr(amr)
    normalize_rti = _normalize_rti(rti, token_type)
    
    # 4. 组装 payload
    payload: Dict[str, Any] = {
        # 标准注册声明(RFC7519)
        "iss": _cfg_str("JWT_ISSUER", "openai-chat.xyz"), # 签发者
        "aud": _cfg_str("JWT_AUDIENCE", "openai_chat_user"), # 接收者
        "sub": sub, # 用户ID
        "iat": now, # 签发时间
        "nbf": now, # 生效时间
        "exp": now + lifetime, # 过期时间
        "jti": str(uuid.uuid4()), # JWT ID, JWT唯一标识
        # 项目扩展自定义声明
        "typ": token_type, # 令牌类型: access / refresh
        "scope": normalize_scope, # 权限范围
        "sv": sv, # 会话版本号
        "sid": normalize_sid, # 会话ID
        "amr": normalize_amr, # 认证方法
    }
    
    # 5. refresh token 特有字段
    if normalize_rti is not None:
        payload["rti"] = normalize_rti
    
    return payload