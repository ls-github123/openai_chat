# === TOTP 服务模块 ===
"""
TOTP 服务层功能

1.初始化绑定流程:
   - 生成临时 TOTP secret
   - 生成认证器 App 可扫描的二维码
   - 将 secret + qrcode 写入 Redis 预绑定缓存
   - 注意: 此阶段不写 MySQL, 只有用户输入验证码验证通过后才正式落库

2.验证并绑定:
   - 从 Redis 读取预绑定 secret
   - 校验用户提交的 6 位 TOTP 动态码
   - 校验成功后写入用户表
   - 启用 TOTP 后提升 sess_ver, 使旧 token 立即失效
   - 数据库保存和 sess_ver 提升都成功后, 清理 Redis 预绑定缓存、失败计数、用户信息缓存

3.解绑:
   - 校验当前已绑定 secret 对应的 TOTP 动态码
   - 校验成功后清空用户表中的 TOTP 字段
   - 解绑 TOTP 后提升 sess_ver, 使旧 token 立即失效
   - 数据库保存和 sess_ver 提升成功后, 清理 Redis 缓存

4.登录阶段TOTP校验:
   - 校验用户已启用 TOTP
   - 校验动态码
   - 处理失败计数和限流

设计原则:
  - Redis key 统一通过函数生成, 避免散落字符串
  - TOTP 失败计数使用专用 Redis DB, 不污染锁库 db=0
  - 初始化绑定时加锁后必须二次读取缓存, 避免并发生成不一致二维码
  - 数据库保存成功后再清理 Redis 缓存, 避免 secret 丢失
  - 对外仍返回 bool/dict, 兼容现有调用
"""
from __future__ import annotations
import json
from typing import Any, Dict, Optional, TypedDict, cast
from django.db import transaction
from redis import Redis

from openai_chat.settings.base import (
    REDIS_DB_TOTP_FAIL,
    REDIS_DB_TOTP_QR_CACHE,
    TOTP_FAIL_LIMIT,
    TOTP_FAIL_WINDOW_SECONDS,
    TOTP_ISSUER_NAME,
    TOTP_LOCK_TTL_MS,
    TOTP_QR_EXPIRE_SECONDS,
)
from openai_chat.settings.utils.locks import build_lock
from openai_chat.settings.utils.logging import get_logger
from openai_chat.settings.utils.redis import get_redis_client
from users.models import User
from users.services.user_info_service import UserInfoService
from users.services.user_state_service import UserStateService
from users.totp.totp_utils import (
    encode_qr_image_to_base64,
    generate_qr_image,
    generate_totp_secret,
    get_totp_uri,
    verify_totp_token,
)

logger = get_logger("users.totp")

class TOTPSetupCache(TypedDict):
    """
    Redis 预绑定缓存结构

    qrcode:
        前端直接渲染用的 base64 PNG 字符串, 不含
        "data:image/png;base64," 前缀

    secret:
        当前预绑定流程生成的 TOTP secret
        注: 敏感值, 只允许短 TTL 存在 Redis 中, 不应写入日志
    """
    qrcode: str
    secret: str

def get_totp_fail_key(user_id: str) -> str:
    """
    生成 TOTP 验证失败计数 key
    
    - 按 user_id 计数
    - 绑定、解绑、登录共用一个失败窗口
    """
    return f"totp:fail:{user_id}"

def get_totp_qr_key(user_id: str) -> str:
    """
    生成 TOTP 预绑定缓存 key
    - key 保存 qrcode + secret, TTL 较短
    """
    return f"totp:setup:{user_id}"

def get_totp_lock_key(user_id: str) -> str:
    """
    生成 TOTP 用户级互斥锁 key
    - 防止同一用户并发初始化绑定, 生成多个不同 secret
    - 防止绑定确认、解绑等写操作互相覆盖
    """
    return f"lock:totp:{user_id}"

def _to_str(raw: Any) -> str:
    """
    统一转换 redis bytes为 str, 便于 json.loads/int 处理
    """
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("utf-8", errors="ignore")
    return str(raw)

def _get_qr_redis() -> Redis:
    """
    获取 TOTP 预绑定二维码缓存 Redis 客户端
    """
    return get_redis_client(db=REDIS_DB_TOTP_QR_CACHE)

def _get_fail_redis() -> Redis:
    """
    获取 TOTP 失败计数 Redis 客户端
    
    注:
    - 失败计数不再使用 db=0
    - db=0 在本项目中是锁相关用途
    """
    return get_redis_client(db=REDIS_DB_TOTP_FAIL)

def _load_setup_cache(redis: Redis, key: str) -> Optional[TOTPSetupCache]:
    """
    从 Redis 读取并解析 TOTP 预绑定缓存

    返回:
    - None: 缓存不存在、格式损坏、字段缺失
    - dict: 合法的 qrcode + secret

    说明:
    - 格式损坏时不直接抛异常, 调用方可以选择重新生成或直接失败
    - 日志只记录 key 和错误, 不记录 secret
    """
    raw = redis.get(key)
    if not raw:
        return None
    
    try:
        data = json.loads(_to_str(raw))
    except Exception as exc:
        logger.warning("[TOTPSetup] parse cache failed key=%s err=%s", key, exc)
        return None
    
    if not isinstance(data, dict):
        logger.warning("[TOTPSetup] invalid cache type key=%s type=%s", key, type(data))
        return None
    
    qrcode = str(data.get("qrcode", "")).strip()
    secret = str(data.get("secret", "")).strip()
    
    if not qrcode or not secret:
        logger.warning("[TOTPSetup] cache missing qrcode/secret key=%s", key)
        return None
    
    return {"qrcode": qrcode, "secret": secret}

def _save_setup_cache(redis: Redis, key: str, value: TOTPSetupCache) -> bool:
    """
    写入 TOTP 预绑定缓存
    
    使用 nx=True:
    - 防止锁异常或并发情况下覆盖已有 secret
    - 返回 True 表示当前调用成功写入
    - 返回 False 表示 key 已存在, 调用方应重新读取 Redis 中的真实缓存
    """
    payload = json.dumps(value, ensure_ascii=False)
    return bool(redis.set(key, payload, ex=TOTP_QR_EXPIRE_SECONDS, nx=True))

def check_totp_fail_limit(user_id: str, max_attempts: int = TOTP_FAIL_LIMIT) -> bool:
    """
    检查 TOTP 失败次数是否达到限制
    
    返回 True:
    - 已达到或超过 max_attempts
    - 调用方应拒绝继续校验, 避免暴力尝试
    
    Redis 异常策略:
    - 当前为了兼容现有登录链路, Redis 异常时 fail-open 返回 False
    - 如果要更严格的生产安全策略, 可以改为 fail-closed, 即异常时拒绝验证
    """
    redis = _get_fail_redis()
    key = get_totp_fail_key(user_id)
    
    try:
        raw = redis.get(key)
        count = int(_to_str(raw)) if raw else 0
        return count >= max_attempts
    except Exception as exc:
        logger.error("[TOTPRateLimit] get fail count failed user_id=%s err=%s", user_id, exc)
        return False

def record_totp_fail(user_id: str, expire_sec: int = TOTP_FAIL_WINDOW_SECONDS) -> int:
    """
    记录一次 TOTP 验证失败
    
    返回:
    - 当前失败次数
    - Redis 异常时返回 0, 兼容旧逻辑
    """
    redis = _get_fail_redis()
    key = get_totp_fail_key(user_id)
    
    try:
        count = cast(int, redis.incr(key))
        if count == 1:
            redis.expire(key, expire_sec)
        else:
            ttl = cast(int, redis.ttl(key))
            if ttl < 0:
                redis.expire(key, expire_sec)
        return count
    except Exception as exc:
        logger.error("[TOTPRateLimit] record fail failed user_id=%s err=%s", user_id, exc)
        return 0

def clear_totp_fail(user_id: str) -> None:
    """
    清除用户 TOTP 失败计数
    
    调用时机:
    - 绑定验证成功
    - 解绑验证成功
    - 登录二阶段验证成功
    """
    redis = _get_fail_redis()
    try:
        redis.delete(get_totp_fail_key(user_id))
    except Exception as exc:
        logger.warning("[TOTPRateLimit] clear fail count failed user_id=%s err=%s", user_id, exc)

def clear_totp_qrcode(user_id: str) -> None:
    """
    清除 TOTP 预绑定二维码缓存
    """
    redis = _get_qr_redis()
    
    try:
        redis.delete(get_totp_qr_key(user_id))
    except Exception as exc:
        logger.warning("[TOTPSetup] clear setup cache failed user_id=%s err=%s", user_id, exc)

def _invalidate_user_info_cache(user_id: str) -> None:
    """
    清理用户信息缓存
    - user_info 缓存中包含 totp_enabled
    - 启用/解绑 TOTP 后如果不清理缓存，前端可能在 TTL 内看到旧状态
    - UserInfoService.invalidate_cache 内部已处理 Redis 异常，这里不阻断主流程
    """
    UserInfoService.invalidate_cache(user_id)

def init_totp(user: User) -> Dict[str, str]:
    """
    初始化 TOTP 绑定流程
    
    返回:
    - {"qrcode": "...", "manual_secret": "..."}: 成功返回二维码 base64 和手动录入 secret
    - {"error": "..."}: 兼容旧调用方式, 由 View 决定如何输出
    """
    user_id = str(user.id)
    
    if user.totp_enabled:
        logger.info("[TOTPSetup] already enabled user_id=%s", user_id)
        return {"error": "您已启用TOTP, 无需重复操作"}

    redis = _get_qr_redis()
    qr_key = get_totp_qr_key(user_id)
    
    # 避免每次刷新绑定页都重新加锁和生成二维码
    cached = _load_setup_cache(redis, qr_key)
    if cached:
        return {
            "qrcode": cached["qrcode"],
            "manual_secret": cached["secret"],
        }
    
    # 用户级分布式锁
    with build_lock(get_totp_lock_key(user_id), ttl=TOTP_LOCK_TTL_MS, strategy="safe"):
        # 锁内二次读取:
        # 请求 A 可能已经在锁内写入缓存并释放锁
        # 请求 B 获锁后如果不二次读取, 就会再次生成 secret
        cached = _load_setup_cache(redis, qr_key)
        if cached:
            return {
                "qrcode": cached["qrcode"],
                "manual_secret": cached["secret"],
            }

        try:
            totp_secret = generate_totp_secret()
            uri = get_totp_uri(
                secret=totp_secret,
                username=user.email,
                issuer_name=TOTP_ISSUER_NAME,
            )
            qr_image = generate_qr_image(uri)
            qr_base64 = encode_qr_image_to_base64(qr_image)

            setup_cache: TOTPSetupCache = {
                "qrcode": qr_base64,
                "secret": totp_secret,
            }
            
            # nx=True 为最后一道并发保护
            # 即使锁实现异常或外部并发写入, 也不会覆盖已有 secret
            # 只有 saved=True 时, 当前生成的二维码才和 Redis 中的 secret 一致
            saved = _save_setup_cache(redis, qr_key, setup_cache)
            if saved:
                logger.info("[TOTPSetup] setup cache created user_id=%s", user_id)
                return {
                    "qrcode": qr_base64,
                    "manual_secret": totp_secret,
                }
            
            # 如果 nx 写入失败, 必须重新读取 Redis 中真实存在的缓存并返回
            cached = _load_setup_cache(redis, qr_key)
            if cached:
                logger.info("[TOTPSetup] setup cache reused after nx conflict user_id=%s", user_id)
                return {
                    "qrcode": cached["qrcode"],
                    "manual_secret": cached["secret"],    
                }

            logger.error("[TOTPSetup] nx conflict but cache missing user_id=%s", user_id)
            return {"error": "TOTP初始化失败, 请稍后重试"}

        except Exception as exc:
            logger.exception("[TOTPSetup] setup failed user_id=%s err=%s", user_id, exc)
            raise

def verify_and_bind_totp(user: User, token: str) -> bool:
    """
    验证用户输入的 TOTP 动态码, 并正式启用 TOTP
    
    顺序:
    1. 检查是否已启用
    2. 检查失败次数是否超限
    3. 从 Redis 读取预绑定 secret
    4. 校验 token
    5. 数据库事务内写入 user.totp_secret / user.totp_enabled
    6. 在同一事务中提升 sess_ver
    7. 数据库保存成功后清理 TOTP Redis 缓存和 user_info 缓存
    """
    user_id = str(user.id)
    token = str(token or "").strip()
    
    if user.totp_enabled:
        logger.info("[TOTPBind] already enabled user_id=%s", user_id)
        clear_totp_fail(user_id)
        clear_totp_qrcode(user_id)
        # 幂等返回成功时清理 user_info, 避免缓存仍显示 totp_enabled=False
        _invalidate_user_info_cache(user_id)
        return True
    
    if check_totp_fail_limit(user_id):
        logger.warning("[TOTPBind] rejected by fail limit user_id=%s", user_id)
        return False
    
    redis = _get_qr_redis()
    qr_key = get_totp_qr_key(user_id)
    
    setup_cache = _load_setup_cache(redis, qr_key)
    if not setup_cache:
        logger.warning("[TOTPBind] setup cache missing or invalid user_id=%s", user_id)
        return False
    
    totp_secret = setup_cache["secret"]
    
    if not verify_totp_token(totp_secret, token):
        count = record_totp_fail(user_id)
        logger.warning("[TOTPBind] bad token user_id=%s fail_count=%s", user_id, count)
        return False
    
    # 绑定 - 敏感写操作
    # 使用用户级分布式锁保护
    # - 防止同一用户并发提交绑定确认
    # - 防止绑定和解绑并发互相覆盖
    with build_lock(get_totp_lock_key(user_id), ttl=TOTP_LOCK_TTL_MS, strategy="safe"):
        try:
            with transaction.atomic():
                locked_user = cast(User, User.objects.select_for_update().get(id=user.id))
                
                # 并发幂等:
                # 如果另一个请求已经成功启用 TOTP, 当前请求不再重复写库或重复提升 sv
                if locked_user.totp_enabled:
                    logger.info("[TOTPBind] enabled by concurrent request user_id=%s", user_id)
                else:
                    locked_user.totp_secret = totp_secret
                    locked_user.totp_enabled = True
                    locked_user.save(update_fields=["totp_secret", "totp_enabled"])
                    
                    # 提升sess_ver, 使启用前签发的 access/refresh token 全部失效
                    UserStateService.invalidate_sessions(
                        int(locked_user.id),
                        reason="totp_enabled",
                    )
        except Exception as exc:
            logger.exception("[TOTPBind] db save failed user_id=%s err=%s", user_id, exc)
            raise
    
    clear_totp_fail(user_id)
    clear_totp_qrcode(user_id)
    _invalidate_user_info_cache(user_id)
    
    logger.info("[TOTPBind] enabled user_id=%s", user_id)
    return True

def disabled_totp(user: User, token: str) -> bool:
    """
    解绑 TOTP
    
    注:
    - 当前只要求 TOTP 动态码
    - 更高安全等级可要求重新输入密码或最近登录确认
    - 解绑成功后提升 session version, 使旧 token 失效
    """
    user_id = str(user.id)
    token = str(token or "").strip()
    
    if not user.totp_enabled or not user.totp_secret:
        logger.warning("[TOTPDisable] not enabled user_id=%s", user_id)
        return False
    
    if check_totp_fail_limit(user_id):
        logger.warning("[TOTPDisable] rejected by fail limit user_id=%s", user_id)
        return False
    
    if not verify_totp_token(user.totp_secret, token):
        count = record_totp_fail(user_id)
        logger.warning("[TOTPDisable] bad token user_id=%s fail_count=%s", user_id, count)
        return False
    
    # 解绑为敏感写操作:
    # 修改 sess_ver, 失效旧 token
    with build_lock(get_totp_lock_key(user_id), ttl=TOTP_LOCK_TTL_MS, strategy="safe"):
        try:
            with transaction.atomic():
                # 行锁保护当前用户 TOTP 状态, 避免并发解绑/绑定覆盖
                locked_user = cast(User, User.objects.select_for_update().get(id=user.id))
                
                # 并发幂等
                # 如果另一个请求已解绑成功, 当前请求无需重复提升sv
                if not locked_user.totp_enabled:
                    logger.info("[TOTPDisable] already disabled user_id=%s", user_id)
                else:
                    locked_user.totp_secret = None
                    locked_user.totp_enabled = False
                    locked_user.save(update_fields=["totp_secret", "totp_enabled"])
                    
                    UserStateService.invalidate_sessions(
                        int(locked_user.id),
                        reason="totp_disabled",
                    )
        except Exception as exc:
            logger.exception("[TOTPDisable] db save or sv bump failed user_id=%s err=%s", user_id, exc)
            raise
    
    clear_totp_fail(user_id)
    clear_totp_qrcode(user_id)
    _invalidate_user_info_cache(user_id)
    
    logger.info("[TOTPDisable] disabled user_id=%s", user_id)
    return True

def verify_login_totp(user: User, token: str) -> bool:
    """
    登录阶段 TOTP 校验
    
    当前保持 bool 返回, 兼容 LoginTOTPVerifyService
    
    True:
    - 验证通过
    
    False:
    - 未启用 TOTP
    - secret 缺失
    - token 格式错误
    - token 校验失败
    - 失败次数超限
    """
    user_id = str(user.id)
    token = str(token or "").strip()
    
    if not user.totp_enabled or not user.totp_secret:
        logger.warning("[TOTPLogin] not enabled user_id=%s", user_id)
        return False
    
    if check_totp_fail_limit(user_id):
        logger.warning("[TOTPLogin] rejected by fail limit user_id=%s", user_id)
        return False
    
    if not verify_totp_token(user.totp_secret, token):
        count = record_totp_fail(user_id)
        logger.warning("[TOTPLogin] bad token user_id=%s fail_count=%s", user_id, count)
        return False
    
    clear_totp_fail(user_id)
    logger.info("[TOTPLogin] verified user_id=%s", user_id)
    return True