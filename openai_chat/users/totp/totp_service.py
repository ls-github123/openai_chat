# === TOTP 函数化服务模块 ===
import json
from redis.exceptions import WatchError
from users.models import User # 自定义用户模型
from users.totp.totp_utils import (
    generate_totp_secret,
    get_totp_uri,
    generate_qr_image,
    encode_qr_image_to_base64,
    verify_totp_token
)
from openai_chat.settings.utils.redis import get_redis_client # Redis客户端封装
from openai_chat.settings.base import REDIS_DB_TOTP_QR_CACHE # TOTP二维码缓存 Redis 占用库
from openai_chat.settings.utils.logging import get_logger # 日志记录器
from openai_chat.settings.utils.locks import build_lock # RedLock分布式锁

logger = get_logger("users.totp")

# 二维码缓存过期时间
QR_EXPIRE_SECONDS = 300

TOTP_FAIL_LIMIT = 5 # 最多允许失败次数
TOTP_FAIL_WINDOW = 300 # 失败记录保留时间(秒)

# Redis Key 工具函数
def get_totp_fail_key(user_id: str) -> str:
    """
    生成 TOTP 失败计数 Redis Key
    """
    return f"totp:fail:{user_id}"

def get_totp_qr_key(user_id: str) -> str:
    """
    生成 TOTP 二维码 Redis 缓存 key
    """
    return f"totp:qrcode:{user_id}"

def get_totp_lock_key(user_id: str) -> str:
    """
    生成 RedLock 分布式锁 Redis Key
    """
    return f"lock:totp:{user_id}"

# Redis 限流操作
def check_totp_fail_limit(user_id: str, max_attempts: int = TOTP_FAIL_LIMIT) -> bool:
    """
    检查用户 TOTP 验证失败次数是否超限
    :param user_id: 用户唯一标识
    :param max_attempts: 最大尝试次数(默认5次)
    :return 是否超过限制(True表示已超限)
    """
    redis = get_redis_client(db=0)
    key = get_totp_fail_key(user_id)
    try:
        raw = redis.get(key)
        count = int(str(raw)) if raw else 0
        return count >= max_attempts
    except Exception as e:
        logger.error(f"[TOTP限流] 获取失败次数异常: {e}")
        return False

def record_totp_fail(user_id: str, expire_sec: int = TOTP_FAIL_WINDOW):
    """
    记录一次 TOTP 验证失败
    - 使用 Redis incr 自增计数器
    - 设置过期时间限制失败窗口
    """
    redis = get_redis_client(db=0)
    key = get_totp_fail_key(user_id)
    try:
        with redis.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(key)
                    current = redis.get(key)
                    # 开启事务
                    pipe.multi()
                    pipe.incr(key)
                    if current is None:
                        # 首次失败, 设置过期时间
                        pipe.expire(key, expire_sec)
                    pipe.execute()
                    break
                except WatchError:
                    continue # 乐观锁冲突重试
    except Exception as e:
        logger.error(f"[TOTP限流] TOTP验证码错误次数校验记录异常: {e}")
    
def clear_totp_fail(user_id: str):
    """
    清除用户失败次数 Redis 记录
    """
    redis = get_redis_client(db=0)
    try:
        redis.delete(get_totp_fail_key(user_id))
    except Exception as e:
        logger.warning(f"[TOTP缓存清理] 清除验证码校验失败计数异常: {e}")
    
def clear_totp_qrcode(user_id: str):
    """
    清除TOTP二维码 Redis 缓存
    """
    redis = get_redis_client(db=REDIS_DB_TOTP_QR_CACHE)
    try:
        redis.delete(get_totp_qr_key(user_id))
    except Exception as e:
        logger.warning(f"[TOTP缓存清理] 清除二维码缓存异常: {e}")
    
    
# 启用TOTP验证(首次绑定)
def init_totp(user: User) -> dict:
    """
    初始化 TOTP 启用流程:
    - 若已启用则直接返回False
    - 若 Redis 缓存中已有二维码 + secret, 一律返回缓存
    - 否则使用锁机制生成新的 secret 与二维码，并写入 Redis 缓存（作为预绑定）
    注: 仅在用户验证通过后再写入 Mysql
    """
    redis = get_redis_client(db=REDIS_DB_TOTP_QR_CACHE)
    qr_key = get_totp_qr_key(str(user.id))
    
    if user.totp_enabled:
        logger.info(f"[TOTP启用] 用户ID={user.id} 已启用TOTP, 无需重复绑定")
        return {"error": "您已启用TOTP, 无需重复操作"}
    
    # 二维码 + secret 缓存存在则直接返回
    try:
        cache_raw = redis.get(qr_key)
        if cache_raw:
            try:
                cache_data = json.loads(str(cache_raw))
                return {"qrcode": cache_data["qrcode"]}
            except Exception as e:
                logger.warning(f"[TOTP启用] 解析缓存内容异常: {e}")
    except Exception as e:
        logger.warning(f"[TOTP启用] 解析TOTP Redis缓存失败: {e}")
    
    # 缓存不存在, 则开始首次生成(使用分布式锁防止并发生成)
    with build_lock(get_totp_lock_key(str(user.id)), ttl=3000, strategy="safe"):
        try:
            # 首次启用流程
            totp_secret = generate_totp_secret() # 生成 TOTP 后端Secret密钥
            uri = get_totp_uri(totp_secret, user.email) # 构建 OTP URI, 用于生成二维码识别信息
            qr_image = generate_qr_image(uri) # 根据 OTP URI 生成二维码图像对象(PIL Image)
            qr_base64 = encode_qr_image_to_base64(qr_image) # 将二维码图像编码为 base64 字符串
            value = json.dumps({"qrcode": qr_base64, "secret": totp_secret})
            redis.set(qr_key, value, ex=QR_EXPIRE_SECONDS, nx=True)
            logger.info(f"[TOTP启用] 用户ID={user.id} 成功生成TOTP绑定二维码")
            return {"qrcode": qr_base64}
        except Exception as e:
            logger.error(f"[TOTP启用] 初始化异常: {e}")
            raise
    
# 验证绑定流程
def verify_and_bind_totp(user: User, token: str) -> bool:
    """
    验证并启用 TOTP(首次绑定流程)
    - 检查TOTP动态验证码失败次数是否超限(限流)
    - 从 Redis 中读取二维码缓存(包含二维码和密钥)
    - 使用缓存中的secret验证动态验证码
    - 校验成功后写入数据库并启用
    - 清除 Redis 缓存与失败计数
    """
    # 检查失败次数是否超限
    if check_totp_fail_limit(str(user.id)):
        logger.warning(f"[TOTP验证] 用户ID={user.id} 验证失败次数过多, 已被限流")
        return False
    
    redis = get_redis_client(db=REDIS_DB_TOTP_QR_CACHE)
    qr_key = get_totp_qr_key(str(user.id))
    cache_raw = redis.get(qr_key)
    
    if not cache_raw:
        logger.warning(f"[TOTP验证] 缓存不存在, 流程中断")
        return False
    
    try:
        totp_data = json.loads(str(cache_raw))
        totp_secret = totp_data.get("secret")
        if not totp_secret:
            logger.error(f"[TOTP验证] TOTP缓存中缺少 secret 字段")
            return False
    except Exception as e:
        logger.error(f"[TOTP验证] 解析Redis缓存异常: {e}")
        return False
    
    # 使用缓存中的 secret 校验 TOTP 动态验证码
    if not verify_totp_token(totp_secret, token):
        record_totp_fail(str(user.id))
        logger.warning(f"[TOTP验证] 用户ID={user.id} 动态验证码错误")
        return False
    
    clear_totp_fail(str(user.id)) # 清除校验失败次数记录
    clear_totp_qrcode(str(user.id)) # 清除TOTP二维码(含secret)缓存
    
    # 数据落库
    if not user.totp_enabled:
        user.totp_secret = totp_secret
        user.totp_enabled = True
        user.save(update_fields=["totp_secret", "totp_enabled"])
        logger.info(f"[TOTP验证] 用户ID={user.id} 成功启用TOTP二次验证")
        
    return True

# 解除TOTP绑定
def disabled_totp(user: User, token: str) -> bool:
    """
    解绑 TOTP
    - 校验是否已启用
    - 校验6位数动态验证码
    - 成功后清除 totp_secret 与 启用状态, 并清理失败计数
    """
    if not user.totp_enabled or not user.totp_secret:
        logger.warning(f"[TOTP解绑] 用户ID={user.id} 尚未启用TOTP, 无法解绑")
        return False
    
    if check_totp_fail_limit(str(user.id)):
        logger.warning(f"[TOTP解绑] 用户ID={user.id} 验证失败次数过多, 已被限流")
        return False
    
    if not verify_totp_token(user.totp_secret, token):
        record_totp_fail(str(user.id))
        logger.warning(f"[TOTP解绑] 用户ID={user.id} 验证码错误")
        return False
    
    clear_totp_fail(str(user.id)) # 清除用户失败次数 Redis 记录
    
    user.totp_secret = None
    user.totp_enabled = False
    user.save(update_fields=["totp_secret", "totp_enabled"])
    logger.info(f"[TOTP解绑] 用户ID={user.id} 成功解绑TOTP")
    return True

# 用户登录阶段 TOTP 验证
def verify_login_totp(user: User, token: str) -> bool:
    """
    登录阶段 TOTP 动态口令校验服务函数
    :param user: 当前用户对象
    :param token: 用户提交的6位动态验证码
    :return: 是否验证成功(True或False)
    """
    user_id = str(user.id)
    
    # 校验是否启用了 TOTP (二次验证)
    if not user.totp_enabled or not user.totp_secret:
        logger.warning(f"[TOTP登录校验] 用户ID={user_id} 未启用TOTP, 无需校验")
        return False
        
    # 限流判断, 失败次数是否超过限制
    if check_totp_fail_limit(user_id):
        logger.warning(f"[TOTP登录校验] 用户ID={user_id} 验证失败次数过多, 已被限流")
        return False
        
    # 验证6位动态口令是否正确
    if not verify_totp_token(user.totp_secret, token):
        record_totp_fail(user_id) # 记录1次失败次数
        logger.warning(f"[TOTP登录校验] 用户ID={user_id} 验证码错误")
        return False
    
    # 清除失败记录, 验证成功
    clear_totp_fail(user_id)
    logger.info(f"[TOTP登录校验] 用户ID={user_id} 登录二次验证TOTP验证通过")
    return True