# === TOTP 接口视图模块(启用、验证、解绑) ===
# REST API 接口, 支持 TOTP 启用、验证与注销
from typing import Any
from rest_framework.views import APIView # 基础API视图类
from rest_framework.response import Response # 标准响应封装
from rest_framework.permissions import IsAuthenticated # 权限控制类
from users.totp.totp_serializers import TOTPEnableSerializer, TOTPVerifySerializer # 引入序列化器
from users.totp.totp_utils import generate_totp_secret, get_totp_uri, generate_qr_image, verify_totp_token, get_qr_image_bytes, encode_qr_image_to_base64 # 核心工具函数
from django.conf import settings # 获取当前环境配置
from openai_chat.settings.base import REDIS_DB_TOTP_QR_CACHE # TOTP生成二维码缓存占用库(db=4)
from openai_chat.settings.utils.logging import get_logger # 导入日志记录器
from openai_chat.settings.utils.redis import get_redis_client # Redis 客户端封装
import base64

logger = get_logger("users.totp")

# === Redis 失败计数键生成器 ===
def get_totp_fail_key(user_id) -> str:
    return f"totp:fail:{user_id}"

# === 通用 Redis 校验函数 ===
def check_redis_fail_limit(redis, key: str, max_attempts: int = 5, expire_sec: int = 300):
    """
    Redis失败次数校验辅助函数
    - 若超过最大次数则返回Response对象
    - 否则返回None表示可继续
    """
    try:
        raw = redis.get(key)
        count = int(raw) if raw else 0
        if count >= max_attempts:
            return Response({"detail": "验证失败次数过多, 请稍后重试"}, status=429)
        return None
    except Exception as e:
        logger.critical(f"[TOTP限流校验] Redis连接失败: {str(e)}")
        return Response({"detail": "系统错误, 暂时无法完成验证"}, status=503)

def record_redis_failure(redis, key: str, expire_sec: int = 300):
    """
    Redis失败计数增加辅助函数
    - - 尝试incr并设置过期时间
    """
    try:
        redis.incr(key)
        redis.expire(key, expire_sec)
    except Exception as e:
        logger.error(f"[TOTP限流记录] Redis 写入失败: {str(e)}")

def clear_redis_key(redis, key: str):
    """
    Redis失败记录清除函数
    """
    try:
        redis.delete(key)
    except Exception as e:
        logger.error(f"[TOTP限流清除] Redis删除失败: {str(e)}")

# === 启用TOTP接口 ===
class TOTPEnableView(APIView):
    permission_classes = [IsAuthenticated] # IsAuthenticated-仅限登录用户访问
    
    def post(self, request):
        """
        用户请求启用TOTP
        - 若未启用则生成新密钥
        - 返回 base64 格式的二维码
        """
        user = request.user # 获取用户信息(DRF机制自动从JWT中解析并注入,保障安全)
        redis = get_redis_client(db=REDIS_DB_TOTP_QR_CACHE)
        qr_key = f"totp:qrcode:{user.id}"
        
        if user.totp_enabled:
            return Response({"detail": "您已启用 TOTP, 无需重复操作。"}, status=400)
        
        # 若已生成但尚未启用, 直接返回现有二维码, 避免重复生成 secret
        if user.totp_secret:
            cached_qr = redis.get(qr_key)
            if cached_qr:
                response_data = {"qrcode": cached_qr}
                if settings.DEBUG:
                    response_data["secret"] = user.totp_secret
                return Response(response_data)
            
            # 若无缓存, 重新生成二维码(但不重新生成 secret)
            uri = get_totp_uri(user.totp_secret, user.email)
            img = generate_qr_image(uri)
            qr_base64 = encode_qr_image_to_base64(img)
            
            # 写入 Redis 缓存(5分钟有效)
            redis.setex(qr_key, 300, qr_base64)
            response_data = {"qrcode": qr_base64}
            if settings.DEBUG:
                response_data["secret"] = user.totp_secret
            return Response(response_data)
        
        # 首次启用, 生成 secret 存入用户表
        secret = generate_totp_secret()
        user.totp_secret = secret
        user.save(update_fields=["totp_secret"])
        
        # 构建 URI 生成二维码图片并缓存
        uri = get_totp_uri(secret, user.email)
        img = generate_qr_image(uri)
        qr_base64 = base64.b64encode(get_qr_image_bytes(img)).decode()
        redis.setex(qr_key, 300, qr_base64)
        response_data = {"qrcode": qr_base64} # base64 PNG 图像, 可前端<img>显示
        # 根据环境决定是否返回密钥
        if settings.DEBUG:
            response_data["secret"] = secret # 仅开发环境返回密钥
        return Response(response_data)

# === 验证TOTP接口 ===
class TOTPVerifyView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        用户提交验证码进行绑定验证, 验证通过后标记为已启用
        """
        user = request.user
        redis_fail = get_redis_client(db=0) # Redis 错误计数库
        redis_qr = get_redis_client(db=REDIS_DB_TOTP_QR_CACHE) # TOTP二维码 Redis 缓存库 
        
        redis_fail_key = f"totp:fail:{user.id}"
        qr_key = f"totp:qrcode:{user.id}"
        
        # 校验失败计数
        response = check_redis_fail_limit(redis_fail, redis_fail_key)
        if response:
            return response
        
        # 执行 TOTP 验证码校验(使用序列化器)
        serializer = TOTPVerifySerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            record_redis_failure(redis_fail, redis_fail_key)
            logger.warning(f"[TOTP验证] 用户ID={user.id} 验证失败:{serializer.errors}")
            return Response(serializer.errors, status=400)
        
        # 若用户未启用TOTP, 则标记启用状态
        if not user.totp_enabled:
            user.totp_enabled = True
            user.save(update_fields=["totp_enabled"])
            logger.info(f"[TOTP验证] 用户ID={user.id} TOTP成功启用")
        
        # 验证成功后 清除 Redis 错误计数
        clear_redis_key(redis_fail, redis_fail_key)
        
        # 清除二维码缓存(避免再次获取已验证成功的二维码)
        clear_redis_key(redis_qr, qr_key)
        
        return Response({"detail": "TOTP验证通过"})
    
# === 解绑 TOTP 接口 ===
class TOTPDisableView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        提交 TOTP 验证码进行验证解绑
        - 成功后清除 TOTP 状态和失败计数
        """
        user = request.user
        token = request.data.get("token")
        redis_fail = get_redis_client(db=0)
        redis_key = f"totp:fail:{user.id}"
        
        # 若用户未启用 TOTP 直接返回错误
        if not user.totp_enabled or not user.totp_secret:
            return Response({"detail": "当前用户未启用 TOTP。"}, status=400)
        
        # 检查 Redis 防刷机制
        response = check_redis_fail_limit(redis_fail, redis_key)
        if response:
            return response
        
        # 验证 TOTP 令牌有效性
        if not token or not verify_totp_token(user.totp_secret, token):
            record_redis_failure(redis_fail, redis_key)
            return Response({"detail": "TOTP验证码错误, 无法解绑。"}, status=400)
        
        # 更新用户状态
        user.totp_secret = None
        user.totp_enabled = False
        user.save(update_fields=["totp_secret", "totp_enabled"])
        
        # 清除失败计数器
        clear_redis_key(redis_fail, redis_key)
        return Response({"detail": "TOTP 已成功解绑。"})