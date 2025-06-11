import pyotp # 生成和验证一次性密码的 Python 库
import qrcode # 二维码生成库
from qrcode.image.pil import PilImage # 使用PIL工厂生成图像
from qrcode.constants import ERROR_CORRECT_M
from PIL import Image # 图像处理库
from typing import Optional
import base64 # Base64 编码工具
from io import BytesIO # 内存缓存, 用于redis存储

# 默认二维码尺寸参数
DEFAULT_BOX_SIZE = 10
DEFAULT_BORDER = 4

def generate_totp_secret() -> str:
    """
    生成 TOTP 密钥(Base32 编码), 用于绑定用户的动态口令应用
    :return: Base32 编码的 TOTP 密钥字符串
    """
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str, issuer_name: str = "OpenAI-Chat") -> str:
    """
    构建 OTP URI, 用于生成二维码识别信息
    示例: otpauth://totp/OpenAI-Chat:user@example.com?secret=XXXX&issuer=OpenAI-Chat
    :param secret: TOTP 密钥
    :param username: 用户标识，一般为邮箱
    :param issuer_name: 应用名称(显示在 TOTP 应用中)
    :return: OTP URI 字符串
    """
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

def generate_qr_image(uri: str, box_size: int = DEFAULT_BOX_SIZE, border: int = DEFAULT_BORDER) -> Image.Image:
    """
    根据 OTP URI 生成二维码图像对象(PIL Image), 用于后续 base64 编码或 Redis 缓存
    （支持动态调整模块尺寸和边框）
    :param uri: OTP URI 字符串
    :param box_size: 单个二维码模块大小(像素), 值越大二维码越大(默认10)
    :param border: 二维码图像边框宽度(单位: 模块数)
    :return: PIL Image 图像对象
    """
    try:
        qr = qrcode.QRCode(
            version=None, # 自动适应内容长度
            error_correction=ERROR_CORRECT_M,
            box_size=box_size,
            border=border
        )
        qr.add_data(uri)
        qr.make(fit=True)
        return qr.make_image(image_factory=PilImage).get_image()
    except (ValueError, TypeError, OSError) as e:
        raise RuntimeError(f"二维码生成失败: {e}, 请稍后重试") from e

def verify_totp_token(secret: Optional[str], token: Optional[str]) -> bool:
    """
    校验用户提交的 TOTP 动态验证码
    支持 ±1 时间窗口容错
    :param secret: 用户绑定的 TOTP 密钥
    :param token: 用户输入的6位动态验证码
    :return: 校验结果(True-成功, False-失败)
    """
    if not secret or not token or not token.isdigit() or len(token) != 6:
        return False # 缺失或非法验证码，直接返回失败
    
    try:
        totp = pyotp.TOTP(secret) # 创建 TOTP 实例
        return totp.verify(token, valid_window=1) # 容忍前后时间窗口(避免同步偏差)
    except Exception:
        return False

def get_qr_image_bytes(img: Image.Image) -> bytes:
    """
    将 PIL 图像转换为原始 PNG 二进制流（可用于 Redis 等缓存场景）
    :param img: PIL 图像对象
    :return: PNG 格式的字节流数据
    """
    # 使用上下文管理器自动释放内存
    with BytesIO() as buffer:
        img.save(buffer, format='PNG')
        return buffer.getvalue()

def encode_qr_image_to_base64(img: Image.Image) -> str:
    """
    将二维码图像编码为 base64 字符串，供前端 img 标签直接渲染使用
    :param img: PIL 图像对象
    :return: base64 字符串（不含前缀）
    """
    return base64.b64encode(get_qr_image_bytes(img)).decode()


__all__ = [
    "generate_totp_secret", # 生成 TOTP 密钥
    "get_totp_uri", # 构建 OTP URI
    "generate_qr_image", # 生成二维码 PIL 图像
    "verify_totp_token", # 验证动态口令
    "get_qr_image_bytes", # 图像转字节流
    "encode_qr_image_to_base64", # 图像转base64
]