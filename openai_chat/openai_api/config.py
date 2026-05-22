"""
OpenAI API 管理模块配置
"""
from openai_chat.settings.config import get_config

# === OpenAI API 管理模块配置 ===
OPENAI_API = {
    # 默认 provider 标识，用于后续支持 OpenAI / Azure OpenAI / 代理网关等多 provider
    "DEFAULT_PROVIDER": get_config(
        "OPENAI_DEFAULT_PROVIDER",
        default="openai",
    ),
    
    # OpenAI API 基础地址
    "OPENAI_API_BASE_URL": get_config(
        "OPENAI_API_BASE_URL",
        default="https://api.openai.com/v1",
    ),
    
    # 默认模型
    "DEFAULT_MODEL": get_config(
        "OPENAI_DEFAULT_MODEL",
        default="",
        allow_blank=True,
    ),
    
    # HTTP 请求超时时间
    "TIMEOUT_SECONDS": int(get_config(
        "OPENAI_TIMEOUT_SECONDS",
        default="60",
    )),
    
    # OpenAI API 调用失败重试次数(网络抖动、限流等可重试错误)
    "MAX_RETRIES": int(get_config(
        "OPENAI_MAX_RETRIES",
        default="2",
    )),
    
    # 单次请求最大输出 tokens
    "MAX_OUTPUT_TOKENS": int(get_config(
        "OPENAI_MAX_OUTPUT_TOKENS",
        default="4096",
    )),
    
    # 是否启用调用日志
    "USAGE_LOG_ENABLED": get_config(
        "OPENAI_USAGE_LOG_ENABLED",
        default="true",
    ).lower() == "true",
    
    # 是否记录 prompt 内容, 生产环境默认不记录
    "LOG_PROMPT_CONTENT": get_config(
        "OPENAI_LOG_PROMPT_CONTENT",
        default="false",
    ).lower() == "true",
    
    # 用户级限流窗口(秒)
    "USER_RATE_LIMIT_WINDOW_SECONDS": int(get_config(
        "OPENAI_USER_RATE_LIMIT_WINDOW_SECONDS",
        default="20",  
    )),
    
    # 单用户每个窗口最大请求数
    "USER_RATE_LIMIT_MAX_REQUESTS": int(get_config(
        "OPENAI_USER_RATE_LIMIT_MAX_REQUESTS",
        default="20",
    )),
    
    # 管理类接口锁TTL(毫秒)
    "CONFIG_LOCK_TTL_MS": int(get_config(
        "OPENAI_CONFIG_LOCK_TTL_MS",
        default="5000",
    )),
}