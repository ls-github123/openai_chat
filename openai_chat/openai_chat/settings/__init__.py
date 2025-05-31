from openai_chat.settings.utils.logging import build_logging # 导入日志处理器模块封装
import logging.config

# === 日志模块初始化配置 ===
logging.config.dictConfig(build_logging()) # 初始化日志配置(确保settings阶段日志可用)
LOGGING = build_logging() # 设置LOGGING变量,供Django使用