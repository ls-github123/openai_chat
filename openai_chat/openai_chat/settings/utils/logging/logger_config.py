"""
Django logging 配置构建器
- 纯函数：build_logging(conf) -> dict（不读环境变量、不 print）
- 严格 root 策略: root/file_project 以 ROOT_LEVEL 过滤(默认 INFO)

支持:
- ConcurrentRotatingFileHandler（多进程安全写入）
- 文件滚动策略（MAX_BYTES / BACKUP_COUNT）
- 控制台输出（ENABLE_CONSOLE）
- JSON / 文本格式（PREFER_JSON）
- logger -> 文件映射（FILES，同文件复用同 handler）
- logger -> level 映射（LEVELS）
- root 兜底（project.log）
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

# 模块级缓存: 解决 Pylance 对 function attribute 的报错
_LOGGING_CACHE: Optional[Tuple[Tuple[Any, ...], Dict[str, Any]]] = None

def _file_handler(
    *,
    filename: str,
    level: str,
    formatter: str,
    max_bytes: int,
    backup_count: int,
) -> Dict[str, Any]:
    return {
        # 多进程安全文件滚动处理器
        "class": "concurrent_log_handler.ConcurrentRotatingFileHandler",
        "filename": filename, # 日志文件路径
        "maxBytes": max_bytes, # 最大文件大小
        "backupCount": backup_count, # 备份文件数量
        "encoding": "utf-8", # 文件编码
        "level": level, # 日志级别
        "formatter": formatter, # 格式化器
    }

def _sanitize_handler_name(file_name: str) -> str:
    # 将文件名转换为合法的 handler 名称
    s = file_name.lower().replace(".", "_").replace("-", "_").replace(" ", "_")
    return "".join(ch for ch in s if ch.isalnum() or ch == "_")

def _conf_fingerprint(conf: Mapping[str, Any]) -> Tuple[Any, ...]:
    """
    生成稳定指纹,用于缓存
    - 只取关键字段，避免 Path/对象导致不可 hash
    """
    log_dir = str(Path(conf.get("LOG_DIR", Path.cwd() / "logs")).resolve())
    enable_console = bool(conf.get("ENABLE_CONSOLE", False))
    prefer_json = bool(conf.get("PREFER_JSON", False))
    max_bytes = int(conf.get("MAX_BYTES", 10 * 1024 * 1024))
    backup_count = int(conf.get("BACKUP_COUNT", 5))
    root_level = str(conf.get("ROOT_LEVEL", "INFO")).upper()
    
    levels = tuple(
        sorted((str(k), str(v).upper()) for k, v in (conf.get("LEVELS") or {}).items())
    )
    files = tuple(
        sorted((str(k), str(v)) for k, v in (conf.get("FILES") or {}).items())
    )
    
    return (
        log_dir,
        enable_console,
        prefer_json,
        max_bytes,
        backup_count,
        root_level,
        levels,
        files
    )


def build_logging(conf: Mapping[str, Any]) -> Dict[str, Any]:
    """ 
    构建 Django LOGGING dictConfig 配置
    
    参数字段:
      - LOG_DIR: Path|str
      - ENABLE_CONSOLE: bool
      - PREFER_JSON: bool
      - MAX_BYTES: int
      - BACKUP_COUNT: int
      - ROOT_LEVEL: str
      - LEVELS: dict[str, str]
      - FILES: dict[str, str]   # logger_name -> file_name（可多个 logger 指向同一文件）
    """
    global _LOGGING_CACHE
    
    key = _conf_fingerprint(conf)
    if _LOGGING_CACHE and _LOGGING_CACHE[0] == key:
        return _LOGGING_CACHE[1]
    
    log_dir = Path(conf.get("LOG_DIR", Path.cwd() / "logs")).resolve()
    enable_console = bool(conf.get("ENABLE_CONSOLE", False)) # 是否启用控制台输出
    prefer_json = bool(conf.get("PREFER_JSON", False))
    max_bytes = int(conf.get("MAX_BYTES", 10 * 1024 *1024))
    backup_count = int(conf.get("BACKUP_COUNT", 5))
    root_level = str(conf.get("ROOT_LEVEL", "INFO")).upper()
    
    levels: Dict[str, str] = {
        str(k): str(v).upper()
        for k, v in (conf.get("LEVELS") or {}).items()
    }
    files: Dict[str, str] = {
        str(k): str(v)
        for k, v in (conf.get("FILES") or {}).items()
    }
    
    # 目录存在性检查
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # 默认格式化器配置
    default_formatter = "json" if prefer_json else "verbose_extra"
    
    # 格式化器配置
    formatters: Dict[str, Any] = {
        "verbose": { # 详细格式化器
            "format": "[{asctime}] [{levelname}] [{name}] {message}", # 详细格式
            "style": "{",
        },
        # verbose_extra - 自动输出 extra(文本 key=value)
        "verbose_extra": {
            "()": "openai_chat.settings.utils.logging.formatters.ExtraKVFormatter",
            "format": "[{asctime}] [{levelname}] [{name}] {message}",
            "style": "{",
        },
        "simple": { # 简单格式化器
            "format": "{levelname}: {message}",
            "style": "{",
        },
        "json": { # JSON 格式化器
            "()": "openai_chat.settings.utils.logging.formatters.ExtraJSONFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(process)d %(threadName)s %(message)s",
        },
    }
    
    # handler: root 兜底文件 + 动态文件 handler + 可选 console
    handlers: Dict[str, Any] = {}
    
    # 根日志文件 handler (严格 root 策略)
    handlers["file_project"] = _file_handler(
        filename=str(log_dir / "project.log"),
        level=root_level, # 根日志级别
        formatter=default_formatter,
        max_bytes=max_bytes,
        backup_count=backup_count,
    )
    
    if enable_console: # 可选控制台 handler
        handlers["console"] = {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": default_formatter,
        }
    
    # 为 FILES 中出现的“文件名”去重创建 handler（同文件复用）
    # file_name -> handler_name
    file_to_handler: Dict[str, str] = {}
    for file_name in sorted(set(files.values())):
        safe = _sanitize_handler_name(file_name)
        handler_name = f"file_{safe}"
        file_to_handler[file_name] = handler_name
        handlers[handler_name] = _file_handler(
            filename=str(log_dir / file_name),
            level="NOTSET", # level=NOTSET，由 logger.level 负责过滤
            formatter=default_formatter,
            max_bytes=max_bytes,
            backup_count=backup_count,
        )
    
    def _handlers_for_logger(logger_name: str) -> list[str]:
        hs: list[str] = []
        
        mapped = files.get(logger_name)
        # 如果该 logger 映射到某文件, 挂载对应 file handler
        if mapped and mapped in file_to_handler:
            hs.append(file_to_handler[mapped])
        else:
            # 没有映射则直接走 root file_project
            hs.append("file_project")
        if enable_console:
            hs.append("console")
        
        return hs
    
    # 关键修复：用 LEVELS ∪ FILES 的并集生成 loggers，确保 FILES 映射一定生效
    logger_names = set(levels.keys()) | set(files.keys())
    # loggers: 为 LEVELS 的 logger 建立配置: handlers 由 files 决定
    loggers: Dict[str, Any] = {}
    
    for logger_name in sorted(logger_names):
        level = levels.get(logger_name, root_level)
        loggers[logger_name] = {
            "handlers": _handlers_for_logger(logger_name),
            "level": level,
            "propagate": False,
        }
    
    root_handlers: list[str] = ["file_project"]
    if enable_console:
        root_handlers.append("console")
    # 关键 -> root logger 兜底(处理未显式声明的logger)
    config: Dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters,
        "handlers": handlers,
        "root": {
            "handlers": root_handlers,
            "level": root_level,
        },
        "loggers": loggers,
    }
    
    _LOGGING_CACHE = (key, config)
    return config

def get_logger(name: str) -> logging.Logger:
    """
    获取 logger(不注入 handler)
    - 若项目未配置 dictConfig，Django 会走 root/basicConfig
    """
    return logging.getLogger(name)