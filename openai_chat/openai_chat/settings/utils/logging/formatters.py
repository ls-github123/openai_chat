from __future__ import annotations
import logging, json
from typing import Any, Dict
from pythonjsonlogger.jsonlogger import JsonFormatter # type: ignore

# LogRecord 自带字段（不属于 extra），不应被追加输出
_RESERVED_ATTRS = {
    "name", "msg", "args", "levelname", "levelno",
    "pathname", "filename", "module",
    "exc_info", "exc_text", "stack_info",
    "lineno", "funcName",
    "created", "msecs", "relativeCreated",
    "thread", "threadName",
    "processName", "process",
    "asctime",
    # --- 关键补充: 避免重复/污染 ---
    "message", # super().format 后会生成
    "taskName", # Celery/集成可能注入
}

def _safe_text(v: Any, *, max_len: int = 500) -> str:
    """
    将 extra 值安全转为单行文本(用于 kv 文本日志)
    - 防止换行污染
    - bytes 解码
    - 长度截断
    """
    if v is None:
        s = ""
    elif isinstance(v, (bytes, bytearray)):
        s = v.decode("utf-8", errors="replace")
    else:
        s = str(v)
    
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if len(s) > max_len:
        s = s[:max_len] + "...(truncated)"
    return s

def _safe_json_value(v: Any) -> Any:
    """
    将 extra 值安全转为 JSON 可序列化对象
    - 可序列化：原样返回
    - 不可序列化：转字符串
    """
    try:
        json.dumps(v, ensure_ascii=False, default=str)
        return v
    except Exception:
        return str(v)


class ExtraKVFormatter(logging.Formatter):
    """
    文本日志格式化器
    - 在原始 message 后追加 extra 字段(key=value)
    """
    def format(self, record: logging.LogRecord) -> str:
        # 父类 Formatter 生成基础日志文本
        base = super().format(record)
        
        # 从 record.__dict__提取 非保留字段
        extra: Dict[str, Any] = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _RESERVED_ATTRS and not k.startswith("_")
            and v not in (None, "", [], {}, ())
        }
        
        if not extra:
            return base
        
        # 追加为 key=value(适合人类阅读)
        extra_str = " ".join(f"{k}={_safe_text(extra[k])}" for k in sorted(extra.keys()))
        return f"{base} | {extra_str}"
    
class ExtraJSONFormatter(JsonFormatter):
    """
    JSON formatter: 显式把 extra 字段合并进 JSON, 保障可观测字段不丢失
    """
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        super().add_fields(log_record, record, message_dict)
        
        extra: Dict[str, Any] = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _RESERVED_ATTRS and not k.startswith("_")
            and v not in (None, "", [], {}, ())
        }
        for k, v in extra.items():
            # 避免覆盖已有字段
            if k not in log_record:
                log_record[k] = _safe_json_value(v)