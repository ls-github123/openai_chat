"""
接口幂等性基础设施模块(Redis)
- 用于防止写接口被重复提交造成重复副作用
- 采用 Redis + Lua 实现原子判重/状态机/结果缓存
- 建议只在 Service 层调用，View 只负责透传 Idempotency-Key

Key 规范：
- idem:v1:<scope>:<idempotency_key>

状态机：
- PENDING：首次请求占位（处理中）
- SUCCEEDED：业务已成功完成，缓存 result（用于重复请求复用）
- FAILED：业务失败（短 TTL），允许后续重试
"""
import json, time
from dataclasses import dataclass # 用数据类表达 lua 返回的结构化结果
from typing import Any, Callable, Dict, Optional, Tuple # 类型注解
from openai_chat.settings.utils.redis import get_redis_client # 获取redis客户端
from openai_chat.settings.base import REDIS_DB_IDEMPOTENCY # 幂等性专用 Redis DB
from openai_chat.settings.utils.logging import get_logger

logger = get_logger("project.redis")

class IdempotencyInProgressError(Exception):
    """同一幂等 key 的请求正在处理中"""
    
class IdempotencyKeyConflictError(Exception):
    """
    幂等 key 已被使用且结果不可用/格式异常（理论上很少见）。
    通常用于提示调用方更换 Idempotency-Key
    """

@dataclass(frozen=True)
class IdemReadResult:
    """
    Lua 脚本读写结果：
    - action:
        - "NEW": 本次成功占位（写入 PENDING），调用方应继续执行业务
        - "DONE": 已有 SUCCEEDED，可直接返回 cached_result
        - "PENDING": 已在处理中，调用方应抛出 IdempotencyInProgressError
        - "FAILED": 上次失败，允许重试（调用方可选择继续执行业务）
    - cached_result_json: 若已 DONE，返回缓存结果 JSON
    """
    action: str
    cached_result_json: Optional[str]
    
class IdempotencyExecutor:
    """
    幂等执行器(Service层调用)
    - execute(): 自动完成 begin -> run -> commit 流程
    """
    # key 前缀与版本
    KEY_PREFIX: str = "idem:v1"
    
    # 默认 TTL(秒)
    DEFAULT_TTL_SECONDS: int = 10 * 60 # 10分钟
    
    # 失败状态 TTL(秒): 失败不应长期阻塞重试
    FAILED_TTL_SECONDS: int = 60 # 1分钟(可按接口调整)
    
    # Lua 脚本: 原子判断 + 写入 PENDING 或读取已缓存结果
    # 返回：
    # - "NEW" / "DONE" / "PENDING" / "FAILED"
    # - cached_result_json（仅 DONE 时返回）
    _LUA_BEGIN = r"""
local key = KEYS[1]
local pending_value = ARGV[1]
local ttl = tonumber(ARGV[2])

local v = redis.call("GET", key)
if not v then
  -- 不存在：占位 PENDING
  redis.call("SET", key, pending_value, "EX", ttl, "NX")
  return {"NEW", ""}
end

-- 存在：解析 JSON，读 state
local ok, obj = pcall(cjson.decode, v)
if not ok or (type(obj) ~= "table") or (not obj["state"]) then
  return {"CONFLICT", ""}
end

local state = obj["state"]
if state == "SUCCEEDED" then
  local r = obj["result"]
  if r == nil then
    return {"DONE", ""}
  end
  return {"DONE", cjson.encode(r)}
elseif state == "PENDING" then
  return {"PENDING", ""}
elseif state == "FAILED" then
  return {"FAILED", ""}
else
  return {"CONFLICT", ""}
end
"""
    
    def __init__(self) -> None:
        # 幂等性专用 Redis 客户端(独立DB)
        self._redis = get_redis_client(db=REDIS_DB_IDEMPOTENCY)
        
        # 预加载 Lua 脚本到 Redis(服务启动后首次使用会完成脚本加载)
        self._begin_script = self._redis.register_script(self._LUA_BEGIN)
        
    def _build_key(self, scope: str, idem_key: str) -> str:
        return f"{self.KEY_PREFIX}:{scope}:{idem_key}"
    
    def begin(self, scope: str, idem_key: str, ttl_seconds: int) -> IdemReadResult:
        """开始幂等: 原子判重 + 占位"""
        redis_key = self._build_key(scope=scope, idem_key=idem_key)
        now = int(time.time())
        pending_payload = {
           "state": "PENDING",
           "ts": now,
        }
        
        try:
            ret = self._begin_script(
              keys=[redis_key],
              args=[json.dumps(pending_payload, ensure_ascii=False), str(ttl_seconds)],
            )
        except Exception as e:
            logger.exception("[IdempotencyExecutor]Idempotency begin failed (redis error). scope=%s key=%s", scope, idem_key)
            raise
        
        # ---显式校验 Lua 返回结构, 消除 IDE/类型检查报红, 保障运行安全---
        if not isinstance(ret, (list, tuple)) or len(ret) < 2:
            logger.error("[IdempotencyExecutor]Unexpected lua return. scope=%s key=%s ret=%r", scope, idem_key, ret)
            raise IdempotencyKeyConflictError("invalid idempotency lua return")
        
        raw_action, raw_cached = ret[0], ret[1]
        
        action = raw_action.decode() if isinstance(raw_action, (bytes, bytearray)) else str(raw_action)
        cached = raw_cached.decode() if isinstance(raw_cached, (bytes, bytearray)) else str(raw_cached)
        
        if action == "NEW":
          return IdemReadResult(action="NEW", cached_result_json=None)
        if action == "DONE":
          return IdemReadResult(action="DONE", cached_result_json=cached if cached else None)
        if action == "PENDING":
          return IdemReadResult(action="PENDING", cached_result_json=None)
        if action == "FAILED":
          return IdemReadResult(action="FAILED", cached_result_json=None)
        if action == "CONFLICT":
          raise IdempotencyKeyConflictError(f"idempotency key conflict: {redis_key}")
        
        # 理论兜底
        raise IdempotencyKeyConflictError(f"unknown idempotency action: {action}")
    
    def succeed(self, scope: str, idem_key: str, result: Dict[str, Any], ttl_seconds: int) -> None:
        """
        标记成功, 并缓存 result
        """
        redis_key = self._build_key(scope=scope, idem_key=idem_key)
        payload = {
          "state": "SUCCEEDED",
          "ts": int(time.time()),
          "result": result,
        }
        self._redis.set(redis_key, json.dumps(payload, ensure_ascii=False), ex=ttl_seconds)
        
    def fail(self, scope: str, idem_key: str, error: Optional[Dict[str, Any]] = None) -> None:
        """
        标记失败(短TTL), 允许后续重试
        注: 不要写入敏感错详情, 建议只写入 error_code 等公开信息
        """
        redis_key = self._build_key(scope=scope, idem_key=idem_key)
        payload = {
          "state": "FAILED",
          "ts": int(time.time()),
        }
        if error:
            payload["error"] = error
        self._redis.set(redis_key, json.dumps(payload, ensure_ascii=False), ex=self.FAILED_TTL_SECONDS)
    
    def execute(
      self,
      *,
      scope: str,
      idem_key: str,
      ttl_seconds: int,
      func: Callable[[], Dict[str, Any]],
      allow_retry_after_failed: bool = True,
      ) -> Dict[str, Any]:
          """
          幂等执行器(service调用入口)
          - func 必须返回 dict(最终响应或关键结果) 
          """
          if not scope or not idem_key:
            # 幂等key缺失
            raise ValueError("scope and idem_key are required for idempotency")
          
          if ttl_seconds <= 0:
              ttl_seconds = self.DEFAULT_TTL_SECONDS
          
          read = self.begin(scope=scope, idem_key=idem_key, ttl_seconds=ttl_seconds)
          
          if read.action == "DONE":
              if read.cached_result_json:
                  try:
                      return json.loads(read.cached_result_json)
                  except Exception:
                      # 缓存损坏: 视为冲突, 强制客户端更换key
                      raise IdempotencyKeyConflictError("cached result json corrupted")
              return {}
          
          if read.action == "PENDING":
              raise IdempotencyInProgressError(f"idempotency request in progress: {scope}:{idem_key}")
          
          if read.action == "FAILED" and not allow_retry_after_failed:
              raise IdempotencyInProgressError(f"idempotency last failed (retry disabled): {scope}:{idem_key}")
          
          
          # NEW 或 FAILED(允许重试) -> 执行业务
          try:
              result = func()
              if not isinstance(result, dict):
                  raise TypeError("idempotency func() must return dict")
          except Exception as e:
              # 业务异常: 写 FAILED, 允许后续重试(短TTL)
              self.fail(scope=scope, idem_key=idem_key, error={"code": "BUSINESS_ERROR"})
              raise
          
          # 成功: 写 SUCCEEDED 并缓存结果
          self.succeed(scope=scope, idem_key=idem_key, result=result, ttl_seconds=ttl_seconds)
          return result