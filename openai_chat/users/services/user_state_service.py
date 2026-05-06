"""
---用户状态事实源构建与同步模块---
本模块负责将用户的核心状态（是否启用 / 是否删除）同步到 Redis,
作为接口鉴权阶段的“事实源(Source of Truth)”。

关键设计：
1) 账户状态（长期）
   - is_active / is_deleted 属于账户生命周期字段
   - 不应被“退出登录/下线”复用
2) 会话全局失效（全端下线 / 改密强制重登 / 后台一键下线）
   - 使用 sess_ver（全局会话版本号）
   - 原理：JWT payload 携带 sv（签发时读取的 sess_ver）
           鉴权时比较 sv == state.sess_ver，不一致则 token 失效（401）
3) 本模块只负责“事实源写入/维护”，不做权限判断、不抛鉴权异常
   - 但对于关键写操作（invalidate_sessions），写失败必须上抛 AppException，让上层回滚/重试

Redis 设计：
- DB: REDIS_DB_USERS_STATE
- Key: user:state:{user_id}
- Type: Hash
- Fields:
  - is_active: 0/1
  - is_deleted: 0/1
  - sess_ver: int（全局会话版本号，默认 1，单调递增）
  - updated_at: int（同步时间戳）
  - session_invalidated_at: int（可选审计字段：最近一次全局下线时间）
  - session_invalidated_reason: str（可选审计字段：原因）
"""
from __future__ import annotations # 延迟类型注解解析
import time
from dataclasses import dataclass # 简化服务类定义
from typing import Optional, cast

from users.models import User # 用户模型
from openai_chat.settings.utils.logging import get_logger
from redis import Redis
from openai_chat.settings.base import REDIS_DB_USERS_STATE # 用户状态事实源 Redis占用库
from openai_chat.settings.utils.redis import get_redis_client

from openai_chat.settings.utils.exceptions import AppException # 统一业务异常
from openai_chat.settings.utils.error_codes import ErrorCodes # 统一错误码

logger = get_logger("users")

# frozen=True：不可变对象; slots=True：减少内存开销、属性访问更快
@dataclass(frozen=True, slots=True)
class UserState:
    """
    用户状态数据类
    - sess_ver 为全局会话版本号：用于全终端失效控制
    """
    is_active: bool
    is_deleted: bool
    updated_at: int
    sess_ver: int
    # 审计字段
    session_invalidated_at: Optional[int] = None
    session_invalidated_reason: Optional[str] = None

class UserStateService:
    """
    用户状态事实源(Redis) 服务类
    - state key 长期存在, 不设置 TTL(由写入覆盖更新)
    - sess_cer: 
      - 登录/刷新 签发JWT时读取该值写入 payload.sv
      - 重置密码/敏感操作后对 sess_ver 执行 bump, 前期所有签发 token 立即失效
    - 读取: 鉴权 guards(Redis-only)
    """
    key_prefix = "user:state:" # Redis Key 前缀
    
    @classmethod
    def _key(cls, user_id: int) -> str:
        """生成 Redis key"""
        return f"{cls.key_prefix}{user_id}"
    
    @staticmethod
    def _now_ts() -> int:
        """
        统一秒级时间戳入口
        """
        return int(time.time())
    
    @staticmethod
    def _redis_sync(db: int) -> Redis:
        """
        获取同步 Redis 客户端，并在类型层面明确为 redis.Redis
        - 解决项目内同步/异步客户端并存导致的 Awaitable|int 类型污染
        """
        return cast(Redis, get_redis_client(db=db))
        
    # Redis 读取(轻量读取 sess_ver)
    @classmethod
    def get_sess_ver(cls, user_id: int) -> int:
        """
        从 Redis 读取 sess_ver (用于登录/刷新签发 JWT 时写入 payload.sv)
        - 若 key 或字段不存在: 返回 1
        - 读取失败：返回 1 (避免签发流程因 Redis 字段异常崩溃)
        """
        r = cls._redis_sync(REDIS_DB_USERS_STATE)
        key = cls._key(int(user_id))
        
        try:
            raw = r.hget(key, "sess_ver")
            if raw is None:
                return 1
            # Redis 返回可能为 bytes 或 str 或 int, 统一转 int
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8")
            raw_str = str(raw).strip()
            return int(raw_str) if raw_str else 1
        except Exception:
            # 读取失败时, 保守处理: 返回 1(避免登录流程因 Redis 字段异常直接崩)
            return 1
    
    # 构建 stste
    @classmethod
    def build_state(
        cls,
        user: User,
        *,
        sess_ver: int,
        session_invalidated_at: Optional[int] = None,
        session_invalidated_reason: Optional[str] = None,
    ) -> UserState:
        """
        根据 User 实例构建 UserState 对象
        参数:
        - sess_ver:
          - 默认 1: 首次初始化/未查到时采用
          - 若用户已在 Redis 中存在 sess_ver，应先读取后再传入，避免覆盖
        """
        return UserState(
            is_active=bool(getattr(user, "is_active", True)),
            is_deleted=bool(getattr(user, "is_deleted", False)),
            updated_at=cls._now_ts(), # 秒级时间戳
            sess_ver=int(sess_ver),
            session_invalidated_at=int(session_invalidated_at) if session_invalidated_at is not None else None,
            session_invalidated_reason=str(session_invalidated_reason) if session_invalidated_reason else None,
        )
    
    
    @classmethod
    def sync_to_redis(cls, user: User) -> None:
        """
        将用户状态同步到 Redis(事实源)
        - 只写入, 不做权限判断
        - 同步时“尽量保留已有 sess_ver”，避免把已 bump 的版本号覆盖回 1
        
        注:
        - 本模块不设置 TTL, state key 属于"长期事实源"
        - sess_ver 是全局会话版本：应保持单调递增，不应在 sync 时回退
        """
        user_id = int(getattr(user, "id"))
        key = cls._key(user_id)
        r = cls._redis_sync(REDIS_DB_USERS_STATE)
        
        # 读取当前 sess_ver, 避免 sync 覆盖回默认值
        current_sess_ver = cls.get_sess_ver(user_id)
        state = cls.build_state(user, sess_ver=current_sess_ver)
        
        payload: dict[str, object] = {
            # 账户是否启用(默认为1/True, 由DB决定)
            "is_active": 1 if state.is_active else 0,
            # 账户是否已注销/软删除(默认为0/False)
            "is_deleted": 1 if state.is_deleted else 0,
            # 全局会话版本号(全局会话失效控制关键字段)
            "sess_ver": state.sess_ver,
            # 状态同步时间
            "updated_at": state.updated_at,
        }
        
        # 不主动覆盖 session_invalidated_* 字段
        r.hset(key, mapping=payload)
        
        logger.info(
            "[UserStateService] synced user state user_id=%s is_active=%s is_deleted=%s sess_ver=%s",
            user_id,
            payload["is_active"],
            payload["is_deleted"],
            payload["sess_ver"],
        )
        
    
    # 通用: 全局下线(全端强制重新登录 / 后台一键下线)
    @classmethod
    def invalidate_sessions(cls, user_id: int, *, reason: str) -> int:
        """
        全局会话失效:
        - 不修改 is_active (避免把“下线”做成“禁用账号”)
        - 通过 sess_ver++ 使所有旧 token 立即失效 (鉴权时 sv != sess_ver -> 401)
        
        参数:
        - reason: 必填, 用于审计与排查(例: admin_force_logout / password_reset)
        
        返回:
        - 新的 sess_ver(int)
        
        失败处理:
        - 写失败抛 AppException（上层应回滚/重试）
        """
        uid = int(user_id)
        if not reason or not str(reason).strip():
            raise AppException.bad_request(
                code=ErrorCodes.COMMON_INVALID_PARAMS,
                message="reason 参数不能为空",
            )
        
        r = cls._redis_sync(REDIS_DB_USERS_STATE)
        key = cls._key(uid)
        now_ts = cls._now_ts()
        reason_norm = str(reason).strip()[:128]
        
        try:
            # 使用 pipeline 保证两次写入以事务方式提交
            pipe = r.pipeline(transaction=True)
            pipe.hincrby(key, "sess_ver", 1)
            # 写入审计字段
            pipe.hset(
                key,
                mapping={
                    "session_invalidated_at": now_ts,
                    "session_invalidated_reason": reason_norm,
                    "updated_at": now_ts,
                },
            )
            res = pipe.execute()
            
            # res[0] 为 hincrby 的返回值(int)
            new_ver = int(res[0])
            
            logger.info(
                "[UserStateService] invalidate_sessions user_id=%s new_sess_ver=%s reason=%s",
                uid,
                new_ver,
                reason_norm,
            )
            return new_ver
        
        except AppException:
            raise
        except Exception as e:
            logger.error(
                "[UserStateService] invalidate_sessions failed user_id=%s reason=%s err=%r",
                uid,
                reason_norm,
                e,
            )
            raise AppException.internal_error(
                code=ErrorCodes.COMMON_ERROR,
                message="系统繁忙, 请稍后重试",
            ) from e