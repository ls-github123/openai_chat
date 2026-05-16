"""
Admin 写操作审计服务

设计目标:
1. admin.py 只负责在写操作成功后调用本服务，不直接拼审计字段
2. 审计服务统一处理:
   - 操作者快照
   - 请求 IP / UA / path / method
   - 目标对象信息
   - before / after JSON 序列化
   - 敏感字段脱敏
   - 事务提交后写入审计日志
3. 只记录成功写操作, 表单校验失败、权限失败、锁未获取导致跳过的对象不应调用本服务
"""
from __future__ import annotations
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any, Iterable
from uuid import UUID

from django.db import transaction
from django.db.models import Model
from django.http import HttpRequest
from django.utils.encoding import force_str
from users.models.user_models import AdminAuditLog

class AdminAuditService:
    """
    Django Admin 写操作审计服务
    
    - 在 admin 写操作成功之后调用 log_admin_write()
    - 服务默认使用 transaction.on_commit() 写审计
    - 确保业务事务真正提交后才生成审计记录，避免事务回滚后留下误导性日志
    """
    # 敏感字段统一脱敏, 禁止 密码、TOTP密钥、token、secret 等原文写入审计表
    MASKED_VALUE = "***"
    
    SENSITIVE_FIELD_NAMES = {
        "password",
        "totp_secret",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "api_key",
        "private_key",
    }

    @classmethod
    def log_admin_write(
        cls,
        *,
        request: HttpRequest,
        action: str,
        reason: str,
        target: Model,
        changed_fields: Iterable[str] | None = None,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
    ) -> None:
        """
        记录一条 admin 写操作审计日志

        参数:
            request:
                Django Admin 当前请求，用于提取管理员、IP、UA、请求路径等信息

            action:
                操作类型。建议使用 AdminAuditLog 常量:
                - AdminAuditLog.ACTION_CREATE
                - AdminAuditLog.ACTION_UPDATE
                - AdminAuditLog.ACTION_PASSWORD_CHANGE
                - AdminAuditLog.ACTION_ADMIN_ACTION
                - AdminAuditLog.ACTION_FORCE_LOGOUT

            reason:
                操作原因 / 场景标识
                例如:
                - admin_create_user
                - admin_user_scalar_sensitive_changed
                - admin_disable_user
                - admin_reset_totp_user

            target:
                被操作的模型对象，例如 User / UserProfile

            changed_fields:
                实际发生变化的字段名列表
                注意只传“实际变化”的字段，避免无变化保存污染审计日志

            before:
                变更前字段快照
                可以只包含 changed_fields 中的字段

            after:
                变更后字段快照。
                可以只包含 changed_fields 中的字段

        行为:
            - 自动脱敏敏感字段
            - 自动转换 JSONField 可接受的值
            - 使用 transaction.on_commit() 延迟写审计，确保业务事务提交成功后才落审计
        """
        normalized_fields = cls._normalize_changed_fields(changed_fields)

        # 如果不是强制下线、改密码、批量动作等事件型操作，并且没有字段变化，则不写审计 
        event_actions = {
            AdminAuditLog.ACTION_PASSWORD_CHANGE,
            AdminAuditLog.ACTION_ADMIN_ACTION,
            AdminAuditLog.ACTION_FORCE_LOGOUT,
        }
        if not normalized_fields and action not in event_actions:
            return

        safe_before = cls._sanitize_payload(before or {})
        safe_after = cls._sanitize_payload(after or {})

        actor = cls._get_actor(request)
        actor_identifier = cls._build_actor_identifier(actor)

        target_model = cls._build_target_model(target)
        target_object_id = cls._build_target_object_id(target)
        target_repr = cls._build_target_repr(target)

        ip_address = cls._get_client_ip(request)
        user_agent = cls._truncate(
            request.META.get("HTTP_USER_AGENT", ""),
            max_length=512,
        )
        request_path = cls._truncate(
            request.get_full_path() if hasattr(request, "get_full_path") else "",
            max_length=512,
        )
        request_method = cls._truncate(
            getattr(request, "method", ""),
            max_length=16,
        )

        def create_log() -> None:
            AdminAuditLog.objects.create(
                actor=actor,
                actor_identifier=actor_identifier,
                action=action,
                reason=reason,
                target_model=target_model,
                target_object_id=target_object_id,
                target_repr=target_repr,
                changed_fields=normalized_fields,
                before=safe_before,
                after=safe_after,
                ip_address=ip_address,
                user_agent=user_agent,
                request_path=request_path,
                request_method=request_method,
            )

        # 当前处于事务中时，业务事务提交成功后再写审计。
        # 如果当前没有事务，on_commit 会立即执行 callback。
        transaction.on_commit(create_log)

    @classmethod
    def build_model_snapshot(
        cls,
        obj: Model,
        fields: Iterable[str],
    ) -> dict[str, Any]:
        """
        根据字段名从模型对象构建快照

        用途:
            admin.py 可以在保存前读取 before:
                before = AdminAuditService.build_model_snapshot(old_obj, changed_fields)

            保存后读取 after:
                after = AdminAuditService.build_model_snapshot(obj, changed_fields)

        说明:
            - 普通字段直接读取 obj.<field>
            - 敏感字段自动脱敏
            - 不存在的字段会跳过，避免 admin 表单里的非模型字段导致异常
        """
        snapshot: dict[str, Any] = {}

        for field_name in cls._normalize_changed_fields(fields):
            if not hasattr(obj, field_name):
                continue

            value = getattr(obj, field_name)
            snapshot[field_name] = cls._sanitize_value(field_name, value)

        return snapshot

    @classmethod
    def build_m2m_snapshot(
        cls,
        obj: Model,
        fields: Iterable[str],
    ) -> dict[str, Any]:
        """
        构建 ManyToMany 字段快照

        用途:
            UserAdmin.save_related 中记录 groups / user_permissions 变化

        输出:
            {
                "groups": [1, 2, 3],
                "user_permissions": [10, 11]
            }

        注意:
            该方法会查询数据库，应只在确实需要记录 M2M 变化时调用
        """
        snapshot: dict[str, Any] = {}

        for field_name in cls._normalize_changed_fields(fields):
            if not hasattr(obj, field_name):
                continue

            manager = getattr(obj, field_name)
            if not hasattr(manager, "values_list"):
                continue

            snapshot[field_name] = list(
                manager.values_list("pk", flat=True).order_by("pk")
            )

        return snapshot

    @classmethod
    def _normalize_changed_fields(
        cls,
        changed_fields: Iterable[str] | None,
    ) -> list[str]:
        """
        规范化 changed_fields:
        - 去掉空值
        - 转成字符串
        - 去重
        - 排序，保证审计 JSON 稳定
        """
        if not changed_fields:
            return []

        return sorted(
            {
                force_str(field)
                for field in changed_fields
                if field is not None and force_str(field).strip()
            }
        )

    @classmethod
    def _sanitize_payload(cls, payload: dict[str, Any]) -> dict[str, Any]:
        """
        清洗 before / after 字典:
        - 敏感字段脱敏
        - 日期、Decimal、UUID 等转成 JSON 可序列化值
        - 嵌套 dict / list 递归处理
        """
        safe_payload: dict[str, Any] = {}

        for key, value in payload.items():
            field_name = force_str(key)
            safe_payload[field_name] = cls._sanitize_value(field_name, value)

        return safe_payload

    @classmethod
    def _sanitize_value(cls, field_name: str, value: Any) -> Any:
        """
        单个字段值清洗

        规则:
            1. 字段名命中敏感字段集合时，统一返回 "***"
            2. 基础 JSON 类型原样保留
            3. datetime/date/time 转 ISO 字符串
            4. Decimal/UUID 转字符串
            5. Model 对象转主键字符串
            6. dict/list/tuple/set 递归处理
            7. 其他对象使用 force_str() 兜底
        """
        normalized_name = field_name.lower()

        if normalized_name in cls.SENSITIVE_FIELD_NAMES:
            return cls.MASKED_VALUE

        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, (datetime, date, time)):
            return value.isoformat()

        if isinstance(value, (Decimal, UUID)):
            return str(value)

        if isinstance(value, Model):
            return str(value.pk)

        if isinstance(value, dict):
            return {
                force_str(k): cls._sanitize_value(force_str(k), v)
                for k, v in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [
                cls._sanitize_value(field_name, item)
                for item in value
            ]

        return force_str(value)

    @staticmethod
    def _get_actor(request: HttpRequest):
        """
        获取当前管理员对象

        匿名用户或未持久化用户不写 actor 外键，但 actor_identifier 仍会尽量保留快照
        """
        actor = getattr(request, "user", None)

        if not actor or not getattr(actor, "is_authenticated", False):
            return None

        if getattr(actor, "pk", None) is None:
            return None

        return actor

    @staticmethod
    def _build_actor_identifier(actor: Any) -> str:
        """
        构建管理员快照

        格式示例:
            123456:user@example.com

        目的:
            即使 actor 外键未来被 SET_NULL，仍能知道当时是谁执行了操作
        """
        if actor is None:
            return ""

        actor_id = getattr(actor, "pk", "")
        email = getattr(actor, "email", "") or ""
        username = getattr(actor, "username", "") or ""
        identifier = email or username or force_str(actor)

        if actor_id:
            return f"{actor_id}:{identifier}"

        return force_str(identifier)

    @staticmethod
    def _build_target_model(target: Model) -> str:
        """
        构建目标模型标识

        示例:
            users.User
            users.UserProfile
        """
        return target._meta.label

    @staticmethod
    def _build_target_object_id(target: Model) -> str:
        """
        构建目标对象主键字符串

        注意:
            审计应在对象保存成功后调用，正常情况下 target.pk 应该存在
        """
        return force_str(getattr(target, "pk", "") or "")

    @classmethod
    def _build_target_repr(cls, target: Model) -> str:
        """
        构建目标对象展示快照

        限制长度是为了匹配 AdminAuditLog.target_repr 的 255 长度
        """
        return cls._truncate(force_str(target), max_length=255)

    @staticmethod
    def _get_client_ip(request: HttpRequest) -> str | None:
        """
        获取客户端 IP

        优先级:
            1. HTTP_X_FORWARDED_FOR 第一个 IP
            2. REMOTE_ADDR

        生产注意:
            如果服务暴露在公网且经过多层代理，应配合可信代理配置使用
            不可信来源可以伪造 X-Forwarded-For
        """
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip() or None

        return request.META.get("REMOTE_ADDR") or None

    @staticmethod
    def _truncate(value: Any, *, max_length: int) -> str:
        """
        字符串截断工具，避免超过模型字段 max_length
        """
        text = force_str(value or "")
        if len(text) <= max_length:
            return text
        return text[:max_length]