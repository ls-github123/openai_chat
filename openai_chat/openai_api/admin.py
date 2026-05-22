"""
OpenAI API 管理模块 Django Admin 配置

职责:
1. 注册 OpenAIProviderConfig / OpenAIModelConfig / OpenAIUsageLog 到 Django Admin
2. Provider / Model 配置属于高风险写操作，保存时显式加分布式锁
3. Provider / Model 写操作成功后写入 AdminAuditLog
4. UsageLog 属于审计数据，只允许查看，不允许后台新增、修改或删除
5. 后台只展示 api_key_secret_name，不读取、不展示 OpenAI API Key 明文
"""
from __future__ import annotations
from typing import Iterable
from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import QuerySet
from django.http import HttpRequest

from openai_chat.settings.utils.locks import build_lock
from openai_api.models import OpenAIModelConfig, OpenAIProviderConfig, OpenAIUsageLog
from users.models.user_models import AdminAuditLog
from users.services.admin_audit_service import AdminAuditService

# OpenAI API 管理后台写操作锁 TTL(ms)
OPENAI_API_ADMIN_LOCK_TTL_MS = 10_000

OPENAI_ADMIN_SENSITIVE_AUDIT_FIELDS = {
    "api_key_secret_name",
}

# Provider 配置允许写入审计快照的字段
PROVIDER_AUDIT_FIELDS = {
    "name",
    "display_name",
    "provider_type",
    "base_url",
    "api_version",
    "api_key_secret_name",
    "organization_id",
    "project_id",
    "enabled",
    "is_default",
    "timeout_seconds",
    "max_retries",
    "remark",
}

# Model 配置允许写入审计快照的字段。
MODEL_AUDIT_FIELDS = {
    "provider",
    "model_name",
    "display_name",
    "api_family",
    "model_category",
    "enabled",
    "is_default",
    "context_window",
    "max_input_tokens",
    "max_output_tokens",
    "supports_stream",
    "supports_tools",
    "supports_json_schema",
    "supports_reasoning",
    "supports_vision",
    "supports_audio_input",
    "supports_audio_output",
    "supports_web_search",
    "supports_file_search",
    "default_service_tier",
    "input_price_per_1k",
    "output_price_per_1k",
    "cached_input_price_per_1k",
    "currency",
    "sort_order",
    "remark",
}

def get_provider_admin_lock_key() -> str:
    """
    Provider 配置写操作全局锁
    
    - Provider 配置影响 OpenAI API 调用出口、密钥引用和默认路由
    - 使用全局锁，避免多个管理员并发修改默认 Provider 或启停 Provider
    """
    return "lock:admin:openai_api:provider_config"

def get_model_admin_lock_key(provider_id: int | str, api_family: str) -> str:
    """
    模型配置写操作锁
    
    默认模型唯一性按 provider + api_family 维护:
    - 同一个 Provider 下，一个 API 类型只允许一个默认模型
    - 例如 responses 有一个默认模型，embeddings 也可以有另一个默认模型
    """
    return f"lock:admin:openai_api:model_config:{provider_id}:{api_family}"

def normalize_changed_fields(
    form_changed_data: Iterable[str],
    allowed_fields: set[str],
) -> list[str]:
    """
    规范化 admin 表单变更字段

    - 只保留模型审计允许的字段，避免把非模型字段或内部字段写入审计日志
    """
    return sorted(set(form_changed_data or []) & allowed_fields)

def get_created_fields(form_fields: Iterable[str], allowed_fields: set[str]) -> list[str]:
    """
    构建新增对象时的审计字段
    """
    return sorted(set(form_fields or []) & allowed_fields)

def build_admin_snapshot(obj, fields: Iterable[str]) -> dict:
    """
    构建 admin 审计快照, 并对 OpenAI 管理模块的敏感字段做二次脱敏
    - 额外屏蔽 api_key_secret_name，避免 Key Vault secret name 进入审计明文
    """
    snapshot = AdminAuditService.build_model_snapshot(obj, fields)
    
    for field_name in OPENAI_ADMIN_SENSITIVE_AUDIT_FIELDS:
        if field_name in snapshot:
            snapshot[field_name] = AdminAuditService.MASKED_VALUE
    return snapshot

class SuperuserWriteModelAdmin(admin.ModelAdmin):
    """
    高风险配置写操作权限控制基类
    
    - 查看权限继续遵循 Django Admin 自身 permission
    - 新增、修改、删除要求超级管理员
    - 继承 admin.ModelAdmin 是为了让 Pylance 能识别 super().has_*_permission()
    """
    def has_add_permission(self, request: HttpRequest) -> bool:
        return bool(request.user.is_superuser) and super().has_add_permission(request)
    
    def has_change_permission(self, request: HttpRequest, obj=None) -> bool:
        if request.method not in ("GET", "HEAD", "OPTIONS") and not request.user.is_superuser:
            return False
        return super().has_change_permission(request, obj)

    def has_delete_permission(self, request: HttpRequest, obj=None) -> bool:
        return bool(request.user.is_superuser) and super().has_delete_permission(request, obj)

@admin.register(OpenAIProviderConfig)
class OpenAIProviderConfigAdmin(SuperuserWriteModelAdmin):
    """
    OpenAI Provider 后台管理
    
    Provider 配置用于控制 OpenAI API 调用后端:
    - OpenAI 官方 API
    - Azure OpenAI
    - OpenAI-compatible 网关
    """
    list_display = (
        "name",
        "display_name",
        "provider_type",
        "base_url",
        "api_version",
        "enabled",
        "is_default",
        "timeout_seconds",
        "max_retries",
        "updated_at",
    )
    list_filter = (
        "provider_type",
        "enabled",
        "is_default",
        "created_at",
        "updated_at",
    )
    search_fields = (
        "name",
        "display_name",
        "base_url",
        "api_key_secret_name",
        "organization_id",
        "project_id",
        "remark",
    )
    readonly_fields = (
        "created_at",
        "updated_at",
    )
    fieldsets = (
        (
            "基础配置",
            {
                "fields": (
                    "name",
                    "display_name",
                    "provider_type",
                    "enabled",
                    "is_default",
                )
            },
        ),
        (
            "API 连接配置",
            {
                "fields": (
                    "base_url",
                    "api_version",
                    "api_key_secret_name",
                    "organization_id",
                    "project_id",
                ),
                "description": "这里只保存 Key Vault secret name，不读取、不展示 OpenAI API Key 明文。",
            },
        ),
        (
            "运行策略",
            {
                "fields": (
                    "timeout_seconds",
                    "max_retries",
                )
            },
        ),
        (
            "备注与时间",
            {
                "fields": (
                    "remark",
                    "created_at",
                    "updated_at",
                )
            },
        ),
    )
    
    actions = None
    
    def get_queryset(self, request: HttpRequest) -> QuerySet[OpenAIProviderConfig]:
        return super().get_queryset(request).order_by("name")
    
    def save_model(self, request: HttpRequest, obj: OpenAIProviderConfig, form, change: bool) -> None:
        """
        保存 Provider 配置
        
        - 只有超级管理员可以写
        - 使用 Provider 全局锁
        - 当前对象设置为默认 Provider 时，自动取消其他 Provider 的默认标记
        - 写入 AdminAuditLog
        """
        if not request.user.is_superuser:
            raise PermissionDenied("只有超级管理员可以修改 OpenAI Provider 配置")
        
        changed_fields = (
            normalize_changed_fields(form.changed_data, PROVIDER_AUDIT_FIELDS)
            if change
            else get_created_fields(form.fields.keys(), PROVIDER_AUDIT_FIELDS)
        )
        
        with build_lock(
            get_provider_admin_lock_key(),
            ttl=OPENAI_API_ADMIN_LOCK_TTL_MS,
            strategy="safe",
        ).lock() as acquired:
            if not acquired:
                raise PermissionDenied("OpenAI Provider 配置正在被其他后台操作修改，请稍后重试")
            
            with transaction.atomic():
                old_obj = (
                    OpenAIProviderConfig.objects.filter(pk=obj.pk).first()
                    if change and obj.pk
                    else None
                )
                before = build_admin_snapshot(old_obj, changed_fields) if old_obj and changed_fields else {}
                super().save_model(request, obj, form, change)
                
                reset_count = 0
                
                if obj.enabled and obj.is_default:
                    reset_count = (
                        OpenAIProviderConfig.objects
                        .exclude(pk=obj.pk)
                        .filter(is_default=True)
                        .update(is_default=False)
                    )
                
                after = build_admin_snapshot(obj, changed_fields)
                if reset_count:
                    after["default_provider_reset_count"] = reset_count
                
                AdminAuditService.log_admin_write(
                    request=request,
                    action=AdminAuditLog.ACTION_UPDATE if change else AdminAuditLog.ACTION_CREATE,
                    reason="admin_openai_provider_update" if change else "admin_openai_provider_create",
                    target=obj,
                    changed_fields=changed_fields,
                    before=before,
                    after=after,
                )
            
            if obj.enabled and obj.is_default:
                self.message_user(
                    request,
                    "默认 Provider 已更新；其他 Provider 的默认标记已自动取消。",
                    level=messages.SUCCESS,
                )

@admin.register(OpenAIModelConfig)
class OpenAIModelConfigAdmin(SuperuserWriteModelAdmin):
    """
    OpenAI 模型配置后台管理

    该后台维护模型治理信息:
    - 模型名
    - API 类型
    - 模型类别
    - token 限额
    - 能力开关
    - 服务层级
    - 内部统计价格
    """
    list_display = (
        "model_name",
        "display_name",
        "provider",
        "api_family",
        "model_category",
        "enabled",
        "is_default",
        "context_window",
        "max_input_tokens",
        "max_output_tokens",
        "default_service_tier",
        "sort_order",
        "updated_at",
    )
    list_filter = (
        "provider",
        "api_family",
        "model_category",
        "enabled",
        "is_default",
        "supports_stream",
        "supports_tools",
        "supports_json_schema",
        "supports_reasoning",
        "supports_vision",
        "supports_audio_input",
        "supports_audio_output",
        "supports_web_search",
        "supports_file_search",
        "default_service_tier",
        "created_at",
        "updated_at",
    )
    search_fields = (
        "model_name",
        "display_name",
        "provider__name",
        "provider__display_name",
        "remark",
    )
    readonly_fields = (
        "created_at",
        "updated_at",
    )
    list_select_related = (
        "provider",
    )
    fieldsets = (
        (
            "基础配置",
            {
                "fields": (
                    "provider",
                    "model_name",
                    "display_name",
                    "api_family",
                    "model_category",
                    "enabled",
                    "is_default",
                    "sort_order",
                )
            },
        ),
        (
            "Token 限制",
            {
                "fields": (
                    "context_window",
                    "max_input_tokens",
                    "max_output_tokens",
                )
            },
        ),
        (
            "能力开关",
            {
                "fields": (
                    "supports_stream",
                    "supports_tools",
                    "supports_json_schema",
                    "supports_reasoning",
                    "supports_vision",
                    "supports_audio_input",
                    "supports_audio_output",
                    "supports_web_search",
                    "supports_file_search",
                )
            },
        ),
        (
            "服务层级与价格",
            {
                "fields": (
                    "default_service_tier",
                    "input_price_per_1k",
                    "output_price_per_1k",
                    "cached_input_price_per_1k",
                    "currency",
                ),
                "description": "价格字段只用于内部统计和看板展示，实际账单以 OpenAI / Provider 为准。",
            },
        ),
        (
            "备注与时间",
            {
                "fields": (
                    "remark",
                    "created_at",
                    "updated_at",
                )
            },
        ),
    )
    
    actions = None
    
    def get_queryset(self, request: HttpRequest) -> QuerySet[OpenAIModelConfig]:
        return super().get_queryset(request).select_related("provider")

    def save_model(self, request: HttpRequest, obj: OpenAIModelConfig, form, change: bool) -> None:
        """
        保存模型配置

        行为:
        - 只有超级管理员可以写
        - 使用 provider + api_family 粒度锁
        - 当前模型设置为默认模型时，自动取消同 Provider / 同 API 类型下其他模型默认标记
        - 写入 AdminAuditLog
        """
        if not request.user.is_superuser:
            raise PermissionDenied("只有超级管理员可以修改 OpenAI 模型配置")

        provider_identity = getattr(obj.provider, "pk", None) or "unknown"
        api_family = obj.api_family or "unknown"
        lock_key = get_model_admin_lock_key(provider_identity, api_family)

        changed_fields = (
            normalize_changed_fields(form.changed_data, MODEL_AUDIT_FIELDS)
            if change
            else get_created_fields(form.fields.keys(), MODEL_AUDIT_FIELDS)
        )

        with build_lock(lock_key, ttl=OPENAI_API_ADMIN_LOCK_TTL_MS, strategy="safe").lock() as acquired:
            if not acquired:
                raise PermissionDenied("OpenAI 模型配置正在被其他后台操作修改，请稍后重试")

            with transaction.atomic():
                old_obj = (
                    OpenAIModelConfig.objects.select_related("provider").filter(pk=obj.pk).first()
                    if change and obj.pk
                    else None
                )
                before = build_admin_snapshot(old_obj, changed_fields) if old_obj and changed_fields else {}

                super().save_model(request, obj, form, change)

                reset_count = 0
                if obj.enabled and obj.is_default:
                    reset_count = (
                        OpenAIModelConfig.objects
                        .exclude(pk=obj.pk)
                        .filter(
                            provider=obj.provider,
                            api_family=obj.api_family,
                            is_default=True,
                        )
                        .update(is_default=False)
                    )

                after = build_admin_snapshot(obj, changed_fields)
                if reset_count:
                    after["default_model_reset_count"] = reset_count

                AdminAuditService.log_admin_write(
                    request=request,
                    action=AdminAuditLog.ACTION_UPDATE if change else AdminAuditLog.ACTION_CREATE,
                    reason="admin_openai_model_update" if change else "admin_openai_model_create",
                    target=obj,
                    changed_fields=changed_fields,
                    before=before,
                    after=after,
                )

        if obj.enabled and obj.is_default:
            self.message_user(
                request,
                "默认模型已更新；同 Provider、同 API 类型下其他模型的默认标记已自动取消。",
                level=messages.SUCCESS,
            )

@admin.register(OpenAIUsageLog)
class OpenAIUsageLogAdmin(admin.ModelAdmin):
    """
    OpenAI API 调用日志后台
    
    UsageLog 为审计数据:
    - 只允许查看
    - 不允许新增
    - 不允许修改
    - 不允许删除
    """
    list_display = (
        "created_at",
        "user",
        "provider_name",
        "model_name",
        "api_operation",
        "status",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "latency_ms",
        "http_status_code",
        "error_code",
        "openai_request_id",
    )
    list_filter = (
        "status",
        "api_operation",
        "provider_type",
        "provider_name",
        "model_name",
        "service_tier",
        "http_status_code",
        "created_at",
    )
    search_fields = (
        "request_id",
        "openai_request_id",
        "provider_response_id",
        "idempotency_key",
        "conversation_id",
        "message_id",
        "provider_name",
        "model_name",
        "error_code",
        "error_message",
    )
    date_hierarchy = "created_at"
    list_select_related = (
        "user",
        "provider",
        "model_config",
    )
    ordering = (
        "-created_at",
    )
    
    actions = None
    
    fieldsets = (
        (
            "调用主体",
            {
                "fields": (
                    "user",
                    "provider",
                    "model_config",
                    "provider_name",
                    "provider_type",
                    "model_name",
                    "api_operation",
                    "status",
                    "created_at",
                )
            },
        ),
        (
            "链路追踪",
            {
                "fields": (
                    "request_id",
                    "openai_request_id",
                    "provider_response_id",
                    "idempotency_key",
                    "conversation_id",
                    "message_id",
                    "request_body_hash",
                    "safety_identifier_hash",
                )
            },
        ),
        (
            "Token 用量",
            {
                "fields": (
                    "input_tokens",
                    "output_tokens",
                    "total_tokens",
                    "input_cached_tokens",
                    "input_audio_tokens",
                    "output_audio_tokens",
                    "output_reasoning_tokens",
                    "accepted_prediction_tokens",
                    "rejected_prediction_tokens",
                )
            },
        ),
        (
            "性能与响应",
            {
                "fields": (
                    "latency_ms",
                    "provider_processing_ms",
                    "http_status_code",
                    "service_tier",
                    "system_fingerprint",
                    "finish_reason",
                    "incomplete_reason",
                )
            },
        ),
        (
            "错误信息",
            {
                "fields": (
                    "error_code",
                    "error_message",
                    "rate_limit_snapshot",
                )
            },
        ),
        (
            "请求环境",
            {
                "fields": (
                    "client_ip",
                    "user_agent",
                    "extra",
                )
            },
        ),
    )
    
    def get_queryset(self, request: HttpRequest) -> QuerySet[OpenAIUsageLog]:
        return super().get_queryset(request).select_related("user", "provider", "model_config")

    def get_readonly_fields(self, request: HttpRequest, obj=None):
        """
        UsageLog 全字段只读

        使用 concrete_fields 自动生成，避免以后模型字段增加后忘记同步只读列表
        """
        return tuple(field.name for field in self.model._meta.concrete_fields)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj=None) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj=None) -> bool:
        """
        允许 GET 进入详情页查看，拒绝 POST 等写入请求
        """
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            return False

        return super().has_view_permission(request, obj) or super().has_change_permission(request, obj)

    def save_model(self, request: HttpRequest, obj: OpenAIUsageLog, form, change: bool) -> None:
        """
        防御性保护

        - 正常情况下 UsageLog 无新增入口且全字段只读，不会走到这里
        - 如果未来有自定义入口绕过表单层，也不允许通过 admin 写入调用日志
        """
        raise PermissionDenied("OpenAI API 调用日志不允许在后台手工修改")