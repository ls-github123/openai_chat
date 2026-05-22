"""
OPENAI API 管理模块数据模型

本模块负责保存 OpenAI API 管理所需的结构化数据:
- Provider 配置：管理 OpenAI / Azure OpenAI / 兼容网关
- Model 配置：管理可用模型、能力、限额、价格
- Usage Log：记录调用审计、token 用量、错误摘要、MongoDB 会话引用

安全边界:
- MySQL 不保存 OpenAI API Key 明文
- MySQL 不保存用户 prompt / 对话正文
- 对话内容、上下文、消息正文应存 MongoDB
"""
from __future__ import annotations
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from decimal import Decimal

class OpenAIProviderConfig(models.Model):
    """
    OpenAI Provider 配置表
    - 一个 Provider 表示一个可调用的 OpenAI API 后端
    - OpenAI 官方 API
    - Azure OpenAI
    - OpenAI-compatible 代理网关
    """
    PROVIDER_OPENAI = "openai"
    PROVIDER_AZURE_OPENAI = "azure_openai"
    PROVIDER_COMPATIBLE = "openai_compatible"

    PROVIDER_TYPE_CHOICES = (
        (PROVIDER_OPENAI, "OpenAI 官方 API"),
        (PROVIDER_AZURE_OPENAI, "Azure OpenAI"),
        (PROVIDER_COMPATIBLE, "OpenAI-compatible 网关"),
    )
    
    name = models.CharField(
        "Provider 标识",
        max_length=64,
        unique=True,
        db_index=True,
        help_text="系统内部唯一标识",
        )
    display_name = models.CharField("显示名称", max_length=128, blank=True, default="", help_text="后台展示名称")
    provider_type = models.CharField(
        "Provider 类型",
        max_length=32,
        choices=PROVIDER_TYPE_CHOICES,
        default=PROVIDER_OPENAI,
        db_index=True,
        help_text="区分 OpenAI 官方、Azure OpenAI 或兼容 OpenAI 协议的网关",
    )
    base_url = models.URLField(
        "API Base URL",
        max_length=512,
        default="https://api.openai.com/v1",
        help_text="API 基础地址, 不包含具体 endpoint",
    )
    api_version = models.CharField(
        "API Version",
        max_length=64,
        blank=True,
        default="",
        help_text="Azure OpenAI 常用 api-version；OpenAI 官方 API 通常留空",
    )
    api_key_secret_name = models.CharField(
        "API Key Secret Name",
        max_length=128,
        help_text="Azure Key Vault 中保存 API Key 的 secret 名称",
    )
    organization_id = models.CharField(
        "OpenAI Organization ID",
        max_length=128,
        blank=True,
        default="",
        help_text="OpenAI-Organization 请求头对应的组织 ID，可选",
    )
    project_id = models.CharField(
        "OpenAI Project ID",
        max_length=128,
        blank=True,
        default="",
        help_text="OpenAI-Project 请求头对应的项目 ID, 可选",
    )
    enabled = models.BooleanField(
        "是否启用",
        default=True,
        db_index=True,
        help_text="关闭后 service 层不得继续使用该 provider 发起调用",
    )
    is_default = models.BooleanField(
        "是否默认 Provider",
        default=False,
        db_index=True,
        help_text="默认 Provider 的唯一性由 admin/service 写操作加锁保证",
    )
    timeout_seconds = models.PositiveIntegerField(
        "请求超时时间",
        default=60,
        help_text="该 Provider 的 HTTP 请求超时时间，单位秒",
    )
    max_retries = models.PositiveIntegerField(
        "最大重试次数",
        default=2,
        help_text="网络抖动、限流等可重试错误的最大重试次数",
    )
    remark = models.CharField(
        "备注",
        max_length=255,
        blank=True,
        default="",
        help_text="运维备注",
    )
    created_at = models.DateTimeField(
        "创建时间",
        default=timezone.now,
        db_index=True,
    )
    updated_at = models.DateTimeField(
        "更新时间",
        auto_now=True,
    )
    
    class Meta:
        db_table = "openai_api_provider_config"
        verbose_name = "OpenAI Provider 配置"
        verbose_name_plural = "OpenAI Provider 配置"
        ordering = ("name",)
        indexes = [
            models.Index(fields=["provider_type", "enabled"], name="idx_oai_provider_type_enabled"),
            models.Index(fields=["is_default", "enabled"], name="idx_oai_provider_default"),
        ]
    
    def clean(self):
        """
        只做本地字段校验, 不访问 OpenAI API, 不访问 Azure Key Vault
        
        - model clean 可能在 admin、测试、管理命令中触发
        - 这里访问外部网络会破坏 Django 启动稳定性
        """
        super().clean()
        
        if self.enabled and not self.api_key_secret_name.strip():
            raise ValidationError({"api_key_secret_name": "启用的 Provider 必须配置 API Key Secret Name。"})
        
        if self.timeout_seconds <= 0:
            raise ValidationError({"timeout_seconds": "请求超时时间必须大于 0 秒。"})
        
        if self.provider_type == self.PROVIDER_AZURE_OPENAI and not self.api_version.strip():
            raise ValidationError({"api_version": "Azure OpenAI Provider 建议明确配置 api_version。"})
        
    def save(self, *args, **kwargs):
        """
        保存前做轻量标准化
        
        - 不在这里处理 is_default 唯一性, 该操作需要分布式锁保护
        - 后续应在 admin/service 写操作中用 build_lock 完成
        """
        self.name = self.name.strip()
        self.display_name = self.display_name.strip()
        self.base_url = self.base_url.strip().rstrip("/")
        self.api_version = self.api_version.strip()
        self.api_key_secret_name = self.api_key_secret_name.strip()
        self.organization_id = self.organization_id.strip()
        self.project_id = self.project_id.strip()
        self.remark = self.remark.strip()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.display_name or self.name} ({self.provider_type})"
    
class OpenAIModelConfig(models.Model):
    """
    OpenAI 模型配置表
    
    - 该表描述系统允许调用哪些模型，以及这些模型的 API 入口、能力、限额和价格
    - 业务模块不应硬编码模型名
    - 通过该表判断模型是否启用、是否支持工具调用、是否支持结构化输出、最大上下文等
    """
    API_FAMILY_RESPONSES = "responses"
    API_FAMILY_CHAT_COMPLETIONS = "chat_completions"
    API_FAMILY_EMBEDDINGS = "embeddings"
    API_FAMILY_IMAGES = "images"
    API_FAMILY_AUDIO = "audio"
    API_FAMILY_REALTIME = "realtime"
    API_FAMILY_OTHER = "other"

    API_FAMILY_CHOICES = (
        (API_FAMILY_RESPONSES, "Responses API"),
        (API_FAMILY_CHAT_COMPLETIONS, "Chat Completions API"),
        (API_FAMILY_EMBEDDINGS, "Embeddings API"),
        (API_FAMILY_IMAGES, "Images API"),
        (API_FAMILY_AUDIO, "Audio API"),
        (API_FAMILY_REALTIME, "Realtime API"),
        (API_FAMILY_OTHER, "其他"),
    )

    CATEGORY_TEXT = "text"
    CATEGORY_REASONING = "reasoning"
    CATEGORY_MULTIMODAL = "multimodal"
    CATEGORY_EMBEDDING = "embedding"
    CATEGORY_IMAGE = "image"
    CATEGORY_AUDIO = "audio"
    CATEGORY_OTHER = "other"
    
    MODEL_CATEGORY_CHOICES = (
        (CATEGORY_TEXT, "文本模型"),
        (CATEGORY_REASONING, "推理模型"),
        (CATEGORY_MULTIMODAL, "多模态模型"),
        (CATEGORY_EMBEDDING, "Embedding 模型"),
        (CATEGORY_IMAGE, "图像模型"),
        (CATEGORY_AUDIO, "音频模型"),
        (CATEGORY_OTHER, "其他"),
    )

    SERVICE_TIER_AUTO = "auto"
    SERVICE_TIER_DEFAULT = "default"
    SERVICE_TIER_FLEX = "flex"
    SERVICE_TIER_PRIORITY = "priority"

    SERVICE_TIER_CHOICES = (
        (SERVICE_TIER_AUTO, "Auto"),
        (SERVICE_TIER_DEFAULT, "Default"),
        (SERVICE_TIER_FLEX, "Flex"),
        (SERVICE_TIER_PRIORITY, "Priority"),
    )
    
    provider = models.ForeignKey(
        OpenAIProviderConfig,
        on_delete=models.PROTECT,
        related_name="model_configs",
        verbose_name="所属 Provider",
        help_text="该模型归属的 Provider。存在模型配置时禁止直接删除 Provider",
    )
    model_name = models.CharField(
        "模型名称",
        max_length=128,
        db_index=True,
        help_text="实际传递给 OpenAI API 的模型名称",
    )
    display_name = models.CharField(
        "显示名称",
        max_length=128,
        blank=True,
        default="",
        help_text="后台或前端展示名称(为空时默认使用模型名称)",
    )
    api_family = models.CharField(
        "API 类型",
        max_length=32,
        choices=API_FAMILY_CHOICES,
        default=API_FAMILY_RESPONSES,
        db_index=True,
        help_text="该模型默认通过哪个 OpenAI API 入口调用",
    )
    model_category = models.CharField(
        "模型类别",
        max_length=32,
        choices=MODEL_CATEGORY_CHOICES,
        default=CATEGORY_TEXT,
        db_index=True,
        help_text="模型能力类别, 用于前端筛选和 service 层策略判断",
    )
    enabled = models.BooleanField(
        "是否启用",
        default=True,
        db_index=True,
        help_text="关闭后业务模块不得继续向用户暴露或调用该模型",
    )
    is_default = models.BooleanField(
        "是否默认模型",
        default=False,
        db_index=True,
        help_text="默认模型唯一性由 admin/service 写操作加锁保证",
    )
    context_window = models.PositiveIntegerField(
        "上下文窗口 Tokens",
        default=0,
        help_text="模型最大上下文 tokens, 未知时填0",
    )
    max_input_tokens = models.PositiveIntegerField(
        "最大输入 Tokens",
        default=0,
        help_text="后端允许的最大输入 tokens。0 表示暂不在模型层限制",
    )
    max_output_tokens = models.PositiveIntegerField(
        "最大输出 Tokens",
        default=4096,
        help_text="后端允许的最大输出 tokens",
    )
    supports_stream = models.BooleanField(
        "支持流式输出",
        default=True,
    )
    supports_tools = models.BooleanField(
        "支持工具调用",
        default=False,
    )
    supports_json_schema = models.BooleanField(
        "支持结构化输出",
        default=False,
    )
    supports_reasoning = models.BooleanField(
        "支持推理参数",
        default=False,
        help_text="是否支持 reasoning effort / reasoning tokens 等推理模型能力",
    )
    supports_vision = models.BooleanField(
        "支持视觉输入",
        default=False,
        help_text="是否支持图片输入或视觉理解",
    )
    supports_audio_input = models.BooleanField(
        "支持音频输入",
        default=False,
    )
    supports_audio_output = models.BooleanField(
        "支持音频输出",
        default=False,
    )
    supports_web_search = models.BooleanField(
        "支持 Web Search",
        default=False,
        help_text="是否允许通过 Responses API 使用 web search 工具",
    )
    supports_file_search = models.BooleanField(
        "支持 File Search",
        default=False,
        help_text="是否允许通过 Responses API 使用 file search 工具",
    )
    default_service_tier = models.CharField(
        "默认服务层级",
        max_length=32,
        choices=SERVICE_TIER_CHOICES,
        default=SERVICE_TIER_AUTO,
        help_text="默认请求服务层级。实际响应中的 service_tier 仍以 OpenAI 返回为准",
    )
    input_price_per_1k = models.DecimalField(
        "输入单价/1K Tokens",
        max_digits=12,
        decimal_places=6,
        default=Decimal("0.000000"),
        help_text="输入 tokens 每 1000 tokens 的内部统计价格",
    )
    output_price_per_1k = models.DecimalField(
        "输出单价/1K Tokens",
        max_digits=12,
        decimal_places=6,
        default=Decimal("0.000000"),
        help_text="输出 tokens 每 1000 tokens 的内部统计价格",
    )
    cached_input_price_per_1k = models.DecimalField(
        "缓存输入单价/1K Tokens",
        max_digits=12,
        decimal_places=6,
        default=Decimal("0.000000"),
        help_text="缓存命中输入 tokens 的内部统计价格",
    )
    currency = models.CharField(
        "计价币种",
        max_length=16,
        default="USD",
        help_text="价格字段使用的币种，仅用于内部展示和粗略统计",
    )
    sort_order = models.PositiveIntegerField(
        "排序值",
        default=100,
        db_index=True,
        help_text="后台或前端展示排序，数值越小越靠前",
    )
    remark = models.CharField(
        "备注",
        max_length=255,
        blank=True,
        default="",
        help_text="运维备注，例如使用场景、限制说明、灰度说明",
    )
    created_at = models.DateTimeField(
        "创建时间",
        default=timezone.now,
        db_index=True,
    )
    updated_at = models.DateTimeField(
        "更新时间",
        auto_now=True,
    )
    
    class Meta:
        db_table = "openai_api_model_config"
        verbose_name = "OpenAI 模型配置"
        verbose_name_plural = "OpenAI 模型配置"
        ordering = ("sort_order", "model_name")
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "model_name"],
                name="uniq_oai_provider_model",
            ),
        ]
        indexes = [
            models.Index(fields=["api_family", "enabled"], name="idx_oai_model_api_enabled"),
            models.Index(fields=["model_category", "enabled"], name="idx_oai_model_cat_enabled"),
            models.Index(fields=["is_default", "enabled"], name="idx_oai_model_default"),
            models.Index(fields=["provider", "enabled"], name="idx_oai_model_provider_enabled"),
        ]
    
    def clean(self):
        """
        模型配置本地校验

        - 不访问 OpenAI API 校验模型是否真实存在
        - 真实模型探测应放在后续 service / celery 任务中，并记录审计日志
        """
        super().clean()

        if self.is_default and not self.enabled:
            raise ValidationError({"is_default": "禁用模型不能设置为默认模型"})

        if self.context_window and self.max_output_tokens > self.context_window:
            raise ValidationError({"max_output_tokens": "最大输出 tokens 不能大于上下文窗口"})

        if self.context_window and self.max_input_tokens and self.max_input_tokens > self.context_window:
            raise ValidationError({"max_input_tokens": "最大输入 tokens 不能大于上下文窗口"})

        if self.api_family == self.API_FAMILY_EMBEDDINGS and self.max_output_tokens:
            raise ValidationError({"max_output_tokens": "Embedding 模型不应配置输出 tokens 限制"})

    def save(self, *args, **kwargs):
        """
        保存前做轻量字段标准化
        
        - 默认模型唯一性不在 model.save() 中处理，因为它需要分布式锁保护
        """
        self.model_name = self.model_name.strip()
        self.display_name = self.display_name.strip()
        self.currency = self.currency.strip().upper()
        self.remark = self.remark.strip()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.display_name or self.model_name} - {self.provider.name}"
    
class OpenAIUsageLog(models.Model):
    """
    OpenAI API 调用日志
    
    用途:
    - 审计
    - 排障
    - token 用量统计
    - 成本估算
    - 用户用量看板
    - 与 MongoDB 对话内容建立关联

    设计原则:
    - MySQL 中只保存调用事实和脱敏摘要
    - 不保存 prompt / message / response 正文
    - conversation_id / message_id 只用于关联 MongoDB 文档
    """
    OP_RESPONSES = "responses"
    OP_CHAT_COMPLETIONS = "chat_completions"
    OP_EMBEDDINGS = "embeddings"
    OP_IMAGES = "images"
    OP_AUDIO = "audio"
    OP_REALTIME = "realtime"
    OP_OTHER = "other"

    OPERATION_CHOICES = (
        (OP_RESPONSES, "Responses"),
        (OP_CHAT_COMPLETIONS, "Chat Completions"),
        (OP_EMBEDDINGS, "Embeddings"),
        (OP_IMAGES, "Images"),
        (OP_AUDIO, "Audio"),
        (OP_REALTIME, "Realtime"),
        (OP_OTHER, "其他"),
    )

    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_TIMEOUT = "timeout"
    STATUS_CANCELLED = "cancelled"

    STATUS_CHOICES = (
        (STATUS_SUCCESS, "成功"),
        (STATUS_FAILED, "失败"),
        (STATUS_TIMEOUT, "超时"),
        (STATUS_CANCELLED, "取消"),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="openai_usage_logs",
        verbose_name="调用用户",
        help_text="发起调用的用户。用户删除后日志保留，外键置空",
    )
    provider = models.ForeignKey(
        OpenAIProviderConfig,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_logs",
        verbose_name="Provider",
        help_text="本次调用使用的 Provider。Provider 删除后保留快照字段",
    )
    model_config = models.ForeignKey(
        OpenAIModelConfig,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="usage_logs",
        verbose_name="模型配置",
        help_text="本次调用使用的模型配置。模型配置删除后保留快照字段",
    )

    provider_name = models.CharField(
        "Provider 快照",
        max_length=64,
        db_index=True,
        help_text="调用发生时的 Provider 标识快照",
    )
    provider_type = models.CharField(
        "Provider 类型快照",
        max_length=32,
        blank=True,
        default="",
        db_index=True,
        help_text="调用发生时的 Provider 类型快照",
    )
    model_name = models.CharField(
        "模型名称快照",
        max_length=128,
        db_index=True,
        help_text="调用发生时的模型名称快照",
    )
    api_operation = models.CharField(
        "API 操作",
        max_length=64,
        choices=OPERATION_CHOICES,
        default=OP_RESPONSES,
        db_index=True,
        help_text="本次调用的 OpenAI API 类型",
    )
    status = models.CharField(
        "调用状态",
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_SUCCESS,
        db_index=True,
    )

    request_id = models.CharField(
        "内部请求 ID",
        max_length=128,
        blank=True,
        default="",
        db_index=True,
        help_text="系统内部 request_id / trace_id",
    )
    openai_request_id = models.CharField(
        "OpenAI Request ID",
        max_length=128,
        blank=True,
        default="",
        db_index=True,
        help_text="OpenAI 响应头 x-request-id，用于官方支持和生产排障",
    )
    provider_response_id = models.CharField(
        "Provider 响应 ID",
        max_length=128,
        blank=True,
        default="",
        db_index=True,
        help_text="OpenAI 返回的 resp_xxx / chatcmpl_xxx 等响应 ID",
    )
    idempotency_key = models.CharField(
        "幂等键",
        max_length=128,
        blank=True,
        default="",
        db_index=True,
        help_text="业务侧幂等键。没有幂等控制时为空",
    )
    conversation_id = models.CharField(
        "会话 ID",
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        help_text="MongoDB conversation 文档 ID；不保存会话正文",
    )
    message_id = models.CharField(
        "消息 ID",
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        help_text="MongoDB conversation_message 文档 ID；不保存消息正文",
    )
    request_body_hash = models.CharField(
        "请求体 Hash",
        max_length=128,
        blank=True,
        default="",
        help_text="请求体脱敏后的 hash，用于排障去重；不要保存 prompt 明文",
    )
    safety_identifier_hash = models.CharField(
        "安全标识 Hash",
        max_length=128,
        blank=True,
        default="",
        help_text="对用户安全标识做 hash 后保存，避免记录邮箱、用户名等明文",
    )

    input_tokens = models.PositiveIntegerField(
        "输入 Tokens",
        default=0,
        help_text="Responses API 的 input_tokens；Chat Completions 的 prompt_tokens 应映射到这里",
    )
    output_tokens = models.PositiveIntegerField(
        "输出 Tokens",
        default=0,
        help_text="Responses API 的 output_tokens；Chat Completions 的 completion_tokens 应映射到这里",
    )
    total_tokens = models.PositiveIntegerField(
        "总 Tokens",
        default=0,
    )
    input_cached_tokens = models.PositiveIntegerField(
        "缓存命中输入 Tokens",
        default=0,
        help_text="input_tokens_details.cached_tokens 或 prompt_tokens_details.cached_tokens",
    )
    input_audio_tokens = models.PositiveIntegerField(
        "音频输入 Tokens",
        default=0,
    )
    output_audio_tokens = models.PositiveIntegerField(
        "音频输出 Tokens",
        default=0,
    )
    output_reasoning_tokens = models.PositiveIntegerField(
        "推理 Tokens",
        default=0,
        help_text="output_tokens_details.reasoning_tokens 或 completion_tokens_details.reasoning_tokens",
    )
    accepted_prediction_tokens = models.PositiveIntegerField(
        "命中预测 Tokens",
        default=0,
        help_text="Predicted Outputs 命中的 tokens",
    )
    rejected_prediction_tokens = models.PositiveIntegerField(
        "未命中预测 Tokens",
        default=0,
        help_text="Predicted Outputs 未命中的 tokens",
    )

    latency_ms = models.PositiveIntegerField(
        "端到端耗时毫秒",
        null=True,
        blank=True,
        help_text="从 service 发起请求到收到最终响应的耗时",
    )
    provider_processing_ms = models.PositiveIntegerField(
        "Provider 处理耗时毫秒",
        null=True,
        blank=True,
        help_text="OpenAI 响应头 openai-processing-ms",
    )
    http_status_code = models.PositiveIntegerField(
        "HTTP 状态码",
        null=True,
        blank=True,
        help_text="OpenAI API 返回的 HTTP 状态码。网络错误时可为空",
    )
    service_tier = models.CharField(
        "实际服务层级",
        max_length=32,
        blank=True,
        default="",
        db_index=True,
        help_text="OpenAI 返回的 service_tier，例如 default、flex、priority",
    )
    system_fingerprint = models.CharField(
        "System Fingerprint",
        max_length=128,
        blank=True,
        default="",
        help_text="后端配置指纹。兼容历史响应字段，不作为核心业务依赖",
    )
    finish_reason = models.CharField(
        "结束原因",
        max_length=64,
        blank=True,
        default="",
        help_text="例如 stop、length、tool_calls、content_filter",
    )
    incomplete_reason = models.CharField(
        "不完整原因",
        max_length=128,
        blank=True,
        default="",
        help_text="Responses API incomplete_details 或内部归一化后的不完整原因",
    )
    error_code = models.CharField(
        "错误码",
        max_length=128,
        blank=True,
        default="",
        db_index=True,
        help_text="OpenAI 或系统内部错误码。成功时为空",
    )
    error_message = models.CharField(
        "错误信息",
        max_length=512,
        blank=True,
        default="",
        help_text="脱敏后的错误摘要，不要记录 API Key、prompt 明文或用户敏感数据",
    )
    rate_limit_snapshot = models.JSONField(
        "限流响应头快照",
        default=dict,
        blank=True,
        help_text="脱敏保存 x-ratelimit-* 响应头，便于排查限流问题",
    )
    client_ip = models.GenericIPAddressField(
        "客户端 IP",
        null=True,
        blank=True,
    )
    user_agent = models.CharField(
        "User-Agent",
        max_length=512,
        blank=True,
        default="",
    )
    extra = models.JSONField(
        "扩展信息",
        default=dict,
        blank=True,
        help_text="少量脱敏扩展字段，例如业务场景、租户、trace 标签",
    )
    created_at = models.DateTimeField(
        "调用时间",
        default=timezone.now,
        db_index=True,
    )

    class Meta:
        db_table = "openai_api_usage_log"
        verbose_name = "OpenAI API 调用日志"
        verbose_name_plural = "OpenAI API 调用日志"
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["user", "-created_at"], name="idx_oai_usage_user_time"),
            models.Index(fields=["model_name", "-created_at"], name="idx_oai_usage_model_time"),
            models.Index(fields=["provider_name", "-created_at"], name="idx_oai_usage_provider_time"),
            models.Index(fields=["status", "-created_at"], name="idx_oai_usage_status_time"),
            models.Index(fields=["api_operation", "-created_at"], name="idx_oai_usage_api_time"),
            models.Index(fields=["conversation_id", "-created_at"], name="idx_oai_usage_conv_time"),
            models.Index(fields=["message_id"], name="idx_oai_usage_message"),
            models.Index(fields=["openai_request_id"], name="idx_oai_usage_openai_req"),
        ]

    def __str__(self):
        user_part = getattr(self, "user_id", None) or "anonymous"
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} user={user_part} model={self.model_name} status={self.status}"