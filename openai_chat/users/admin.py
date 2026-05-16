"""
用户模块 Django Admin 配置。

职责:
1. 注册 User / UserProfile / UserLoginRecord / AdminAuditLog 到 Django Admin。
2. 控制后台用户创建、编辑、权限变更、逻辑删除、TOTP 重置等管理行为。
3. 对用户状态、权限、密码、TOTP 等高风险写操作加用户粒度分布式锁。
4. 在敏感字段变更后同步 Redis 用户状态事实源，并强制旧 JWT token 失效。
5. 对成功完成的 Admin 写操作写入 AdminAuditLog。
6. 登录记录和 Admin 审计日志均作为审计数据处理，只允许查看。
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, cast

from django import forms
from django.contrib import admin, messages
from django.contrib.admin.options import IS_POPUP_VAR
from django.contrib.admin.utils import unquote
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import AdminPasswordChangeForm, ReadOnlyPasswordHashField
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import QuerySet
from django.http import Http404, HttpRequest, HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.html import escape
from django.utils.translation import gettext
from django.views.decorators.debug import sensitive_post_parameters

from openai_chat.settings.utils.locks import build_lock
from users.models.user_models import AdminAuditLog, User, UserLoginRecord, UserProfile
from users.services.admin_audit_service import AdminAuditService
from users.services.user_state_service import UserStateService


sensitive_post_parameters_m = method_decorator(sensitive_post_parameters())

# 后台用户写操作锁 TTL，单位毫秒。
USER_ADMIN_LOCK_TTL_MS = 10_000

# 影响账号生命周期的字段。
USER_STATE_FIELDS = {"is_active", "is_deleted"}

# 影响 JWT scope / 后台权限的字段。
USER_M2M_PERMISSION_FIELDS = {"groups", "user_permissions"}
USER_PERMISSION_FIELDS = {"is_staff", "is_superuser"} | USER_M2M_PERMISSION_FIELDS

# 变更后必须强制失效旧 token 的字段。
USER_SESSION_SENSITIVE_FIELDS = (
    USER_STATE_FIELDS
    | USER_PERMISSION_FIELDS
    | {"password", "totp_enabled", "totp_secret"}
)

# 禁止管理员对自己执行的高风险字段修改。
SELF_PROTECTED_FIELDS = USER_STATE_FIELDS | USER_PERMISSION_FIELDS

# User 主表允许写入审计快照的标量字段。
USER_AUDIT_SCALAR_FIELDS = {
    "email",
    "username",
    "phone",
    "organization",
    "is_active",
    "is_staff",
    "is_superuser",
    "is_deleted",
    "totp_enabled",
    "totp_secret",
    "password",
}

# UserProfile 允许写入审计快照的字段。
USER_PROFILE_AUDIT_FIELDS = {
    "avatar",
    "gender",
    "birthday",
    "bio",
}


def get_user_admin_lock_key(user_id: int | str) -> str:
    """
    后台用户写操作分布式锁 key。

    同一个用户的状态、权限、密码、TOTP、扩展资料写操作统一使用同一把锁，
    避免多个管理员并发修改同一用户时发生状态覆盖。
    """
    return f"lock:admin:user:{user_id}"


class UserCreationForm(forms.ModelForm):
    """
    后台创建用户专用表单。

    password1/password2 只用于输入和确认；保存时必须调用 set_password()，
    禁止把明文密码直接写入数据库。
    """

    password1 = forms.CharField(label="密码", widget=forms.PasswordInput)
    password2 = forms.CharField(label="确认密码", widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = (
            "email",
            "username",
            "phone",
            "organization",
            "is_active",
            "is_staff",
            "is_superuser",
        )

    def clean_password2(self):
        """
        校验两次密码输入是否一致。
        """
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("两次输入的密码不一致!")

        return password2

    def save(self, commit=True):
        """
        创建用户时使用 Django 标准 set_password() 生成安全哈希。
        """
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])

        if commit:
            user.save()

        return user


class UserChangeForm(forms.ModelForm):
    """
    后台编辑用户专用表单。

    password 使用只读哈希字段展示；修改密码必须走 Django Admin 独立密码修改入口。
    """

    password = ReadOnlyPasswordHashField(
        label="密码(哈希)",
        help_text="原始密码不会被保存, 无法查看明文",
    )

    class Meta:
        model = User
        fields = "__all__"

    def clean(self):
        """
        约束逻辑删除状态。

        逻辑删除用户必须同时禁用账户，避免已删除用户仍可登录或被签发 token。
        """
        cleaned_data = super().clean()

        is_deleted = bool(cleaned_data.get("is_deleted"))
        is_active = bool(cleaned_data.get("is_active"))

        if is_deleted and is_active:
            raise forms.ValidationError("逻辑删除用户时, 必须同时禁用账户!")

        return cleaned_data


class UserAdminPasswordChangeForm(AdminPasswordChangeForm):
    """
    后台修改用户密码专用表单。

    表单层负责密码保存、Redis 状态同步和旧 token 失效。
    审计日志放在 CustomUserAdmin.user_change_password() 中写，因为那里能拿到 request。
    """

    def save(self, commit=True):
        """
        保存后台修改后的新密码，并在提交后失效该用户旧 token。
        """
        managed_user = cast(User, self.user)
        user_id = int(managed_user.pk)
        lock_key = get_user_admin_lock_key(user_id)

        with build_lock(lock_key, ttl=USER_ADMIN_LOCK_TTL_MS, strategy="safe").lock() as acquired:
            if not acquired:
                raise RuntimeError("当前用户正在被其他后台操作修改, 请稍后重试")

            with transaction.atomic():
                super().save(commit=commit)

                if commit:
                    UserStateService.sync_to_redis(managed_user)
                    UserStateService.invalidate_sessions(
                        user_id,
                        reason="admin_change_password",
                    )

                return managed_user


class UserProfileInline(admin.StackedInline):
    """
    用户详情页内联资料区。

    目的:
    - 合并“用户列表”和“用户资料”两个后台入口。
    - 管理员在用户详情页即可查看和维护扩展资料。
    - 不允许在用户详情页删除资料记录，资料生命周期跟随 User。
    """

    model = UserProfile
    can_delete = False
    extra = 0
    max_num = 1
    verbose_name = "用户资料"
    verbose_name_plural = "用户资料"

    fields = (
        "avatar",
        "gender",
        "birthday",
        "bio",
        "updated_at",
    )
    readonly_fields = (
        "updated_at",
    )

    def has_add_permission(self, request, obj=None):
        """
        不在页面上显示额外新增表单。

        缺失的资料记录由 CustomUserAdmin.changeform_view() 在进入用户详情页前自动补齐，
        这样内联区域始终只编辑一条真实存在的 UserProfile，避免 SimpleUI 渲染空表单占位框。
        """
        return False

    def has_delete_permission(self, request, obj=None):
        """
        用户资料与用户主表生命周期绑定，不允许在后台删除。
        """
        return False


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    User 模型后台管理。

    核心策略:
    - 禁止后台物理删除用户，统一走 is_deleted 逻辑删除。
    - 非超级管理员不能修改账号状态、权限、TOTP 等敏感字段。
    - 超级管理员也不能通过后台批量动作修改自己的高风险状态。
    - 所有成功写操作接入 AdminAuditLog。
    """

    form = UserChangeForm
    add_form = UserCreationForm
    change_password_form = UserAdminPasswordChangeForm
    model = User
    inlines = (UserProfileInline,)

    save_on_top = True
    date_hierarchy = "date_joined"
    show_full_result_count = False
    empty_value_display = "-"

    list_display = (
        "id",
        "email",
        "username",
        "phone",
        "organization",
        "is_active",
        "is_staff",
        "is_superuser",
        "totp_status",
        "is_deleted",
        "date_joined",
        "last_login",
        "last_login_ip",
    )

    list_filter = (
        "is_active",
        "is_staff",
        "is_superuser",
        "totp_enabled",
        "is_deleted",
        "date_joined",
        "last_login",
    )

    search_fields = (
        "id",
        "email",
        "username",
        "phone",
    )

    ordering = ("-date_joined",)
    list_per_page = 15

    filter_horizontal = (
        "groups",
        "user_permissions",
    )

    readonly_fields = (
        "id",
        "password",
        "date_joined",
        "last_login",
        "last_login_ip",
    )

    actions = (
        "enable_users",
        "disable_users",
        "logic_delete_users",
        "restore_users",
        "force_logout_users",
        "reset_totp_users",
    )

    fieldsets = (
        (
            "基础信息",
            {
                "fields": (
                    "id",
                    "email",
                    "username",
                    "password",
                    "phone",
                    "organization",
                )
            },
        ),
        (
            "账号状态",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "is_deleted",
                )
            },
        ),
        (
            "TOTP二次验证",
            {
                "fields": (
                    "totp_status",
                )
            },
        ),
        (
            "权限",
            {
                "fields": (
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (
            "登录与审计信息",
            {
                "fields": (
                    "date_joined",
                    "last_login",
                    "last_login_ip",
                )
            },
        ),
    )

    add_fieldsets = (
        (
            "创建用户",
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "username",
                    "phone",
                    "organization",
                    "password1",
                    "password2",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                ),
            },
        ),
    )

    @staticmethod
    def _is_self_target(request: HttpRequest, user: User) -> bool:
        """
        判断当前管理员是否正在操作自己。
        """
        current_user_id = getattr(request.user, "pk", None)
        target_user_id = getattr(user, "pk", None)

        if current_user_id is None or target_user_id is None:
            return False

        return int(current_user_id) == int(target_user_id)

    @staticmethod
    def _get_existing_user(user_id: int | str) -> User | None:
        """
        读取保存前的用户对象，用于构建 before 快照。
        """
        if not user_id:
            return None

        return User.objects.filter(pk=user_id).first()

    @staticmethod
    def _ensure_user_profile(user_id: int | str | None) -> None:
        """
        确保指定用户已经有一条扩展资料。

        用户资料已经合并进用户详情页展示；进入详情页前补齐资料行，可以避免
        Django Admin inline 渲染额外的空新增表单。
        """
        if not user_id:
            return

        UserProfile.objects.get_or_create(user_id=user_id)

    def _require_superuser(self, request: HttpRequest) -> bool:
        """
        高危后台操作只允许超级管理员执行。
        """
        if request.user.is_superuser:
            return True

        self.message_user(
            request,
            "该操作仅允许超级管理员执行",
            level=messages.ERROR,
        )
        return False

    @admin.display(boolean=True, description="TOTP状态")
    def totp_status(self, obj: User) -> bool:
        """
        列表页 / 详情页展示用户是否完成 TOTP 绑定。
        """
        return bool(obj.totp_enabled and obj.totp_secret)

    @contextmanager
    def _user_write_lock(
        self,
        request: HttpRequest,
        identity: int | str,
    ) -> Iterator[None]:
        """
        用户写操作分布式锁上下文。

        Django Admin 编辑页会依次调用 save_model / save_related。
        同一个请求已经持有同一用户锁时复用锁边界，避免重复抢同一把非重入锁。
        """
        lock_key = get_user_admin_lock_key(identity)

        if getattr(request, "_user_admin_lock_key", None) == lock_key:
            yield
            return

        with build_lock(lock_key, ttl=USER_ADMIN_LOCK_TTL_MS, strategy="safe").lock() as acquired:
            if not acquired:
                raise RuntimeError("当前用户正在被其他后台操作修改，请稍后重试")

            setattr(request, "_user_admin_lock_key", lock_key)
            try:
                yield
            finally:
                if getattr(request, "_user_admin_lock_key", None) == lock_key:
                    delattr(request, "_user_admin_lock_key")

    def get_readonly_fields(self, request, obj=None):
        """
        根据当前管理员权限动态控制只读字段。

        普通 staff 不能修改账号状态、后台权限、TOTP 等敏感字段。
        """
        readonly_fields = list(super().get_readonly_fields(request, obj))
        readonly_fields.append("totp_status")

        if not request.user.is_superuser:
            readonly_fields.extend(
                [
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "is_deleted",
                    "totp_enabled",
                    "totp_secret",
                ]
            )

        return tuple(dict.fromkeys(readonly_fields))

    def get_fieldsets(
        self,
        request: HttpRequest,
        obj: Any | None = None,
    ) -> list[tuple[str | None, dict[str, Any]]]:
        """
        根据当前管理员权限动态控制字段分组。

        普通 staff 隐藏账号状态、后台权限和 TOTP 敏感字段；空分组不展示。
        """
        fieldsets = super().get_fieldsets(request, obj)

        if request.user.is_superuser:
            return fieldsets

        hidden_fields = {
            "is_active",
            "is_staff",
            "is_superuser",
            "is_deleted",
            "totp_enabled",
            "totp_secret",
            "groups",
            "user_permissions",
        }

        cleaned_fieldsets: list[tuple[str | None, dict[str, Any]]] = []

        for title, options in fieldsets:
            fields = options.get("fields", ())
            filtered_fields = tuple(
                field for field in fields if field not in hidden_fields
            )

            if not filtered_fields:
                continue

            cleaned_fieldsets.append(
                (
                    title,
                    {
                        **options,
                        "fields": filtered_fields,
                    },
                )
            )

        return cleaned_fieldsets

    def get_actions(self, request):
        """
        控制列表页批量动作。

        - 移除 Django 默认物理删除动作。
        - 非超级管理员不展示高危批量动作。
        """
        actions = super().get_actions(request)
        actions.pop("delete_selected", None)

        if not request.user.is_superuser:
            for action_name in (
                "enable_users",
                "disable_users",
                "logic_delete_users",
                "restore_users",
                "force_logout_users",
                "reset_totp_users",
            ):
                actions.pop(action_name, None)

        return actions

    def has_delete_permission(self, request, obj=None):
        """
        禁止后台物理删除用户。
        """
        return False

    def changeform_view(self, request, object_id=None, form_url="", extra_context=None):
        """
        用户新增 / 编辑页视图。

        写请求包事务；已有用户写请求额外加用户粒度锁。
        只读 GET 不包事务，降低后台浏览页面的数据库连接占用。
        """
        self._ensure_user_profile(object_id)

        if request.method in {"POST", "PUT", "PATCH"} and object_id:
            with self._user_write_lock(request, object_id):
                with transaction.atomic():
                    return super().changeform_view(
                        request,
                        object_id=object_id,
                        form_url=form_url,
                        extra_context=extra_context,
                    )

        if request.method in {"POST", "PUT", "PATCH"}:
            with transaction.atomic():
                return super().changeform_view(
                    request,
                    object_id=object_id,
                    form_url=form_url,
                    extra_context=extra_context,
                )

        return super().changeform_view(
            request,
            object_id=object_id,
            form_url=form_url,
            extra_context=extra_context,
        )

    def save_model(self, request, obj, form, change):
        """
        保存 User 主表字段，并写入审计日志。

        新建用户记录 create；修改用户只记录实际变化的标量字段。
        groups / user_permissions 在 save_related() 中单独审计。
        """
        changed_fields = set(getattr(form, "changed_data", []) or [])
        scalar_sensitive_fields = USER_SESSION_SENSITIVE_FIELDS - USER_M2M_PERMISSION_FIELDS
        scalar_changed_fields = sorted(
            (changed_fields & USER_AUDIT_SCALAR_FIELDS) - USER_M2M_PERMISSION_FIELDS
        )

        if changed_fields & scalar_sensitive_fields and not request.user.is_superuser:
            raise PermissionDenied("只有超级管理员权限可修改用户状态、权限或TOTP配置")

        if (
            change
            and self._is_self_target(request, obj)
            and changed_fields & (SELF_PROTECTED_FIELDS - USER_M2M_PERMISSION_FIELDS)
        ):
            raise PermissionDenied("不允许修改自己的账号状态或后台权限")

        lock_identity = obj.pk or obj.email

        with self._user_write_lock(request, lock_identity):
            old_obj = self._get_existing_user(obj.pk) if change else None
            before = (
                AdminAuditService.build_model_snapshot(old_obj, scalar_changed_fields)
                if old_obj and scalar_changed_fields
                else {}
            )

            super().save_model(request, obj, form, change)
            UserStateService.sync_to_redis(obj)

            if change and changed_fields & scalar_sensitive_fields:
                UserStateService.invalidate_sessions(
                    int(obj.pk),
                    reason="admin_user_scalar_sensitive_changed",
                )

            if change:
                if scalar_changed_fields:
                    after = AdminAuditService.build_model_snapshot(obj, scalar_changed_fields)
                    AdminAuditService.log_admin_write(
                        request=request,
                        action=AdminAuditLog.ACTION_UPDATE,
                        reason="admin_user_update",
                        target=obj,
                        changed_fields=scalar_changed_fields,
                        before=before,
                        after=after,
                    )
                return

            created_fields = sorted(
                (set(form.fields.keys()) & USER_AUDIT_SCALAR_FIELDS) | {"password"}
            )
            after = AdminAuditService.build_model_snapshot(obj, created_fields)

            AdminAuditService.log_admin_write(
                request=request,
                action=AdminAuditLog.ACTION_CREATE,
                reason="admin_create_user",
                target=obj,
                changed_fields=created_fields,
                before={},
                after=after,
            )

    def save_related(self, request, form, formsets, change):
        """
        保存 User 相关对象、用户资料内联表单和 M2M 字段。

        审计范围:
        - groups / user_permissions 变化。
        - 用户详情页内联 UserProfile 新增 / 修改。
        """
        obj = form.instance
        changed_fields = set(getattr(form, "changed_data", []) or [])
        m2m_changed_fields = sorted(changed_fields & USER_M2M_PERMISSION_FIELDS)

        if changed_fields & USER_M2M_PERMISSION_FIELDS and not request.user.is_superuser:
            raise PermissionDenied("只有超级管理员可以修改用户组或用户权限")

        if (
            change
            and self._is_self_target(request, obj)
            and changed_fields & USER_M2M_PERMISSION_FIELDS
        ):
            raise PermissionDenied("不允许修改自己的用户组或直接权限")

        with self._user_write_lock(request, obj.pk):
            m2m_before = (
                AdminAuditService.build_m2m_snapshot(obj, m2m_changed_fields)
                if change and m2m_changed_fields
                else {}
            )
            profile_audits = self._collect_profile_inline_audits(formsets)

            super().save_related(request, form, formsets, change)

            if change and m2m_changed_fields:
                UserStateService.invalidate_sessions(
                    int(obj.pk),
                    reason="admin_user_permission_changed",
                )

                after = AdminAuditService.build_m2m_snapshot(obj, m2m_changed_fields)
                AdminAuditService.log_admin_write(
                    request=request,
                    action=AdminAuditLog.ACTION_UPDATE,
                    reason="admin_user_permission_changed",
                    target=obj,
                    changed_fields=m2m_changed_fields,
                    before=m2m_before,
                    after=after,
                )

            self._write_profile_inline_audits(request, profile_audits)

    @staticmethod
    def _collect_profile_inline_audits(formsets) -> list[dict[str, Any]]:
        """
        在内联表单保存前收集 UserProfile 变更信息。

        save_related() 调用 super() 后，内联对象已经写库；因此 before 快照必须在
        super().save_related() 之前读取，after 快照在保存后从 form.instance 读取。
        """
        audits: list[dict[str, Any]] = []

        for formset in formsets:
            if getattr(formset, "model", None) is not UserProfile:
                continue

            for inline_form in formset.forms:
                if not inline_form.has_changed():
                    continue

                if inline_form.cleaned_data.get("DELETE"):
                    continue

                changed_fields = sorted(
                    set(getattr(inline_form, "changed_data", []) or [])
                    & USER_PROFILE_AUDIT_FIELDS
                )
                if not changed_fields:
                    continue

                profile = inline_form.instance
                old_profile = (
                    UserProfile.objects.filter(pk=profile.pk).first()
                    if profile.pk
                    else None
                )
                before = (
                    AdminAuditService.build_model_snapshot(old_profile, changed_fields)
                    if old_profile
                    else {}
                )

                audits.append(
                    {
                        "profile": profile,
                        "is_create": old_profile is None,
                        "changed_fields": changed_fields,
                        "before": before,
                    }
                )

        return audits

    @staticmethod
    def _write_profile_inline_audits(
        request: HttpRequest,
        audits: list[dict[str, Any]],
    ) -> None:
        """
        写入用户详情页内联 UserProfile 审计日志。
        """
        for audit in audits:
            profile = audit["profile"]
            changed_fields = audit["changed_fields"]
            after = AdminAuditService.build_model_snapshot(profile, changed_fields)

            AdminAuditService.log_admin_write(
                request=request,
                action=(
                    AdminAuditLog.ACTION_CREATE
                    if audit["is_create"]
                    else AdminAuditLog.ACTION_UPDATE
                ),
                reason=(
                    "admin_create_user_profile"
                    if audit["is_create"]
                    else "admin_user_profile_update"
                ),
                target=profile,
                changed_fields=changed_fields,
                before=audit["before"],
                after=after,
            )

    def _apply_user_flags(
        self,
        request: HttpRequest,
        queryset: QuerySet[User],
        *,
        flags: dict[str, bool],
        reason: str,
        success_message: str,
    ) -> None:
        """
        批量修改用户状态字段。

        每个用户单独加分布式锁和数据库行锁；成功修改后同步 Redis、失效旧 token、
        并写入一条 AdminAuditLog。
        """
        if not self._require_superuser(request):
            return

        updated_count = 0
        skipped_count = 0
        changed_field_names = sorted(flags.keys())

        for raw_user in queryset.only("id"):
            with transaction.atomic():
                lock_key = get_user_admin_lock_key(raw_user.id)

                with build_lock(lock_key, ttl=USER_ADMIN_LOCK_TTL_MS, strategy="safe").lock() as acquired:
                    if not acquired:
                        skipped_count += 1
                        continue

                    user = User.objects.select_for_update().get(pk=raw_user.pk)

                    if self._is_self_target(request, user):
                        skipped_count += 1
                        continue

                    before = AdminAuditService.build_model_snapshot(user, changed_field_names)
                    changed = False

                    for field, value in flags.items():
                        if getattr(user, field) != value:
                            setattr(user, field, value)
                            changed = True

                    if not changed:
                        skipped_count += 1
                        continue

                    user.save(update_fields=changed_field_names)

                    UserStateService.sync_to_redis(user)
                    UserStateService.invalidate_sessions(
                        int(user.pk),
                        reason=reason,
                    )

                    after = AdminAuditService.build_model_snapshot(user, changed_field_names)
                    AdminAuditService.log_admin_write(
                        request=request,
                        action=AdminAuditLog.ACTION_ADMIN_ACTION,
                        reason=reason,
                        target=user,
                        changed_fields=changed_field_names,
                        before=before,
                        after=after,
                    )

                    updated_count += 1

        self.message_user(
            request,
            f"{success_message}：成功 {updated_count} 个，跳过 {skipped_count} 个",
            level=messages.SUCCESS,
        )

    @admin.action(description="启用所选用户")
    def enable_users(self, request, queryset):
        self._apply_user_flags(
            request,
            queryset,
            flags={"is_active": True},
            reason="admin_enable_user",
            success_message="启用用户完成",
        )

    @admin.action(description="禁用所选用户")
    def disable_users(self, request, queryset):
        self._apply_user_flags(
            request,
            queryset,
            flags={"is_active": False},
            reason="admin_disable_user",
            success_message="禁用用户完成",
        )

    @admin.action(description="逻辑删除所选用户")
    def logic_delete_users(self, request, queryset):
        self._apply_user_flags(
            request,
            queryset,
            flags={"is_active": False, "is_deleted": True},
            reason="admin_logic_delete_user",
            success_message="逻辑删除用户完成",
        )

    @admin.action(description="恢复所选逻辑删除用户")
    def restore_users(self, request, queryset):
        self._apply_user_flags(
            request,
            queryset,
            flags={"is_deleted": False},
            reason="admin_restore_user",
            success_message="恢复用户完成",
        )

    @admin.action(description="强制下线所选用户")
    def force_logout_users(self, request, queryset):
        """
        批量强制全端重新登录。

        该动作不修改 User 表字段，只递增 Redis 用户状态中的 sess_ver。
        """
        if not self._require_superuser(request):
            return

        updated_count = 0
        skipped_count = 0

        for raw_user in queryset.only("id", "email"):
            lock_key = get_user_admin_lock_key(raw_user.id)

            with build_lock(lock_key, ttl=USER_ADMIN_LOCK_TTL_MS, strategy="safe").lock() as acquired:
                if not acquired:
                    skipped_count += 1
                    continue

                if int(raw_user.id) == int(request.user.id):
                    skipped_count += 1
                    continue

                UserStateService.invalidate_sessions(
                    int(raw_user.id),
                    reason="admin_force_logout_user",
                )

                AdminAuditService.log_admin_write(
                    request=request,
                    action=AdminAuditLog.ACTION_FORCE_LOGOUT,
                    reason="admin_force_logout_user",
                    target=raw_user,
                    changed_fields=["sessions"],
                    before={},
                    after={"sessions": "invalidated"},
                )

                updated_count += 1

        self.message_user(
            request,
            f"强制下线用户完成：成功 {updated_count} 个，跳过 {skipped_count} 个",
            level=messages.SUCCESS,
        )

    @admin.action(description="重置所选用户TOTP")
    def reset_totp_users(self, request, queryset):
        """
        清空 TOTP 绑定并强制重新登录。

        后台不直接编辑 TOTP secret，用户需通过前台绑定流程重新启用。
        """
        if not self._require_superuser(request):
            return

        updated_count = 0
        skipped_count = 0
        changed_fields = ["totp_enabled", "totp_secret"]

        for raw_user in queryset.only("id"):
            with transaction.atomic():
                lock_key = get_user_admin_lock_key(raw_user.id)

                with build_lock(lock_key, ttl=USER_ADMIN_LOCK_TTL_MS, strategy="safe").lock() as acquired:
                    if not acquired:
                        skipped_count += 1
                        continue

                    user = User.objects.select_for_update().get(pk=raw_user.pk)

                    if self._is_self_target(request, user):
                        skipped_count += 1
                        continue

                    if not user.totp_enabled and not user.totp_secret:
                        skipped_count += 1
                        continue

                    before = AdminAuditService.build_model_snapshot(user, changed_fields)

                    user.totp_enabled = False
                    user.totp_secret = None
                    user.save(update_fields=changed_fields)

                    UserStateService.sync_to_redis(user)
                    UserStateService.invalidate_sessions(
                        int(user.pk),
                        reason="admin_reset_totp_user",
                    )

                    after = AdminAuditService.build_model_snapshot(user, changed_fields)
                    AdminAuditService.log_admin_write(
                        request=request,
                        action=AdminAuditLog.ACTION_ADMIN_ACTION,
                        reason="admin_reset_totp_user",
                        target=user,
                        changed_fields=changed_fields,
                        before=before,
                        after=after,
                    )

                    updated_count += 1

        self.message_user(
            request,
            f"重置TOTP完成：成功 {updated_count} 个，跳过 {skipped_count} 个",
            level=messages.SUCCESS,
        )

    def delete_model(self, request, obj):
        """
        防御性兜底: 单个删除统一改为逻辑删除。
        """
        self._apply_user_flags(
            request,
            User.objects.filter(pk=obj.pk),
            flags={"is_active": False, "is_deleted": True},
            reason="admin_delete_model_fallback",
            success_message="逻辑删除用户完成",
        )

    def delete_queryset(self, request, queryset):
        """
        防御性兜底: 批量删除统一改为逻辑删除。
        """
        self._apply_user_flags(
            request,
            queryset,
            flags={"is_active": False, "is_deleted": True},
            reason="admin_delete_queryset_fallback",
            success_message="批量逻辑删除用户完成",
        )

    @sensitive_post_parameters_m
    def user_change_password(self, request, id, form_url=""):
        """
        覆盖 Django UserAdmin 的密码修改视图。

        密码表单负责保存密码和失效 token；这里在 form.save() 成功后补充审计日志，
        以便记录 actor、IP、UA、请求路径等 request 级信息。
        """
        user = self.get_object(request, unquote(id))

        if not self.has_change_permission(request, user):
            raise PermissionDenied

        if user is None:
            raise Http404(
                gettext("%(name)s object with primary key %(key)r does not exist.")
                % {
                    "name": self.opts.verbose_name,
                    "key": escape(id),
                }
            )

        if request.method == "POST":
            form = self.change_password_form(user, request.POST)

            if form.is_valid():
                valid_submission = (
                    form.cleaned_data["set_usable_password"]
                    or "unset-password" in request.POST
                )

                if not valid_submission:
                    msg = gettext("Conflicting form data submitted. Please try again.")
                    messages.error(request, msg)
                    return HttpResponseRedirect(request.get_full_path())

                user = form.save()
                change_message = self.construct_change_message(request, form, None)
                self.log_change(request, user, change_message)

                AdminAuditService.log_admin_write(
                    request=request,
                    action=AdminAuditLog.ACTION_PASSWORD_CHANGE,
                    reason="admin_change_password",
                    target=user,
                    changed_fields=["password"],
                    before={"password": AdminAuditService.MASKED_VALUE},
                    after={"password": AdminAuditService.MASKED_VALUE},
                )

                if user.has_usable_password():
                    msg = gettext("Password changed successfully.")
                else:
                    msg = gettext("Password-based authentication was disabled.")

                messages.success(request, msg)
                update_session_auth_hash(request, form.user)

                return HttpResponseRedirect(
                    reverse(
                        "%s:%s_%s_change"
                        % (
                            self.admin_site.name,
                            user._meta.app_label,
                            user._meta.model_name,
                        ),
                        args=(user.pk,),
                    )
                )
        else:
            form = self.change_password_form(user)

        fieldsets = [(None, {"fields": list(form.base_fields)})]
        admin_form = admin.helpers.AdminForm(form, fieldsets, {})

        if user.has_usable_password():
            title = gettext("Change password: %s")
        else:
            title = gettext("Set password: %s")

        context = {
            "title": title % escape(user.get_username()),
            "adminForm": admin_form,
            "form_url": form_url,
            "form": form,
            "is_popup": (IS_POPUP_VAR in request.POST or IS_POPUP_VAR in request.GET),
            "is_popup_var": IS_POPUP_VAR,
            "add": True,
            "change": False,
            "has_delete_permission": False,
            "has_change_permission": True,
            "has_absolute_url": False,
            "opts": self.opts,
            "original": user,
            "save_as": False,
            "show_save": True,
            **self.admin_site.each_context(request),
        }

        request.current_app = self.admin_site.name

        return TemplateResponse(
            request,
            self.change_user_password_template or "admin/auth/user/change_password.html",
            context,
        )


@admin.register(UserLoginRecord)
class UserLoginRecordAdmin(admin.ModelAdmin):
    """
    用户登录记录后台管理。

    登录记录属于审计数据，只允许查看，不允许后台新增、修改或删除。
    """

    list_display = (
        "id",
        "user",
        "login_ip",
        "login_type",
        "login_status",
        "platform",
        "location",
        "risk_flag",
        "login_time",
    )

    list_select_related = ("user",)
    date_hierarchy = "login_time"
    show_full_result_count = False
    empty_value_display = "-"

    search_fields = (
        "user__id",
        "user__email",
        "user__username",
        "login_ip",
        "platform",
        "location",
    )

    list_filter = (
        "login_status",
        "login_type",
        "risk_flag",
        "platform",
        "login_time",
    )

    readonly_fields = (
        "user",
        "login_ip",
        "login_type",
        "login_status",
        "fail_reason",
        "user_agent",
        "platform",
        "location",
        "login_time",
        "risk_flag",
    )

    ordering = ("-login_time",)
    list_per_page = 30

    def has_add_permission(self, request):
        """
        登录记录应由登录流程自动写入，后台不允许手工新增。
        """
        return False

    def has_change_permission(self, request, obj=None):
        """
        登录记录作为审计数据，只允许查看，不允许修改。
        """
        return False

    def has_view_permission(self, request, obj=None):
        """
        允许具备 view 权限的管理员查看登录记录。
        """
        return super().has_view_permission(request, obj=obj)

    def has_delete_permission(self, request, obj=None):
        """
        禁止后台删除登录记录。
        """
        return False


@admin.register(AdminAuditLog)
class AdminAuditLogAdmin(admin.ModelAdmin):
    """
    Admin 写操作审计日志后台管理。

    审计日志是安全证据链，只允许查看，禁止后台新增、修改或删除。
    """

    list_display = (
        "id",
        "created_at",
        "actor_identifier",
        "action",
        "reason",
        "target_model",
        "target_object_id",
        "ip_address",
    )

    list_filter = (
        "action",
        "target_model",
        "created_at",
    )

    search_fields = (
        "actor_identifier",
        "target_model",
        "target_object_id",
        "target_repr",
        "reason",
        "ip_address",
        "request_path",
    )

    readonly_fields = (
        "id",
        "actor",
        "actor_identifier",
        "action",
        "reason",
        "target_model",
        "target_object_id",
        "target_repr",
        "changed_fields",
        "before",
        "after",
        "ip_address",
        "user_agent",
        "request_path",
        "request_method",
        "created_at",
    )

    fieldsets = (
        (
            "操作信息",
            {
                "fields": (
                    "id",
                    "created_at",
                    "actor",
                    "actor_identifier",
                    "action",
                    "reason",
                )
            },
        ),
        (
            "目标对象",
            {
                "fields": (
                    "target_model",
                    "target_object_id",
                    "target_repr",
                )
            },
        ),
        (
            "变更内容",
            {
                "fields": (
                    "changed_fields",
                    "before",
                    "after",
                )
            },
        ),
        (
            "请求信息",
            {
                "fields": (
                    "ip_address",
                    "user_agent",
                    "request_path",
                    "request_method",
                )
            },
        ),
    )

    date_hierarchy = "created_at"
    ordering = ("-created_at",)
    list_select_related = ("actor",)
    show_full_result_count = False
    empty_value_display = "-"
    list_per_page = 30

    def has_add_permission(self, request):
        """
        审计日志不允许后台手工新增。
        """
        return False

    def has_change_permission(self, request, obj=None):
        """
        审计日志不允许后台修改。
        """
        return False

    def has_view_permission(self, request, obj=None):
        """
        允许具备 view 权限的管理员查看审计日志。
        """
        return super().has_view_permission(request, obj=obj)

    def has_delete_permission(self, request, obj=None):
        """
        审计日志不允许后台删除。
        """
        return False
