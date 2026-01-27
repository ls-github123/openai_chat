from django.db import models # ORM核心模块
from django.utils import timezone # 时间处理, 获取当前时间戳
from django.conf import settings # 获取 AUTH_USER_MODEL配置
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin # 自定义用户模型基类
from users.managers import CutsomUserManager # 自定义用户管理器,支持邮箱注册、权限设定
from openai_chat.settings.utils.snowflake import get_snowflake_id # 雪花算法模块:生成用户ID

# === 用户主模型 ===
class User(AbstractBaseUser, PermissionsMixin):
    """
    自定义用户模型:
    - 使用邮箱作为登录字段
    - 使用雪花算法生成唯一ID
    - 支持 is_staff/is_superuser 权限控制
    - 密码字段由 AbstractBaseUser 提供, 自动加密存储
    """
    # editable=False 该字段不会在Django管理后台或表单中显示,也不能被编辑器修改
    id = models.BigIntegerField('用户ID', primary_key=True, editable=False, help_text="雪花算法生成的用户ID")
    email = models.EmailField('邮箱地址', unique=True, null=False, blank=False, help_text="用于用户账户登录与验证")
    username = models.CharField('用户名', max_length=150, unique=True, null=False, blank=False, help_text="可选用户名")
    phone = models.CharField("手机号", max_length=20, null=True, blank=True, help_text="可选添加手机号")
    organization = models.BigIntegerField("组织ID", null=True, blank=True, help_text="所属组织/项目")
    
    is_active = models.BooleanField("账户是否启用", default=True)
    is_staff = models.BooleanField("后台管理员", default=False)
    is_superuser = models.BooleanField("超级管理员", default=False)
    
    totp_enabled = models.BooleanField("是否启用TOTP", default=False)
    totp_secret = models.CharField("TOTP密钥", max_length=64, null=True, blank=True)
    
    date_joined = models.DateTimeField("注册时间", null=False, default=timezone.now)
    last_login_ip = models.GenericIPAddressField("上次登录IP", null=True, blank=True)
    
    is_deleted = models.BooleanField("是否已逻辑删除", default=False)
    
    # 配置用户管理器
    objects = CutsomUserManager()
    
    # 配置Django登录字段与必须字段
    USERNAME_FIELD = 'email' # 指定登录标识字段(createsuperuser使用该字段作为登录账号)
    REQUIRED_FIELDS = ['username'] # 创建超级用户时,需额外填写的字段
    
    class Meta:
        db_table = 'users_user' # 模型在数据库中对应的表名
        verbose_name = '用户' # 后台管理界面模型单数名
        verbose_name_plural = '用户表' # 后台模型复数名
    
    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        """
        主键赋值策略:
        - 仅当新对象且 id 为空时生成 Snowflake ID
        - 避免 Django 启动期间实例化模型触发 get_default()
        """
        if self._state.adding and not self.id:
            self.id = get_snowflake_id()
        super().save(*args, **kwargs)

# === 用户资料模型 ===
class UserProfile(models.Model):
    """
    用户扩展资料表(与主User模型一对一绑定)
    - 包含性别、头像、生日、简介等非核心字段
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
        help_text="关联的主用户"
    )
    avatar = models.URLField("头像URL", null=True, blank=True, help_text="图片URL地址")
    gender = models.CharField("性别", max_length=10, choices=[("male", "男"), ("female", "女"), ("other", "其他")], default="other")
    birthday = models.DateField("生日", null=True, blank=True)
    bio = models.TextField("个性签名", null=True, blank=True)
    updated_at = models.DateTimeField("资料更新时间", auto_now=True)
    
    class Meta:
        db_table = "users_profile"
        verbose_name = "用户资料"
        verbose_name_plural = "用户资料"
        
    def __str__(self):
        return f"{self.user}的扩展资料"
    
# === 用户登录日志模型 ===
class UserLoginRecord(models.Model):
    """
    用户登录记录表
    - 用于追踪用户 登录历史/IP/设备信息
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="login_records",
        help_text="关联的用户"
    )
    login_ip = models.GenericIPAddressField("登录IP", null=True, blank=True)
    login_type = models.CharField("登录方式", max_length=64, null=True, blank=True, help_text="登录方式(如:password/totp/github/email-code等)")
    login_status = models.BooleanField("当前登录是否成功", default=True)
    fail_reason = models.CharField("失败原因", max_length=128, null=True, blank=True, help_text="如密码错误/验证码失效等")
    user_agent = models.CharField("浏览器UA", max_length=256, null=True, blank=True)
    platform = models.CharField("设备平台", max_length=64, null=True, blank=True, help_text="如IOS/Android/Windows等")
    location = models.CharField("基于IP的地理位置", max_length=64, null=True, blank=True)
    login_time = models.DateTimeField("登录时间", default=timezone.now)
    risk_flag = models.BooleanField("是否为风控标记登录", default=False)
    
    class Meta:
        db_table = 'users_login_record'
        verbose_name = '登录记录'
        verbose_name_plural = '用户登录记录'
    
    def __str__(self):
        return f"{self.user}的用户登录记录"