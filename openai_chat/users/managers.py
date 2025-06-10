from django.contrib.auth.base_user import BaseUserManager # django内置基础用户管理器

class CutsomUserManager(BaseUserManager):
    """
    自定义用户管理器:
    - 替代默认User.objects
    - 支持通过邮箱(email)创建普通用户和超级用户
    - 搭配自定义 User 模型(继承 AbstractBaseUser)使用
    """
    
    def create_user(self, email, password=None, **extra_fields):
        """
        创建普通用户方法
        参数:
        - email: str,用户邮箱地址(唯一身份标识)
        - password: str, set_password() (数据库中使用加密存储-bcrypt + SHA256密码哈希)
        - extra_fields: 其他可扩展字段
        
        返回:
        - user: 创建成功的用户对象实例 保存至数据库
        """
        if not email:
            raise ValueError("必须提供邮箱地址")
        
        if not password:
            raise ValueError("密码不能为空")
        
        email = self.normalize_email(email) # 邮箱格式规范化
        user = self.model(email=email, **extra_fields) # 通过绑定模型创建用户对象实例
        user.set_password(password) # 使用base.py中配置的加密器进行密码哈希加密
        user.save(using=self._db) # 保存对象,支持多数据库路由
        
        return user # 返回创建成功的用户对象实例
    
    def create_superuser(self, email, password=None, **extra_fields):
        """
        创建超级管理员用户
        
        自动设置:
        - is_staff = True
        - is_superuser = True
        
        返回:
        - 创建的超级用户对象实例
        """
        extra_fields.setdefault("is_staff", True) # 添加管理员权限
        extra_fields.setdefault("is_superuser", True) # 添加超级用户权限
        
        if not extra_fields.get("is_staff"):
            raise ValueError("超级用户必须设置 is_staff=True")
        if not extra_fields.get("is_superuser"):
            raise ValueError("超级用户必须设置 is_superuser=True")
        
        return self.create_user(email, password, **extra_fields)