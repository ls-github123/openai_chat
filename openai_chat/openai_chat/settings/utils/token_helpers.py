from users.models import User

def get_scope_for_user(user: User) -> str:
    """
    根据用户权限动态确定 access_token 的 scope 值
    """
    if user.is_superuser:
        return "super"
    elif user.is_staff:
        return "admin"
    return "user"