from django.urls import path
from .views import test_snowflake, TestRedisLockView, TestRedLockView, test_send_email

urlpatterns = [
    path('test_snowflake/', test_snowflake), # 测试雪花ID生成接口
    path('test_redis_lock/', TestRedisLockView.as_view()), # 测试 Redis 锁接口
    path('test_red_lock/', TestRedLockView.as_view()), # 测试 RedLock 接口
    path("test_send_email/", test_send_email), # 测试邮件异步发送
]