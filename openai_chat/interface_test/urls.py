from django.urls import path
from .views import test_snowflake

urlpatterns = [
    path('test_snowflake/', test_snowflake), # 测试雪花ID生成接口
]