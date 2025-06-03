from rest_framework.views import APIView
from rest_framework.response import Response
from openai_chat.settings.utils.locks import build_lock
from openai_chat.settings.utils.redis import get_redis_client
from django.http import JsonResponse
from openai_chat.settings.utils.snowflake import get_snowflake_id

def test_snowflake(request):
    """
    生成并返回一个全局唯一雪花ID(测试接口)
    """
    try:
        snowflake_id = get_snowflake_id()
        return JsonResponse({"snowflake_id": snowflake_id})
    except Exception as e:
        print(e)
        return JsonResponse({
            "snowflake_id": None,
            "error": str(e)
        }, status=500)


class TestRedisLockView(APIView):
    def get(self, request):
        key = "test:redis:lock"
        redis_ttl = 10000
        lock = build_lock(key, redis_ttl, strategy='fast')  # 单节点 Redis 锁

        with lock:
            get_redis_client().set("test:key:fast", "redis_lock", ex=60)
            print("[test:redis:lock] 写入 test:key:fast成功")
            return Response({"status": "fast lock success"})


class TestRedLockView(APIView):
    def get(self, request):
        key = "test:red:lock"
        redlock_ttl = 10000
        lock = build_lock(key, redlock_ttl, strategy='safe')  # RedLock 分布式锁

        with lock:
            get_redis_client().set("test:key:safe", "redlock", ex=60)
            print("[test:red:lock] 写入 test:key:safe成功")
            return Response({"status": "redlock success"})