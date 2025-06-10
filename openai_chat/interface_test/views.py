from rest_framework.views import APIView
from rest_framework.response import Response
from openai_chat.settings.utils.locks import build_lock
from openai_chat.settings.utils.redis import get_redis_client
from django.http import JsonResponse
from openai_chat.settings.utils.snowflake import get_snowflake_id
from tasks.email_tasks import send_email_async_task  # Ensure this is a Celery task, not a list
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated

# If send_email_async_task is a list, fix the import in tasks/email_tasks.py to export the Celery task function.
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

@api_view(['GET'])
@permission_classes([AllowAny])
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
    permission_classes = [AllowAny]  # 允许匿名访问
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
        

@csrf_exempt
@require_POST
def test_send_email(request):
    """
    测试邮件异步发送接口
    POST参数:
    - to_email:收件人邮箱
    - subject: 邮件标题
    - content: HTML内容
    """
    to_email = request.POST.get("to_email")
    subject = request.POST.get("subject")
    content = request.POST.get("content")
    
    if not to_email:
        return JsonResponse({"error": "参数to_email不能为空"}, status=400)
    
    # 调用Celery异步任务
    send_email_async_task.delay(to_email, subject, content) # type: ignore
    
    return JsonResponse({
        "status": "任务已提交",
        "to": to_email,
        "subject": subject
    })