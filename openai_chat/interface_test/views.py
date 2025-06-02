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
