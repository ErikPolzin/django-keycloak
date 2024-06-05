import logging

from django.http.response import JsonResponse
from django.contrib.auth.decorators import login_required

logger = logging.getLogger(__name__)


def api_end_point(request):
    return JsonResponse({'foo': 'bar'})


@login_required
def authenticated_end_point(request):
    return JsonResponse({
        'user': {
            'username': request.user.username,
            'first_name': request.user.first_name,
            'last_name': request.user.last_name
        }
    })
