"""
URL configuration for codea_auth_server project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.http import HttpResponse, JsonResponse
from django.urls import path, include
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
import time

# Simple health check for uptime monitors (root level)
@csrf_exempt
@require_http_methods(["GET"])
def simple_health_check(request):
    """Ultra-lightweight health check endpoint for uptime monitors."""
    return JsonResponse({
        'status': 'healthy',
        'message': 'Auth server is running',
        'timestamp': time.time()
    }, status=200)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('codea_auth_server.api.urls')),
    
    # Swagger/OpenAPI documentation endpoints
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

    # Simple health check endpoint for uptime monitors (root level)
    path('health', simple_health_check, name='health'),
    path('health/', simple_health_check, name='health_slash'),

    # Add this line for a simple homepage
    path('', lambda request: HttpResponse("Welcome to Codea Auth Server 👋")),
]
