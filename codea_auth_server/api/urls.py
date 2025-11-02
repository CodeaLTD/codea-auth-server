"""
URL configuration for the Codea Auth Server API.

This module defines all API endpoints organized by functionality.
"""
from django.http import HttpResponse
from django.urls import path
from codea_auth_server.api import auth_views, user_views, health_views, docs_views, google_auth_views

# API URL patterns organized by functionality
urlpatterns = [
    # Google OAuth Authentication endpoints
    path('auth/google/login/', google_auth_views.google_login_view, name='api_google_login'),
    path('auth/google/auth/', google_auth_views.google_auth_callback_view, name='api_google_auth'),
    path('auth/google/verify/', google_auth_views.google_verify_view, name='api_google_verify'),
    path('auth/google/me/', google_auth_views.google_me_view, name='api_google_me'),
    path('auth/google/logout/', google_auth_views.google_logout_view, name='api_google_logout'),
    path('auth/google/refresh/', google_auth_views.google_refresh_view, name='api_google_refresh'),
    
    # JWT Authentication endpoints (recommended)
    path('auth/jwt/login/', auth_views.jwt_login_view, name='api_jwt_login'),
    path('auth/jwt/refresh/', auth_views.jwt_refresh_view, name='api_jwt_refresh'),
    path('auth/jwt/verify/', auth_views.jwt_verify_view, name='api_jwt_verify'),
    path('auth/jwt/logout/', auth_views.jwt_logout_view, name='api_jwt_logout'),
    path('auth/jwt/register/', user_views.register_view, name='api_jwt_register'),
    
    # Legacy Authentication endpoints (deprecated)
    # path('auth/login/', auth_views.jwt_login_view, name='api_login'),
    # path('auth/logout/', auth_views., name='api_logout'),
    # path('auth/refresh-token/', auth_views.refresh_token_view, name='api_refresh_token'),
    # path('auth/change-password/', auth_views.change_password_view, name='api_change_password'),
    #
    # User management endpoints
    path('users/profile/', user_views.profile_view, name='api_profile'),
    path('users/profile/by-username/', user_views.get_user_profile_by_username_view, name='api_profile_by_username'),
    path('users/profile/update/', user_views.update_profile_view, name='api_update_profile'),
    path('users/profile/delete/', user_views.delete_profile_view, name='api_delete_profile'),
    path('users/list/', user_views.user_list_view, name='api_user_list'),
    
    # Role checking endpoints
    path('users/roles/check/', user_views.check_role_view, name='api_check_role'),
    path('users/roles/check-any/', user_views.check_any_role_view, name='api_check_any_role'),
    path('users/roles/check-all/', user_views.check_all_roles_view, name='api_check_all_roles'),
    path('users/roles/', user_views.get_user_roles_view, name='api_get_user_roles'),
    
    # Health and monitoring endpoints
    path('health/', health_views.health_check_view, name='api_health'),
    path('health/detailed/', health_views.detailed_health_view, name='api_health_detailed'),
    path('health/metrics/', health_views.metrics_view, name='api_metrics'),
    path('health/status/', health_views.status_view, name='api_status')
]
    
#     # API Documentation endpoints
#     path('docs/', docs_views.api_info_view, name='api_docs'),
#     path('docs/schema/', docs_views.CustomSpectacularAPIView.as_view(), name='api_schema'),
#     path('docs/swagger/', docs_views.CustomSpectacularSwaggerView.as_view(url_name='api_schema'), name='api_swagger'),
#     path('docs/redoc/', docs_views.CustomSpectacularRedocView.as_view(url_name='api_schema'), name='api_redoc'),
# ]
