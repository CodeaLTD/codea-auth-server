"""
API Documentation views for the Codea Auth Server.

This module provides Swagger/OpenAPI documentation endpoints
and API schema generation.
"""

from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
import logging

from codea_auth_server.logging_utils import log_request_info, log_message, log_error

# Get logger for this module
logger = logging.getLogger('codea_auth_server')

#
#
# class CustomSpectacularAPIView(SpectacularAPIView):
#     """
#     Custom API schema view with logging.
#     """
#
#     def get(self, request, *args, **kwargs):
#         log_message("API schema requested", "INFO")
#         log_request_info(request)
#         return super().get(request, *args, **kwargs)
#
#
# class CustomSpectacularSwaggerView(SpectacularSwaggerView):
#     """
#     Custom Swagger UI view with logging.
#     """
#
#     def get(self, request, *args, **kwargs):
#         log_message("Swagger UI requested", "INFO")
#         log_request_info(request)
#         return super().get(request, *args, **kwargs)
#
#
# class CustomSpectacularRedocView(SpectacularRedocView):
#     """
#     Custom ReDoc view with logging.
#     """
#
#     def get(self, request, *args, **kwargs):
#         log_message("ReDoc UI requested", "INFO")
#         log_request_info(request)
#         return super().get(request, *args, **kwargs)
#
#
# @extend_schema(
#     tags=['Documentation'],
#     summary='API Information',
#     description='Get basic information about the API',
#     responses={
#         200: {
#             'description': 'API information retrieved successfully',
#             'content': {
#                 'application/json': {
#                     'example': {
#                         'name': 'Codea Auth Server API',
#                         'version': '1.0.0',
#                         'description': 'Authentication and user management API',
#                         'endpoints': {
#                             'authentication': '/api/auth/',
#                             'users': '/api/users/',
#                             'health': '/api/health/',
#                             'docs': '/api/docs/'
#                         }
#                     }
#                 }
#             }
#         }
#     }
# )
# @api_view(['GET'])
# @permission_classes([AllowAny])
# def api_info_view(request):
#     """
#     Get basic API information and available endpoints.
#     """
#     try:
#         log_message("API info requested", "INFO")
#         log_request_info(request)
#
#         api_info = {
#             'name': 'Codea Auth Server API',
#             'version': '1.0.0',
#             'description': 'Authentication and user management API for Codea platform',
#             'documentation': {
#                 'swagger_ui': '/api/docs/swagger/',
#                 'redoc': '/api/docs/redoc/',
#                 'schema': '/api/docs/schema/'
#             },
#             'endpoints': {
#                 'authentication': {
#                     'login': '/api/auth/login/',
#                     'logout': '/api/auth/logout/',
#                     'refresh_token': '/api/auth/refresh-token/',
#                     'change_password': '/api/auth/change-password/'
#                 },
#                 'users': {
#                     'register': '/api/users/register/',
#                     'profile': '/api/users/profile/',
#                     'update_profile': '/api/users/update-profile/',
#                     'list_users': '/api/users/list/'
#                 },
#                 'health': {
#                     'health_check': '/api/health/',
#                     'detailed_health': '/api/health/detailed/',
#                     'metrics': '/api/health/metrics/',
#                     'status': '/api/health/status/'
#                 }
#             },
#             'authentication': {
#                 'methods': ['Session', 'JWT Token'],
#                 'note': 'Use session authentication for web clients, JWT for mobile/API clients'
#             }
#         }
#
#         log_message("API info provided successfully", "INFO")
#         return Response(api_info, status=status.HTTP_200_OK)
#
#     except Exception as e:
#         logger.error(f"Error in api_info_view: {str(e)}", exc_info=True)
#         return Response(
#             {'error': 'Failed to retrieve API information'},
#             status=status.HTTP_500_INTERNAL_SERVER_ERROR
#         )
