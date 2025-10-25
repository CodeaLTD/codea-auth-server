"""
Authentication API views for the Codea Auth Server.

This module handles all authentication-related endpoints including
login, logout, token management, and password operations.
"""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login, logout
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes
import time
import logging

from codea_auth_server.logging_utils import log_auth_event, log_security_event, log_request_info, log_error, log_message

# Get logger for this module
logger = logging.getLogger('codea_auth_server')


@extend_schema(
    tags=['Authentication'],
    summary='Login',
    description='Authenticate user with username and password and return JWT tokens',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string', 'description': 'Username'},
                'password': {'type': 'string', 'description': 'Password', 'format': 'password'}
            },
            'required': ['username', 'password']
        }
    },
    responses={
        200: {
            'description': 'Login successful',
            'content': {
                'application/json': {
                    'example': {
                        'access': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                        'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                        'user': {
                            'id': 1,
                            'username': 'john_doe',
                            'email': 'john@example.com'
                        }
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - missing credentials',
            'content': {
                'application/json': {
                    'example': {'error': 'Username and password required'}
                }
            }
        },
        401: {
            'description': 'Unauthorized - invalid credentials',
            'content': {
                'application/json': {
                    'example': {'error': 'Invalid credentials'}
                }
            }
        },
        500: {
            'description': 'Internal server error',
            'content': {
                'application/json': {
                    'example': {'error': 'Internal server error'}
                }
            }
        }
    },
    examples=[
        OpenApiExample(
            'Valid Login',
            summary='Successful login',
            description='Example of a successful login request',
            value={'username': 'john_doe', 'password': 'securepassword123'},
            request_only=True
        )
    ]
)
@api_view(['POST'])
@permission_classes([AllowAny])
def jwt_login_view(request):
    """
    JWT-based user login endpoint with comprehensive logging.
    """
    start_time = time.time()
    
    try:
        # Log the incoming request
        log_request_info(request)
        log_message("JWT login attempt started", "INFO")
        
        # Get credentials from request
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            log_security_event(
                'invalid_login_attempt',
                'WARNING',
                'Missing username or password',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Username and password required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Attempt authentication
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access = refresh.access_token
            
            # Log successful login
            log_auth_event(
                'jwt_login_success',
                user_id=str(user.id),
                ip_address=request.META.get('REMOTE_ADDR'),
                additional_data={'username': username}
            )
            
            processing_time = time.time() - start_time
            log_message(f"User {username} logged in successfully with JWT in {processing_time:.3f}s", "INFO")
            
            return Response({
                'access': str(access),
                'refresh': str(refresh),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_active': user.is_active,
                    'date_joined': user.date_joined.isoformat(),
                }
            }, status=status.HTTP_200_OK)
        else:
            # Log failed login attempt
            log_auth_event(
                'jwt_login_failed',
                ip_address=request.META.get('REMOTE_ADDR'),
                additional_data={'username': username}
            )
            
            log_security_event(
                'failed_login_attempt',
                'WARNING',
                f'Failed JWT login attempt for username: {username}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
            
    except Exception as e:
        log_error(e, 'jwt_login_view', {
            'username': request.data.get('username'),
            'ip_address': request.META.get('REMOTE_ADDR')
        })
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Authentication'],
    summary='JWT Token Refresh',
    description='Refresh JWT access token using refresh token',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'refresh': {'type': 'string', 'description': 'Refresh token'}
            },
            'required': ['refresh']
        }
    },
    responses={
        200: {
            'description': 'Token refreshed successfully',
            'content': {
                'application/json': {
                    'example': {
                        'access': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - missing refresh token',
            'content': {
                'application/json': {
                    'example': {'error': 'Refresh token required'}
                }
            }
        },
        401: {
            'description': 'Unauthorized - invalid refresh token',
            'content': {
                'application/json': {
                    'example': {'error': 'Invalid refresh token'}
                }
            }
        },
        500: {
            'description': 'Internal server error',
            'content': {
                'application/json': {
                    'example': {'error': 'Internal server error'}
                }
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def jwt_refresh_view(request):
    """
    JWT token refresh endpoint with comprehensive logging.
    """
    try:
        log_message("JWT token refresh requested", "INFO")
        log_request_info(request)
        
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            log_security_event(
                'invalid_token_refresh',
                'WARNING',
                'Missing refresh token',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Validate and refresh the token
            refresh = RefreshToken(refresh_token)
            access = refresh.access_token
            
            # Log successful token refresh
            log_auth_event(
                'jwt_token_refresh_success',
                user_id=str(refresh.payload.get('user_id')),
                ip_address=request.META.get('REMOTE_ADDR'),
                additional_data={'token_type': 'refresh'}
            )
            
            log_message("JWT token refreshed successfully", "INFO")
            
            return Response({
                'access': str(access)
            }, status=status.HTTP_200_OK)
            
        except TokenError as e:
            log_security_event(
                'invalid_token_refresh',
                'WARNING',
                f'Invalid refresh token: {str(e)}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
            
    except Exception as e:
        log_error(e, 'jwt_refresh_view')
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Authentication'],
    summary='JWT Token Verify',
    description='Verify JWT access token validity',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'token': {'type': 'string', 'description': 'Access token to verify'}
            },
            'required': ['token']
        }
    },
    responses={
        200: {
            'description': 'Token is valid',
            'content': {
                'application/json': {
                    'example': {
                        'valid': True,
                        'user_id': 1,
                        'username': 'john_doe'
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - missing token',
            'content': {
                'application/json': {
                    'example': {'error': 'Token required'}
                }
            }
        },
        401: {
            'description': 'Unauthorized - invalid token',
            'content': {
                'application/json': {
                    'example': {'error': 'Invalid token'}
                }
            }
        },
        500: {
            'description': 'Internal server error',
            'content': {
                'application/json': {
                    'example': {'error': 'Internal server error'}
                }
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def jwt_verify_view(request):
    """
    JWT token verification endpoint with comprehensive logging.
    """
    try:
        log_message("JWT token verification requested", "INFO")
        log_request_info(request)
        
        token = request.data.get('token')
        
        if not token:
            log_security_event(
                'invalid_token_verify',
                'WARNING',
                'Missing token for verification',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Token required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Validate the token
            access = AccessToken(token)
            user_id = access.payload.get('user_id')
            
            # Get user information
            from django.contrib.auth import get_user_model
            try:
                user = get_user_model().objects.get(id=user_id)
                username = user.username
            except get_user_model().DoesNotExist:
                username = 'unknown'
            
            # Log successful token verification
            log_auth_event(
                'jwt_token_verify_success',
                user_id=str(user_id),
                ip_address=request.META.get('REMOTE_ADDR'),
                additional_data={'username': username}
            )
            
            log_message(f"JWT token verified successfully for user {username}", "INFO")
            
            return Response({
                'valid': True,
                'user_id': user_id,
                'username': username
            }, status=status.HTTP_200_OK)
            
        except TokenError as e:
            log_security_event(
                'invalid_token_verify',
                'WARNING',
                f'Invalid token for verification: {str(e)}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)
            
    except Exception as e:
        log_error(e, 'jwt_verify_view')
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Authentication'],
    summary='Logout',
    description='Logout user and blacklist refresh token',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'refresh': {'type': 'string', 'description': 'Refresh token to blacklist'}
            },
            'required': ['refresh']
        }
    },
    responses={
        200: {
            'description': 'Logout successful',
            'content': {
                'application/json': {
                    'example': {'message': 'Logout successful'}
                }
            }
        },
        400: {
            'description': 'Bad request - missing refresh token',
            'content': {
                'application/json': {
                    'example': {'error': 'Refresh token required'}
                }
            }
        },
        500: {
            'description': 'Internal server error',
            'content': {
                'application/json': {
                    'example': {'error': 'Internal server error'}
                }
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def jwt_logout_view(request):
    """
    JWT-based logout endpoint that blacklists the refresh token.
    """
    try:
        log_message("JWT logout requested", "INFO")
        log_request_info(request)
        
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            log_security_event(
                'invalid_logout',
                'WARNING',
                'Missing refresh token for logout',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Blacklist the refresh token
            refresh = RefreshToken(refresh_token)
            refresh.blacklist()
            
            # Log successful logout
            log_auth_event(
                'jwt_logout_success',
                user_id=str(refresh.payload.get('user_id')),
                ip_address=request.META.get('REMOTE_ADDR'),
                additional_data={'token_type': 'refresh'}
            )
            
            log_message("JWT logout successful", "INFO")
            
            return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
            
        except TokenError as e:
            log_security_event(
                'invalid_logout',
                'WARNING',
                f'Invalid refresh token for logout: {str(e)}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        log_error(e, 'jwt_logout_view')
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# @extend_schema(
#     tags=['Authentication'],
#     summary='User Logout',
#     description='Logout the currently authenticated user',
#     responses={
#         200: {
#             'description': 'Logout successful',
#             'content': {
#                 'application/json': {
#                     'example': {'message': 'Logout successful'}
#                 }
#             }
#         },
#         401: {
#             'description': 'Unauthorized - user not authenticated',
#             'content': {
#                 'application/json': {
#                     'example': {'error': 'User not authenticated'}
#                 }
#             }
#         },
#         500: {
#             'description': 'Internal server error',
#             'content': {
#                 'application/json': {
#                     'example': {'error': 'Internal server error'}
#                 }
#             }
#         }
#     }
# )
# @csrf_exempt
# @require_http_methods(["POST"])
# def logout_view(request):
#     """
#     User logout endpoint with logging.
#     """
#     try:
#         if request.user.is_authenticated:
#             username = request.user.username
#             user_id = request.user.id
#
#             logout(request)
#
#             # Log successful logout
#             log_auth_event(
#                 'logout_success',
#                 user_id=str(user_id),
#                 ip_address=request.META.get('REMOTE_ADDR'),
#                 additional_data={'username': username}
#             )
#
#             log_message(f"User {username} logged out successfully", "INFO")
#
#             return JsonResponse({'message': 'Logout successful'})
#         else:
#             return JsonResponse({'error': 'User not authenticated'}, status=401)
#
#     except Exception as e:
#         log_error(e, 'logout_view')
#         return JsonResponse({'error': 'Internal server error'}, status=500)


# @extend_schema(
#     tags=['Authentication'],
#     summary='Legacy Token Refresh (Deprecated)',
#     description='Legacy token refresh endpoint - use JWT refresh instead',
#     responses={
#         200: {
#             'description': 'Deprecated endpoint',
#             'content': {
#                 'application/json': {
#                     'example': {
#                         'message': 'This endpoint is deprecated. Use /api/auth/jwt/refresh/ instead.',
#                         'status': 'deprecated'
#                     }
#                 }
#             }
#         }
#     }
# )
# @csrf_exempt
# @require_http_methods(["POST"])
# def refresh_token_view(request):
#     """
#     Legacy token refresh endpoint (deprecated - use JWT refresh instead).
#     """
#     try:
#         log_message("Legacy token refresh requested - redirecting to JWT", "INFO")
#         log_request_info(request)
#
#         return JsonResponse({
#             'message': 'This endpoint is deprecated. Use /api/auth/jwt/refresh/ instead.',
#             'status': 'deprecated',
#             'new_endpoint': '/api/auth/jwt/refresh/'
#         })
#
#     except Exception as e:
#         log_error(e, 'refresh_token_view')
#         return JsonResponse({'error': 'Internal server error'}, status=500)
#

@extend_schema(
    tags=['Authentication'],
    summary='Change Password',
    description='Change user password (JWT authentication required)',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'old_password': {'type': 'string', 'description': 'Current password', 'format': 'password'},
                'new_password': {'type': 'string', 'description': 'New password', 'format': 'password'}
            },
            'required': ['old_password', 'new_password']
        }
    },
    responses={
        200: {
            'description': 'Password changed successfully',
            'content': {
                'application/json': {
                    'example': {'message': 'Password changed successfully'}
                }
            }
        },
        400: {
            'description': 'Bad request - missing or invalid data',
            'content': {
                'application/json': {
                    'example': {'error': 'Old and new passwords required'}
                }
            }
        },
        401: {
            'description': 'Unauthorized - authentication required',
            'content': {
                'application/json': {
                    'example': {'error': 'Authentication required'}
                }
            }
        },
        500: {
            'description': 'Internal server error',
            'content': {
                'application/json': {
                    'example': {'error': 'Internal server error'}
                }
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password_view(request):
    """
    Change password endpoint with JWT authentication.
    """
    try:
        log_message(f"Password change requested by user {request.user.username}", "INFO")
        log_request_info(request)
        
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        
        if not old_password or not new_password:
            return Response({'error': 'Old and new passwords required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify old password
        if not request.user.check_password(old_password):
            log_security_event(
                'invalid_password_change',
                'WARNING',
                'Invalid old password provided',
                {'user_id': str(request.user.id), 'username': request.user.username}
            )
            return Response({'error': 'Invalid old password'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Set new password
        request.user.set_password(new_password)
        request.user.save()
        
        log_auth_event(
            'password_changed',
            user_id=str(request.user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={'username': request.user.username}
        )
        
        log_message(f"Password changed successfully for user {request.user.username}", "INFO")
        
        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'change_password_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
