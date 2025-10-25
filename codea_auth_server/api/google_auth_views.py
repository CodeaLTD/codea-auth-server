"""
Google OAuth Authentication API views for the Codea Auth Server.

This module handles Google OAuth authentication including:
- Google OAuth URL generation
- Google OAuth callback handling
- User creation/authentication via Google
- JWT token generation for Google-authenticated users
"""

import requests
import json
import time
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from codea_auth_server.logging_utils import log_auth_event, log_security_event, log_request_info, log_error, log_message

# Get logger for this module
logger = logging.getLogger('codea_auth_server')

# Google OAuth Configuration from settings
GOOGLE_CONFIG = getattr(settings, 'GOOGLE_OAUTH_CONFIG', {})
GOOGLE_CLIENT_ID = GOOGLE_CONFIG.get('CLIENT_ID', 'your-google-client-id')
GOOGLE_CLIENT_SECRET = GOOGLE_CONFIG.get('CLIENT_SECRET', 'your-google-client-secret')
GOOGLE_REDIRECT_URI = GOOGLE_CONFIG.get('REDIRECT_URI', 'http://localhost:8000/api/auth/google/callback/')
GOOGLE_SCOPE = GOOGLE_CONFIG.get('SCOPE', 'openid email profile')
GOOGLE_AUTH_URL = GOOGLE_CONFIG.get('AUTH_URL', 'https://accounts.google.com/o/oauth2/v2/auth')
GOOGLE_TOKEN_URL = GOOGLE_CONFIG.get('TOKEN_URL', 'https://oauth2.googleapis.com/token')
GOOGLE_USER_INFO_URL = GOOGLE_CONFIG.get('USER_INFO_URL', 'https://www.googleapis.com/oauth2/v2/userinfo')


@extend_schema(
    tags=['Authentication'],
    summary='Get Google OAuth URL',
    description='Generate Google OAuth authorization URL for user authentication',
    parameters=[
        OpenApiParameter(
            name='redirect_uri',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Redirect URI after Google authentication',
            required=False
        ),
        OpenApiParameter(
            name='state',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='State parameter for CSRF protection',
            required=False
        )
    ],
    responses={
        200: {
            'description': 'Google OAuth URL generated successfully',
            'content': {
                'application/json': {
                    'example': {
                        'auth_url': 'https://accounts.google.com/o/oauth2/v2/auth?client_id=...',
                        'state': 'random_state_string'
                    }
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
@api_view(['GET'])
@permission_classes([AllowAny])
def google_auth_url_view(request):
    """
    Generate Google OAuth authorization URL.
    """
    try:
        log_message("Google OAuth URL generation requested", "INFO")
        log_request_info(request)
        
        # Get optional parameters
        redirect_uri = request.GET.get('redirect_uri', GOOGLE_REDIRECT_URI)
        state = request.GET.get('state', f'google_auth_{int(time.time())}')
        
        # Build Google OAuth URL
        auth_params = {
            'client_id': GOOGLE_CLIENT_ID,
            'redirect_uri': redirect_uri,
            'scope': GOOGLE_SCOPE,
            'response_type': 'code',
            'state': state,
            'access_type': 'offline',
            'prompt': 'consent'
        }
        
        auth_url = f"{GOOGLE_AUTH_URL}?" + "&".join([f"{k}={v}" for k, v in auth_params.items()])
        
        log_auth_event(
            'google_auth_url_generated',
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={'state': state, 'redirect_uri': redirect_uri}
        )
        
        log_message(f"Google OAuth URL generated with state: {state}", "INFO")
        
        return Response({
            'auth_url': auth_url,
            'state': state
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'google_auth_url_view')
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Authentication'],
    summary='Google OAuth Callback',
    description='Handle Google OAuth callback and authenticate user',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'code': {'type': 'string', 'description': 'Authorization code from Google'},
                'state': {'type': 'string', 'description': 'State parameter for CSRF protection'},
                'redirect_uri': {'type': 'string', 'description': 'Redirect URI used in authorization'}
            },
            'required': ['code']
        }
    },
    responses={
        200: {
            'description': 'Google authentication successful',
            'content': {
                'application/json': {
                    'example': {
                        'access': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                        'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                        'user': {
                            'id': 1,
                            'username': 'user@gmail.com',
                            'email': 'user@gmail.com',
                            'first_name': 'John',
                            'last_name': 'Doe',
                            'is_active': True,
                            'date_joined': '2024-01-01T00:00:00Z'
                        },
                        'is_new_user': False
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - missing or invalid data',
            'content': {
                'application/json': {
                    'example': {'error': 'Authorization code required'}
                }
            }
        },
        401: {
            'description': 'Unauthorized - Google authentication failed',
            'content': {
                'application/json': {
                    'example': {'error': 'Google authentication failed'}
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
            'Google OAuth Callback',
            summary='Successful Google authentication',
            description='Example of a successful Google OAuth callback',
            value={
                'code': '4/0AX4XfWh...',
                'state': 'google_auth_1234567890',
                'redirect_uri': 'http://localhost:8000/api/auth/google/callback/'
            },
            request_only=True
        )
    ]
)
@api_view(['POST'])
@permission_classes([AllowAny])
def google_auth_callback_view(request):
    """
    Handle Google OAuth callback and authenticate user.
    """
    start_time = time.time()
    
    try:
        log_message("Google OAuth callback received", "INFO")
        log_request_info(request)
        
        # Get parameters from request
        code = request.data.get('code')
        state = request.data.get('state')
        redirect_uri = request.data.get('redirect_uri', GOOGLE_REDIRECT_URI)
        
        if not code:
            log_security_event(
                'invalid_google_auth',
                'WARNING',
                'Missing authorization code in Google OAuth callback',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Authorization code required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Exchange authorization code for access token
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri
        }
        
        token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data)
        
        if token_response.status_code != 200:
            log_security_event(
                'google_token_exchange_failed',
                'WARNING',
                f'Failed to exchange code for token: {token_response.status_code}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Failed to exchange authorization code'}, status=status.HTTP_401_UNAUTHORIZED)
        
        token_info = token_response.json()
        access_token = token_info.get('access_token')
        
        if not access_token:
            log_security_event(
                'google_token_missing',
                'WARNING',
                'No access token in Google response',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'No access token received from Google'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Get user information from Google
        user_info_response = requests.get(
            GOOGLE_USER_INFO_URL,
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if user_info_response.status_code != 200:
            log_security_event(
                'google_user_info_failed',
                'WARNING',
                f'Failed to get user info from Google: {user_info_response.status_code}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Failed to get user information from Google'}, status=status.HTTP_401_UNAUTHORIZED)
        
        user_info = user_info_response.json()
        google_id = user_info.get('id')
        email = user_info.get('email')
        first_name = user_info.get('given_name', '')
        last_name = user_info.get('family_name', '')
        picture = user_info.get('picture', '')
        
        if not google_id or not email:
            log_security_event(
                'google_user_info_incomplete',
                'WARNING',
                'Incomplete user information from Google',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Incomplete user information from Google'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check if user exists by email
        try:
            user = User.objects.get(email=email)
            is_new_user = False
            
            # Update user information if needed
            if user.first_name != first_name or user.last_name != last_name:
                user.first_name = first_name
                user.last_name = last_name
                user.save()
                
        except User.DoesNotExist:
            # Create new user
            username = email  # Use email as username
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_active=True
            )
            is_new_user = True
            
            log_message(f"New user created via Google OAuth: {email}", "INFO")
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token
        
        # Log successful authentication
        log_auth_event(
            'google_auth_success',
            user_id=str(user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={
                'email': email,
                'google_id': google_id,
                'is_new_user': is_new_user
            }
        )
        
        processing_time = time.time() - start_time
        log_message(f"User {email} authenticated via Google OAuth in {processing_time:.3f}s", "INFO")
        
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
            },
            'is_new_user': is_new_user,
            'google_id': google_id,
            'picture': picture
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'google_auth_callback_view', {
            'code': request.data.get('code'),
            'ip_address': request.META.get('REMOTE_ADDR')
        })
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Authentication'],
    summary='Google OAuth Configuration',
    description='Get Google OAuth configuration for frontend integration',
    responses={
        200: {
            'description': 'Google OAuth configuration retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'client_id': 'your-google-client-id',
                        'redirect_uri': 'http://localhost:8000/api/auth/google/callback/',
                        'scope': 'openid email profile',
                        'auth_url': 'https://accounts.google.com/o/oauth2/v2/auth'
                    }
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
@api_view(['GET'])
@permission_classes([AllowAny])
def google_auth_config_view(request):
    """
    Get Google OAuth configuration for frontend integration.
    """
    try:
        log_message("Google OAuth configuration requested", "INFO")
        log_request_info(request)
        
        config = {
            'client_id': GOOGLE_CLIENT_ID,
            'redirect_uri': GOOGLE_REDIRECT_URI,
            'scope': GOOGLE_SCOPE,
            'auth_url': GOOGLE_AUTH_URL
        }
        
        log_message("Google OAuth configuration provided", "INFO")
        
        return Response(config, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'google_auth_config_view')
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Authentication'],
    summary='Google OAuth Status',
    description='Check Google OAuth service status and configuration',
    responses={
        200: {
            'description': 'Google OAuth status retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'status': 'active',
                        'client_id_configured': True,
                        'redirect_uri': 'http://localhost:8000/api/auth/google/callback/',
                        'google_services_accessible': True
                    }
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
@api_view(['GET'])
@permission_classes([AllowAny])
def google_auth_status_view(request):
    """
    Check Google OAuth service status and configuration.
    """
    try:
        log_message("Google OAuth status check requested", "INFO")
        log_request_info(request)
        
        # Check if Google services are accessible
        try:
            test_response = requests.get('https://www.googleapis.com', timeout=5)
            google_accessible = test_response.status_code == 200
        except:
            google_accessible = False
        
        status_info = {
            'status': 'active' if GOOGLE_CLIENT_ID != 'your-google-client-id' else 'not_configured',
            'client_id_configured': GOOGLE_CLIENT_ID != 'your-google-client-id',
            'redirect_uri': GOOGLE_REDIRECT_URI,
            'google_services_accessible': google_accessible,
            'scope': GOOGLE_SCOPE
        }
        
        log_message(f"Google OAuth status: {status_info['status']}", "INFO")
        
        return Response(status_info, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'google_auth_status_view')
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
