"""
Google OAuth Authentication API views for the Codea Auth Server.

This module handles Google OAuth authentication with 5 endpoints:
1. `/login` - Redirects to Google login
2. `/auth` - Callback that exchanges code for tokens, fetches user info, issues JWT
3. `/me` - Protected endpoint (requires Bearer or cookie)
4. `/logout` - Deletes token
5. `/refresh` - Refreshes JWT access token using refresh token
"""
"""
💾 Real-world improvements

If you integrate into production:

Store refresh tokens in your User model, encrypted (e.g., with Django’s Fernet).

Add a last_refresh field for auditing.

Rotate tokens regularly.

Handle revoked Google tokens by catching invalid_grant responses.

Consider refreshing Google access tokens automatically in background if you call Google APIs.
"""

import requests
import json
import time
import logging
from django.http import HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from codea_auth_server.logging_utils import log_auth_event, log_security_event, log_request_info, log_error, log_message
from .role_utils import get_user_roles
from .google_token_utils import store_google_token, get_stored_refresh_token, handle_revoked_token, refresh_google_access_token

# Get logger for this module
logger = logging.getLogger('codea_auth_server')

# Google OAuth Configuration from settings
GOOGLE_CONFIG = getattr(settings, 'GOOGLE_OAUTH_CONFIG', {})
GOOGLE_CLIENT_ID = GOOGLE_CONFIG.get('CLIENT_ID', 'your-google-client-id')
GOOGLE_CLIENT_SECRET = GOOGLE_CONFIG.get('CLIENT_SECRET', 'your-google-client-secret')
GOOGLE_REDIRECT_URI = GOOGLE_CONFIG.get('REDIRECT_URI', 'http://localhost:8000/api/auth/google/auth/')
GOOGLE_SCOPE = GOOGLE_CONFIG.get('SCOPE', 'openid email profile')
GOOGLE_AUTH_URL = GOOGLE_CONFIG.get('AUTH_URL', 'https://accounts.google.com/o/oauth2/v2/auth')
GOOGLE_TOKEN_URL = GOOGLE_CONFIG.get('TOKEN_URL', 'https://oauth2.googleapis.com/token')
GOOGLE_USER_INFO_URL = GOOGLE_CONFIG.get('USER_INFO_URL', 'https://www.googleapis.com/oauth2/v2/userinfo')


@extend_schema(
    tags=['Google Authentication'],
    summary='Google OAuth Login',
    description='Redirects to Google OAuth login page',
    parameters=[
        OpenApiParameter(
            name='redirect_uri',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Redirect URI after Google authentication',
            required=False
        ),
    ],
    responses={
        302: {
            'description': 'Redirects to Google OAuth login page',
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
def google_login_view(request):
    """
    Redirects to Google OAuth login.
    """
    try:
        log_message("Google OAuth login requested", "INFO")
        log_request_info(request)
        
        # Get optional parameters
        redirect_uri = request.GET.get('redirect_uri', GOOGLE_REDIRECT_URI)
        state = f'google_auth_{int(time.time())}'
        
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
            'google_auth_login_initiated',
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={'state': state, 'redirect_uri': redirect_uri}
        )
        
        log_message(f"Redirecting to Google OAuth with state: {state}", "INFO")
        
        # Redirect to Google OAuth
        return HttpResponseRedirect(auth_url)
        
    except Exception as e:
        log_error(e, 'google_login_view')
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Google Authentication'],
    summary='Google OAuth Callback',
    description='Handle Google OAuth callback and authenticate user. Supports both GET (browser redirect from Google) and POST (direct API call).',
    methods=['GET', 'POST'],
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
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def google_auth_callback_view(request):
    """
    Handle Google OAuth callback and authenticate user.
    Supports both GET (browser redirect) and POST (direct API call).
    """
    start_time = time.time()
    
    try:
        log_message("Google OAuth callback received", "INFO")
        log_request_info(request)
        
        # Get parameters from request - support both GET (browser) and POST (API)
        code = request.GET.get('code') or request.data.get('code')
        state = request.GET.get('state') or request.data.get('state')
        redirect_uri = request.GET.get('redirect_uri') or request.data.get('redirect_uri', GOOGLE_REDIRECT_URI)
        
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
        google_refresh_token = token_info.get('refresh_token')  # Store this for production use
        
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
        
        # Store Google refresh token and user data for production use
        if google_refresh_token:
            try:
                store_google_token(user, google_refresh_token, google_id, picture)
                log_message(f"Stored Google refresh token for user {user.username}", "INFO")
            except Exception as e:
                log_error(e, 'google_auth_callback_view - store_token', {'user_id': str(user.id)})
        
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
        
        # Get user roles
        user_roles = get_user_roles(user)
        
        response_data = {
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
                'roles': user_roles
            },
            'is_new_user': is_new_user,
            'google_id': google_id,
            'picture': picture
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'google_auth_callback_view', {
            'code': request.data.get('code'),
            'ip_address': request.META.get('REMOTE_ADDR')
        })
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Google Authentication'],
    summary='Get Current User Info',
    description='Get current authenticated user information (requires Bearer token or cookie)',
    responses={
        200: {
            'description': 'User information retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'id': 1,
                        'username': 'user@gmail.com',
                        'email': 'user@gmail.com',
                        'first_name': 'John',
                        'last_name': 'Doe',
                        'is_active': True,
                        'date_joined': '2024-01-01T00:00:00Z',
                        'last_login': '2024-01-01T12:00:00Z',
                        'roles': ['general-user', 'taxapp-user']
                    }
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
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def google_me_view(request):
    """
    Get current user information.
    """
    try:
        log_message(f"Current user info requested by user {request.user.username}", "INFO")
        log_request_info(request)
        
        # Get user roles
        user_roles = get_user_roles(request.user)
        
        profile_data = {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'is_active': request.user.is_active,
            'date_joined': request.user.date_joined.isoformat(),
            'last_login': request.user.last_login.isoformat() if request.user.last_login else None,
            'roles': user_roles
        }
        
        log_message(f"User info retrieved for user {request.user.username}", "INFO")
        
        return Response(profile_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'google_me_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Google Authentication'],
    summary='Logout',
    description='Logout current user and invalidate tokens',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'refresh': {'type': 'string', 'description': 'Refresh token to invalidate'}
            }
        }
    },
    responses={
        200: {
            'description': 'Logout successful',
            'content': {
                'application/json': {
                    'example': {
                        'message': 'Logout successful'
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
def google_logout_view(request):
    """
    Logout user and invalidate refresh token.
    """
    try:
        log_message("Google OAuth logout requested", "INFO")
        log_request_info(request)
        
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            log_security_event(
                'invalid_google_logout',
                'WARNING',
                'Missing refresh token for logout',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Blacklist the refresh token
            refresh = RefreshToken(refresh_token)
            user_id = refresh.payload.get('user_id')
            refresh.blacklist()
            
            # Log successful logout
            log_auth_event(
                'google_logout_success',
                user_id=str(user_id),
                ip_address=request.META.get('REMOTE_ADDR'),
                additional_data={'token_type': 'refresh'}
            )
            
            log_message(f"Google OAuth logout successful for user {user_id}", "INFO")
            
            # Create response to delete cookie if it exists
            response = Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
            response.delete_cookie('refresh', path='/')
            response.delete_cookie('access', path='/')
            
            return response
            
        except TokenError as e:
            log_security_event(
                'invalid_google_logout',
                'WARNING',
                f'Invalid refresh token for logout: {str(e)}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        log_error(e, 'google_logout_view')
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Google Authentication'],
    summary='Refresh Token',
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
            'description': 'Bad request - missing or invalid refresh token',
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
def google_refresh_view(request):
    """
    Refresh JWT access token using refresh token.
    """
    try:
        log_message("Google OAuth token refresh requested", "INFO")
        log_request_info(request)
        
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            log_security_event(
                'invalid_google_token_refresh',
                'WARNING',
                'Missing refresh token',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Validate and refresh the JWT token
            refresh = RefreshToken(refresh_token)
            access = refresh.access_token
            user_id = refresh.payload.get('user_id')
            
            # Optional: Refresh Google token if needed for background API calls
            try:
                user = User.objects.get(id=user_id)
                if hasattr(user, 'profile'):
                    # Attempt to refresh Google access token if expired
                    google_access_token = refresh_google_access_token(
                        get_stored_refresh_token(user),
                        GOOGLE_CLIENT_ID,
                        GOOGLE_CLIENT_SECRET
                    )
                    if not google_access_token:
                        # Google token was revoked
                        handle_revoked_token(user)
                        log_message(f"Google token revoked for user {user.username}, cleared stored credentials", "WARNING")
            except (User.DoesNotExist, Exception) as e:
                # Silently continue if Google token refresh fails
                pass
            
            # Log successful token refresh
            log_auth_event(
                'google_token_refresh_success',
                user_id=str(user_id),
                ip_address=request.META.get('REMOTE_ADDR'),
                additional_data={'token_type': 'refresh'}
            )
            
            log_message(f"Google OAuth token refreshed successfully for user {user_id}", "INFO")
            
            return Response({
                'access': str(access)
            }, status=status.HTTP_200_OK)
            
        except TokenError as e:
            log_security_event(
                'invalid_google_token_refresh',
                'WARNING',
                f'Invalid refresh token: {str(e)}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
        
    except Exception as e:
        log_error(e, 'google_refresh_view')
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Google Authentication'],
    summary='Verify Google Token',
    description='Verify Google OAuth access token validity by checking with Google tokeninfo endpoint',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'token': {'type': 'string', 'description': 'Google OAuth access token to verify'}
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
                        'audience': '123456789-abcdefgh.apps.googleusercontent.com',
                        'scope': 'openid email profile',
                        'expires_in': 3599,
                        'user_id': '123456789',
                        'email': 'user@example.com',
                        'verified_email': True
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
            'description': 'Unauthorized - invalid or expired token',
            'content': {
                'application/json': {
                    'example': {'error': 'Invalid token', 'valid': False}
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
def google_verify_view(request):
    """
    Verify Google OAuth access token by calling Google's tokeninfo endpoint.
    
    This endpoint checks if a Google OAuth access token is valid, not expired,
    and returns information about the token including audience, scope, and user info.
    """
    try:
        log_message("Google token verification requested", "INFO")
        log_request_info(request)
        
        token = request.data.get('token')
        
        if not token:
            log_security_event(
                'invalid_google_token_verify',
                'WARNING',
                'Missing token for Google verification',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({'error': 'Token required', 'valid': False}, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify token with Google's tokeninfo endpoint
        tokeninfo_url = 'https://oauth2.googleapis.com/tokeninfo'
        params = {'access_token': token}
        
        try:
            verify_response = requests.get(tokeninfo_url, params=params, timeout=10)
            
            if verify_response.status_code == 200:
                token_info = verify_response.json()
                
                # Verify the audience (client ID) matches our configured client ID
                audience = token_info.get('aud')
                if audience and audience != GOOGLE_CLIENT_ID:
                    log_security_event(
                        'google_token_audience_mismatch',
                        'WARNING',
                        f'Token audience mismatch: {audience} vs {GOOGLE_CLIENT_ID}',
                        {'ip_address': request.META.get('REMOTE_ADDR')}
                    )
                    return Response({
                        'error': 'Token audience does not match',
                        'valid': False
                    }, status=status.HTTP_401_UNAUTHORIZED)
                
                # Log successful verification
                email = token_info.get('email', 'unknown')
                log_auth_event(
                    'google_token_verify_success',
                    user_id=None,  # Google token doesn't have our user ID
                    ip_address=request.META.get('REMOTE_ADDR'),
                    additional_data={
                        'email': email,
                        'audience': audience,
                        'scope': token_info.get('scope', '')
                    }
                )
                
                log_message(f"Google token verified successfully for {email}", "INFO")
                
                # Return token information
                return Response({
                    'valid': True,
                    'audience': token_info.get('aud'),
                    'scope': token_info.get('scope'),
                    'expires_in': token_info.get('expires_in'),
                    'user_id': token_info.get('user_id'),
                    'email': token_info.get('email'),
                    'verified_email': token_info.get('verified_email', False),
                    'issued_to': token_info.get('issued_to'),
                    'expires_at': token_info.get('exp')
                }, status=status.HTTP_200_OK)
                
            elif verify_response.status_code == 400:
                # Invalid token
                error_data = verify_response.json()
                log_security_event(
                    'invalid_google_token_verify',
                    'WARNING',
                    f'Invalid Google token: {error_data.get("error_description", "Unknown error")}',
                    {'ip_address': request.META.get('REMOTE_ADDR')}
                )
                return Response({
                    'error': 'Invalid token',
                    'valid': False,
                    'error_description': error_data.get('error_description', 'Token verification failed')
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            else:
                log_security_event(
                    'google_token_verify_error',
                    'WARNING',
                    f'Google token verification returned status {verify_response.status_code}',
                    {'ip_address': request.META.get('REMOTE_ADDR')}
                )
                return Response({
                    'error': 'Token verification failed',
                    'valid': False
                }, status=status.HTTP_401_UNAUTHORIZED)
                
        except requests.exceptions.RequestException as e:
            log_error(e, 'google_verify_view - request_exception')
            return Response({
                'error': 'Failed to connect to Google token verification service',
                'valid': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    except Exception as e:
        log_error(e, 'google_verify_view', {
            'ip_address': request.META.get('REMOTE_ADDR')
        })
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)