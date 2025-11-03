"""
OAuth 2.0 Authorization Server API views for the Codea Auth Server.

This module implements the OAuth 2.0 Authorization Framework (RFC 6749) with three main endpoints:
1. /authorize - Authorization endpoint (browser-facing, handles user authentication)
2. /token - Token endpoint (server-to-server, handles client secrets)
3. /userinfo - UserInfo endpoint (resource API, controlled via access tokens)

Supported Grant Types:
- authorization_code: Standard OAuth 2.0 authorization code flow
- refresh_token: Token refresh flow
- password: Resource Owner Password Credentials (for trusted clients only)
- client_credentials: Client Credentials flow (for machine-to-machine)
"""

import secrets
import time
import logging
from urllib.parse import urlencode, urlparse, parse_qs
from django.http import HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.conf import settings
from django.core.cache import cache
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from codea_auth_server.logging_utils import (
    log_auth_event, log_security_event, log_request_info, 
    log_error, log_message
)
from .role_utils import get_user_roles

# Get logger for this module
logger = logging.getLogger('codea_auth_server')

# OAuth 2.0 Configuration
OAUTH2_CONFIG = getattr(settings, 'OAUTH2_CONFIG', {})
AUTHORIZATION_CODE_EXPIRY = OAUTH2_CONFIG.get('AUTHORIZATION_CODE_EXPIRY', 600)  # 10 minutes
ACCESS_TOKEN_EXPIRY = OAUTH2_CONFIG.get('ACCESS_TOKEN_EXPIRY', 3600)  # 1 hour
REFRESH_TOKEN_EXPIRY = OAUTH2_CONFIG.get('REFRESH_TOKEN_EXPIRY', 2592000)  # 30 days

# In-memory storage for authorization codes and client credentials
# In production, store these in a database
AUTHORIZATION_CODES = {}
REGISTERED_CLIENTS = OAUTH2_CONFIG.get('REGISTERED_CLIENTS', {
    'example_client_id': {
        'client_secret': 'example_client_secret',
        'redirect_uris': ['http://localhost:3000/callback'],
        'grant_types': ['authorization_code', 'refresh_token', 'password'],
        'name': 'Example Client Application'
    }
})


def validate_client_credentials(client_id, client_secret):
    """Validate client credentials."""
    client = REGISTERED_CLIENTS.get(client_id)
    if not client:
        return False, None
    if client.get('client_secret') != client_secret:
        return False, None
    return True, client


def validate_redirect_uri(client_id, redirect_uri):
    """Validate redirect URI against registered URIs."""
    client = REGISTERED_CLIENTS.get(client_id)
    if not client:
        return False
    registered_uris = client.get('redirect_uris', [])
    return redirect_uri in registered_uris


def generate_authorization_code(client_id, redirect_uri, scope, user_id):
    """Generate and store authorization code."""
    code = secrets.token_urlsafe(32)
    AUTHORIZATION_CODES[code] = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'user_id': user_id,
        'created_at': time.time(),
        'used': False
    }
    return code


def validate_authorization_code(code, client_id, redirect_uri):
    """Validate authorization code."""
    code_data = AUTHORIZATION_CODES.get(code)
    if not code_data:
        return None
    
    # Check if code is expired (10 minutes)
    if time.time() - code_data['created_at'] > AUTHORIZATION_CODE_EXPIRY:
        return None
    
    # Check if code has been used
    if code_data['used']:
        return None
    
    # Validate client_id and redirect_uri
    if code_data['client_id'] != client_id or code_data['redirect_uri'] != redirect_uri:
        return None
    
    # Mark code as used
    code_data['used'] = True
    return code_data


@extend_schema(
    tags=['OAuth 2.0 Authorize'],
    summary='OAuth 2.0 Authorization Endpoint',
    description='''
    OAuth 2.0 authorization endpoint (browser-facing). Authenticates the user and obtains authorization.
    
    This endpoint initiates the OAuth 2.0 authorization code flow:
    1. Client redirects user to this endpoint with client_id and redirect_uri
    2. User authenticates (if not already authenticated)
    3. User grants authorization to the client
    4. Server redirects back to client with authorization code
    
    Supports response_type: code (Authorization Code Grant)
    ''',
    parameters=[
        OpenApiParameter(
            name='response_type',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Must be "code" for authorization code flow',
            required=True,
            examples=[OpenApiExample('Authorization Code', value='code')]
        ),
        OpenApiParameter(
            name='client_id',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Client identifier',
            required=True,
            examples=[OpenApiExample('Example Client', value='example_client_id')]
        ),
        OpenApiParameter(
            name='redirect_uri',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Redirect URI where authorization code will be sent',
            required=True,
            examples=[OpenApiExample('Local Callback', value='http://localhost:3000/callback')]
        ),
        OpenApiParameter(
            name='scope',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Space-delimited scope values (e.g., "read write")',
            required=False,
            examples=[OpenApiExample('Read Write', value='read write')]
        ),
        OpenApiParameter(
            name='state',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Opaque value used by client to maintain state (CSRF protection)',
            required=False,
            examples=[OpenApiExample('Random State', value='random_state_value')]
        ),
        OpenApiParameter(
            name='username',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Username for authentication (if submitting login form)',
            required=False
        ),
        OpenApiParameter(
            name='password',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Password for authentication (if submitting login form)',
            required=False
        ),
    ],
    responses={
        302: {
            'description': 'Redirects to redirect_uri with authorization code',
        },
        400: {
            'description': 'Bad request - invalid parameters',
            'content': {
                'application/json': {
                    'example': {'error': 'invalid_request', 'error_description': 'Missing required parameter: client_id'}
                }
            }
        },
        401: {
            'description': 'Unauthorized - authentication required',
            'content': {
                'application/json': {
                    'example': {'error': 'access_denied', 'error_description': 'Invalid credentials'}
                }
            }
        }
    }
)
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def oauth2_authorize_view(request):
    """
    OAuth 2.0 authorization endpoint (browser-facing).
    
    Handles user authentication and authorization consent.
    Returns authorization code to client via redirect.
    """
    try:
        log_message("OAuth 2.0 authorization request received", "INFO")
        log_request_info(request)
        
        # Get OAuth parameters
        response_type = request.GET.get('response_type') or request.POST.get('response_type')
        client_id = request.GET.get('client_id') or request.POST.get('client_id')
        redirect_uri = request.GET.get('redirect_uri') or request.POST.get('redirect_uri')
        scope = request.GET.get('scope', 'read') or request.POST.get('scope', 'read')
        state = request.GET.get('state') or request.POST.get('state')
        
        # Validate required parameters
        if not response_type or not client_id or not redirect_uri:
            log_security_event(
                'oauth2_invalid_request',
                'WARNING',
                'Missing required OAuth 2.0 parameters',
                {'client_id': client_id, 'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({
                'error': 'invalid_request',
                'error_description': 'Missing required parameters: response_type, client_id, redirect_uri'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate response_type
        if response_type != 'code':
            return Response({
                'error': 'unsupported_response_type',
                'error_description': 'Only response_type=code is supported'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate client_id
        client = REGISTERED_CLIENTS.get(client_id)
        if not client:
            log_security_event(
                'oauth2_invalid_client',
                'WARNING',
                f'Unknown client_id: {client_id}',
                {'client_id': client_id, 'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return Response({
                'error': 'invalid_client',
                'error_description': 'Unknown client_id'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate redirect_uri
        if not validate_redirect_uri(client_id, redirect_uri):
            log_security_event(
                'oauth2_invalid_redirect_uri',
                'WARNING',
                f'Invalid redirect_uri for client {client_id}: {redirect_uri}',
                {'client_id': client_id, 'redirect_uri': redirect_uri}
            )
            return Response({
                'error': 'invalid_request',
                'error_description': 'Invalid redirect_uri'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if user is authenticated (via session or credentials)
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if username and password:
            # Authenticate with provided credentials
            user = authenticate(request, username=username, password=password)
            if not user:
                log_security_event(
                    'oauth2_authentication_failed',
                    'WARNING',
                    f'Failed OAuth 2.0 authentication for username: {username}',
                    {'client_id': client_id, 'username': username}
                )
                return Response({
                    'error': 'access_denied',
                    'error_description': 'Invalid credentials'
                }, status=status.HTTP_401_UNAUTHORIZED)
        elif request.user.is_authenticated:
            # Use already authenticated user
            user = request.user
        else:
            # Return login form (in production, render HTML template)
            return Response({
                'message': 'Authentication required',
                'login_url': f'/api/oauth2/authorize?{urlencode(request.GET.dict())}',
                'required_fields': ['username', 'password'],
                'client_name': client.get('name', client_id),
                'scope': scope
            }, status=status.HTTP_200_OK)
        
        # Generate authorization code
        code = generate_authorization_code(client_id, redirect_uri, scope, user.id)
        
        # Log successful authorization
        log_auth_event(
            'oauth2_authorization_granted',
            user_id=str(user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={
                'client_id': client_id,
                'scope': scope
            }
        )
        
        log_message(f"Authorization code granted to client {client_id} for user {user.username}", "INFO")
        
        # Redirect back to client with authorization code
        redirect_params = {'code': code}
        if state:
            redirect_params['state'] = state
        
        redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
        return HttpResponseRedirect(redirect_url)
        
    except Exception as e:
        log_error(e, 'oauth2_authorize_view', {
            'client_id': request.GET.get('client_id'),
            'ip_address': request.META.get('REMOTE_ADDR')
        })
        return Response({
            'error': 'server_error',
            'error_description': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['OAuth 2.0 Token'],
    summary='OAuth 2.0 Token Endpoint',
    description='''
    OAuth 2.0 token endpoint (server-to-server). Exchanges authorization codes or refresh tokens for access tokens.
    
    Supported grant types:
    - authorization_code: Exchange authorization code for access token
    - refresh_token: Refresh an expired access token
    - password: Resource Owner Password Credentials (trusted clients only)
    - client_credentials: Client Credentials Grant (machine-to-machine)
    
    Requires client authentication via HTTP Basic Auth or request body.
    ''',
    request={
        'application/x-www-form-urlencoded': {
            'type': 'object',
            'properties': {
                'grant_type': {
                    'type': 'string',
                    'description': 'Grant type',
                    'enum': ['authorization_code', 'refresh_token', 'password', 'client_credentials'],
                    'example': 'authorization_code'
                },
                'code': {
                    'type': 'string',
                    'description': 'Authorization code (required for authorization_code grant)',
                    'example': 'abc123...'
                },
                'redirect_uri': {
                    'type': 'string',
                    'description': 'Redirect URI (required for authorization_code grant)',
                    'example': 'http://localhost:3000/callback'
                },
                'refresh_token': {
                    'type': 'string',
                    'description': 'Refresh token (required for refresh_token grant)',
                    'example': 'refresh_token_xyz...'
                },
                'username': {
                    'type': 'string',
                    'description': 'Username (required for password grant)',
                    'example': 'john_doe'
                },
                'password': {
                    'type': 'string',
                    'description': 'Password (required for password grant)',
                    'example': 'secret_password'
                },
                'client_id': {
                    'type': 'string',
                    'description': 'Client identifier',
                    'example': 'example_client_id'
                },
                'client_secret': {
                    'type': 'string',
                    'description': 'Client secret',
                    'example': 'example_client_secret'
                },
                'scope': {
                    'type': 'string',
                    'description': 'Requested scope (space-delimited)',
                    'example': 'read write'
                }
            },
            'required': ['grant_type']
        }
    },
    responses={
        200: {
            'description': 'Access token issued successfully',
            'content': {
                'application/json': {
                    'example': {
                        'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                        'token_type': 'Bearer',
                        'expires_in': 3600,
                        'refresh_token': 'refresh_token_xyz...',
                        'scope': 'read write'
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - invalid grant',
            'content': {
                'application/json': {
                    'example': {'error': 'invalid_grant', 'error_description': 'Invalid authorization code'}
                }
            }
        },
        401: {
            'description': 'Unauthorized - client authentication failed',
            'content': {
                'application/json': {
                    'example': {'error': 'invalid_client', 'error_description': 'Client authentication failed'}
                }
            }
        }
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def oauth2_token_view(request):
    """
    OAuth 2.0 token endpoint (server-to-server).
    
    Handles token issuance for various grant types.
    Requires client authentication.
    """
    try:
        log_message("OAuth 2.0 token request received", "INFO")
        log_request_info(request)
        
        # Get grant type
        grant_type = request.POST.get('grant_type')
        if not grant_type:
            return Response({
                'error': 'invalid_request',
                'error_description': 'Missing grant_type parameter'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Extract client credentials (from Authorization header or request body)
        client_id = request.POST.get('client_id')
        client_secret = request.POST.get('client_secret')
        
        # Try HTTP Basic Auth if not in body
        if not client_id or not client_secret:
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if auth_header.startswith('Basic '):
                import base64
                try:
                    decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    client_id, client_secret = decoded.split(':', 1)
                except Exception:
                    pass
        
        # Validate client credentials
        valid, client = validate_client_credentials(client_id, client_secret)
        if not valid:
            log_security_event(
                'oauth2_invalid_client',
                'WARNING',
                'Invalid client credentials',
                {'client_id': client_id}
            )
            return Response({
                'error': 'invalid_client',
                'error_description': 'Client authentication failed'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Validate grant type is allowed for this client
        if grant_type not in client.get('grant_types', []):
            return Response({
                'error': 'unauthorized_client',
                'error_description': f'Grant type {grant_type} not allowed for this client'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Handle different grant types
        if grant_type == 'authorization_code':
            return handle_authorization_code_grant(request, client_id)
        elif grant_type == 'refresh_token':
            return handle_refresh_token_grant(request, client_id)
        elif grant_type == 'password':
            return handle_password_grant(request, client_id)
        elif grant_type == 'client_credentials':
            return handle_client_credentials_grant(request, client_id)
        else:
            return Response({
                'error': 'unsupported_grant_type',
                'error_description': f'Grant type {grant_type} is not supported'
            }, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        log_error(e, 'oauth2_token_view')
        return Response({
            'error': 'server_error',
            'error_description': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def handle_authorization_code_grant(request, client_id):
    """Handle authorization_code grant type."""
    code = request.POST.get('code')
    redirect_uri = request.POST.get('redirect_uri')
    
    if not code or not redirect_uri:
        return Response({
            'error': 'invalid_request',
            'error_description': 'Missing code or redirect_uri'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Validate authorization code
    code_data = validate_authorization_code(code, client_id, redirect_uri)
    if not code_data:
        log_security_event(
            'oauth2_invalid_grant',
            'WARNING',
            'Invalid or expired authorization code',
            {'client_id': client_id, 'code': code[:10] + '...'}
        )
        return Response({
            'error': 'invalid_grant',
            'error_description': 'Invalid or expired authorization code'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Get user
    from django.contrib.auth import get_user_model
    try:
        user = get_user_model().objects.get(id=code_data['user_id'])
    except get_user_model().DoesNotExist:
        return Response({
            'error': 'invalid_grant',
            'error_description': 'User not found'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Generate tokens
    refresh = RefreshToken.for_user(user)
    access = refresh.access_token
    
    # Log token issuance
    log_auth_event(
        'oauth2_token_issued',
        user_id=str(user.id),
        ip_address=request.META.get('REMOTE_ADDR'),
        additional_data={
            'client_id': client_id,
            'grant_type': 'authorization_code',
            'scope': code_data['scope']
        }
    )
    
    return Response({
        'access_token': str(access),
        'token_type': 'Bearer',
        'expires_in': ACCESS_TOKEN_EXPIRY,
        'refresh_token': str(refresh),
        'scope': code_data['scope']
    }, status=status.HTTP_200_OK)


def handle_refresh_token_grant(request, client_id):
    """Handle refresh_token grant type."""
    refresh_token = request.POST.get('refresh_token')
    
    if not refresh_token:
        return Response({
            'error': 'invalid_request',
            'error_description': 'Missing refresh_token'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Validate and refresh token
        refresh = RefreshToken(refresh_token)
        access = refresh.access_token
        
        # Log token refresh
        log_auth_event(
            'oauth2_token_refreshed',
            user_id=str(refresh.payload.get('user_id')),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={'client_id': client_id}
        )
        
        return Response({
            'access_token': str(access),
            'token_type': 'Bearer',
            'expires_in': ACCESS_TOKEN_EXPIRY,
            'refresh_token': str(refresh),
            'scope': 'read write'
        }, status=status.HTTP_200_OK)
        
    except TokenError as e:
        return Response({
            'error': 'invalid_grant',
            'error_description': 'Invalid refresh token'
        }, status=status.HTTP_400_BAD_REQUEST)


def handle_password_grant(request, client_id):
    """Handle password grant type (Resource Owner Password Credentials)."""
    username = request.POST.get('username')
    password = request.POST.get('password')
    scope = request.POST.get('scope', 'read')
    
    if not username or not password:
        return Response({
            'error': 'invalid_request',
            'error_description': 'Missing username or password'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Authenticate user
    user = authenticate(request, username=username, password=password)
    if not user:
        log_security_event(
            'oauth2_password_grant_failed',
            'WARNING',
            f'Failed password grant for username: {username}',
            {'client_id': client_id, 'username': username}
        )
        return Response({
            'error': 'invalid_grant',
            'error_description': 'Invalid username or password'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Generate tokens
    refresh = RefreshToken.for_user(user)
    access = refresh.access_token
    
    # Log token issuance
    log_auth_event(
        'oauth2_token_issued',
        user_id=str(user.id),
        ip_address=request.META.get('REMOTE_ADDR'),
        additional_data={
            'client_id': client_id,
            'grant_type': 'password',
            'scope': scope
        }
    )
    
    return Response({
        'access_token': str(access),
        'token_type': 'Bearer',
        'expires_in': ACCESS_TOKEN_EXPIRY,
        'refresh_token': str(refresh),
        'scope': scope
    }, status=status.HTTP_200_OK)


def handle_client_credentials_grant(request, client_id):
    """Handle client_credentials grant type (machine-to-machine)."""
    scope = request.POST.get('scope', 'read')
    
    # For client credentials, we create a token without a user
    # You might want to create a service account user for this
    from django.contrib.auth import get_user_model
    
    # Create or get a service account for this client
    service_account_username = f'service_{client_id}'
    user, created = get_user_model().objects.get_or_create(
        username=service_account_username,
        defaults={
            'email': f'{service_account_username}@service.local',
            'is_active': True
        }
    )
    
    # Generate access token (no refresh token for client credentials)
    refresh = RefreshToken.for_user(user)
    access = refresh.access_token
    
    # Log token issuance
    log_auth_event(
        'oauth2_token_issued',
        user_id=str(user.id),
        ip_address=request.META.get('REMOTE_ADDR'),
        additional_data={
            'client_id': client_id,
            'grant_type': 'client_credentials',
            'scope': scope
        }
    )
    
    return Response({
        'access_token': str(access),
        'token_type': 'Bearer',
        'expires_in': ACCESS_TOKEN_EXPIRY,
        'scope': scope
    }, status=status.HTTP_200_OK)


@extend_schema(
    tags=['OAuth 2.0 UserInfo'],
    summary='OAuth 2.0 UserInfo Endpoint',
    description='''
    OAuth 2.0 UserInfo endpoint (resource API). Returns information about the authenticated user.
    
    This endpoint is protected and requires a valid Bearer access token in the Authorization header.
    
    Returns user profile information including:
    - sub: Subject identifier (user ID)
    - email: User email address
    - name: User's full name
    - preferred_username: Username
    - given_name: First name
    - family_name: Last name
    - roles: User roles
    ''',
    responses={
        200: {
            'description': 'User information retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'sub': '12345',
                        'email': 'john@example.com',
                        'name': 'John Doe',
                        'preferred_username': 'john_doe',
                        'given_name': 'John',
                        'family_name': 'Doe',
                        'email_verified': True,
                        'roles': ['user', 'admin']
                    }
                }
            }
        },
        401: {
            'description': 'Unauthorized - invalid or missing access token',
            'content': {
                'application/json': {
                    'example': {'error': 'invalid_token', 'error_description': 'Access token is invalid or expired'}
                }
            }
        }
    }
)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def oauth2_userinfo_view(request):
    """
    OAuth 2.0 UserInfo endpoint (resource API).
    
    Returns user information based on access token.
    Requires Bearer token authentication.
    """
    try:
        log_message(f"OAuth 2.0 UserInfo request for user {request.user.username}", "INFO")
        log_request_info(request)
        
        # Get user roles
        user_roles = get_user_roles(request.user)
        
        # Build UserInfo response according to OpenID Connect standard
        userinfo = {
            'sub': str(request.user.id),  # Subject - unique user identifier
            'email': request.user.email,
            'name': f"{request.user.first_name} {request.user.last_name}".strip() or request.user.username,
            'preferred_username': request.user.username,
            'given_name': request.user.first_name,
            'family_name': request.user.last_name,
            'email_verified': True,  # Assume email is verified
            'roles': user_roles,
            'updated_at': int(request.user.date_joined.timestamp())
        }
        
        # Log UserInfo access
        log_auth_event(
            'oauth2_userinfo_accessed',
            user_id=str(request.user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={'username': request.user.username}
        )
        
        return Response(userinfo, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'oauth2_userinfo_view', {
            'user_id': str(request.user.id) if request.user.is_authenticated else None
        })
        return Response({
            'error': 'server_error',
            'error_description': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

