"""
JWT Authentication utilities for the Codea Auth Server.

This module provides JWT authentication decorators, middleware, and utility functions
for handling JWT tokens in the authentication system.
"""

from functools import wraps
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.authentication import JWTAuthentication
import logging

from codea_auth_server.logging_utils import log_auth_event, log_security_event, log_error

# Get logger for this module
logger = logging.getLogger('codea_auth_server')


def jwt_required(view_func):
    """
    Decorator that requires a valid JWT token for the view.
    
    This decorator can be used on Django view functions to ensure
    that the request contains a valid JWT access token.
    
    Args:
        view_func: The view function to decorate
        
    Returns:
        Decorated view function that checks for JWT authentication
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        try:
            # Extract token from Authorization header
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            
            if not auth_header.startswith('Bearer '):
                log_security_event(
                    'jwt_auth_failed',
                    'WARNING',
                    'Missing or invalid Authorization header',
                    {'ip_address': request.META.get('REMOTE_ADDR')}
                )
                return JsonResponse({'error': 'Authorization header required'}, status=401)
            
            token = auth_header.split(' ')[1]
            
            # Validate the token
            try:
                access_token = AccessToken(token)
                user_id = access_token.payload.get('user_id')
                
                # Get user from database
                from django.contrib.auth import get_user_model
                try:
                    user = get_user_model().objects.get(id=user_id)
                    request.user = user
                    request.jwt_payload = access_token.payload
                    
                    # Log successful authentication
                    log_auth_event(
                        'jwt_auth_success',
                        user_id=str(user_id),
                        ip_address=request.META.get('REMOTE_ADDR'),
                        additional_data={'username': user.username}
                    )
                    
                except User.DoesNotExist:
                    log_security_event(
                        'jwt_auth_failed',
                        'WARNING',
                        'User not found for JWT token',
                        {'user_id': str(user_id), 'ip_address': request.META.get('REMOTE_ADDR')}
                    )
                    return JsonResponse({'error': 'Invalid token'}, status=401)
                    
            except TokenError as e:
                log_security_event(
                    'jwt_auth_failed',
                    'WARNING',
                    f'Invalid JWT token: {str(e)}',
                    {'ip_address': request.META.get('REMOTE_ADDR')}
                )
                return JsonResponse({'error': 'Invalid token'}, status=401)
            
            # Call the original view function
            return view_func(request, *args, **kwargs)
            
        except Exception as e:
            log_error(e, 'jwt_required_decorator')
            return JsonResponse({'error': 'Authentication error'}, status=500)
    
    return wrapper


def jwt_optional(view_func):
    """
    Decorator that optionally validates JWT token if present.
    
    This decorator can be used on Django view functions where
    JWT authentication is optional. If a token is present, it will
    be validated and the user will be set on the request.
    
    Args:
        view_func: The view function to decorate
        
    Returns:
        Decorated view function that optionally checks for JWT authentication
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        try:
            # Extract token from Authorization header
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                
                try:
                    # Validate the token
                    access_token = AccessToken(token)
                    user_id = access_token.payload.get('user_id')
                    
                    # Get user from database
                    from django.contrib.auth import get_user_model
                    try:
                        user = get_user_model().objects.get(id=user_id)
                        request.user = user
                        request.jwt_payload = access_token.payload
                        request.is_jwt_authenticated = True
                        
                        # Log successful authentication
                        log_auth_event(
                            'jwt_optional_auth_success',
                            user_id=str(user_id),
                            ip_address=request.META.get('REMOTE_ADDR'),
                            additional_data={'username': user.username}
                        )
                        
                    except User.DoesNotExist:
                        log_security_event(
                            'jwt_optional_auth_failed',
                            'WARNING',
                            'User not found for JWT token',
                            {'user_id': str(user_id), 'ip_address': request.META.get('REMOTE_ADDR')}
                        )
                        request.is_jwt_authenticated = False
                        
                except TokenError as e:
                    log_security_event(
                        'jwt_optional_auth_failed',
                        'WARNING',
                        f'Invalid JWT token: {str(e)}',
                        {'ip_address': request.META.get('REMOTE_ADDR')}
                    )
                    request.is_jwt_authenticated = False
            else:
                request.is_jwt_authenticated = False
            
            # Call the original view function
            return view_func(request, *args, **kwargs)
            
        except Exception as e:
            log_error(e, 'jwt_optional_decorator')
            request.is_jwt_authenticated = False
            return view_func(request, *args, **kwargs)
    
    return wrapper


class JWTMiddleware:
    """
    Middleware for automatic JWT authentication.
    
    This middleware automatically validates JWT tokens in the Authorization
    header and sets the user on the request object.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = JWTAuthentication()
    
    def __call__(self, request):
        # Process the request
        try:
            # Try to authenticate with JWT
            auth_result = self.jwt_auth.authenticate(request)
            if auth_result:
                user, token = auth_result
                request.user = user
                request.jwt_payload = token.payload
                request.is_jwt_authenticated = True
                
                # Log successful authentication
                log_auth_event(
                    'jwt_middleware_auth_success',
                    user_id=str(user.id),
                    ip_address=request.META.get('REMOTE_ADDR'),
                    additional_data={'username': user.username}
                )
            else:
                request.is_jwt_authenticated = False
                
        except Exception as e:
            log_error(e, 'jwt_middleware')
            request.is_jwt_authenticated = False
        
        response = self.get_response(request)
        return response


def get_user_from_jwt(request):
    """
    Extract user information from JWT token in request.
    
    Args:
        request: Django request object
        
    Returns:
        User object if token is valid, None otherwise
    """
    try:
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header.split(' ')[1]
        access_token = AccessToken(token)
        user_id = access_token.payload.get('user_id')
        
        from django.contrib.auth import get_user_model
        return get_user_model().objects.get(id=user_id)
        
    except (TokenError, get_user_model().DoesNotExist, IndexError):
        return None


def get_jwt_payload(request):
    """
    Extract JWT payload from request.
    
    Args:
        request: Django request object
        
    Returns:
        JWT payload dict if token is valid, None otherwise
    """
    try:
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header.split(' ')[1]
        access_token = AccessToken(token)
        return access_token.payload
        
    except (TokenError, IndexError):
        return None


def is_jwt_authenticated(request):
    """
    Check if request is authenticated with JWT.
    
    Args:
        request: Django request object
        
    Returns:
        bool: True if JWT authenticated, False otherwise
    """
    return getattr(request, 'is_jwt_authenticated', False)


def require_jwt_auth(view_func):
    """
    DRF-style decorator for JWT authentication.
    
    This decorator can be used with DRF views to require JWT authentication.
    
    Args:
        view_func: The view function to decorate
        
    Returns:
        Decorated view function that requires JWT authentication
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not is_jwt_authenticated(request):
            return Response(
                {'error': 'JWT authentication required'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        return view_func(request, *args, **kwargs)
    
    return wrapper
