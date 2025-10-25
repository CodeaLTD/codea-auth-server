"""
Role management utilities for the Codea Auth Server.

This module provides role checking functions, decorators, and utilities
for handling user roles in the authentication system.
"""

import json
from functools import wraps
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework import status
import logging

from codea_auth_server.logging_utils import log_auth_event, log_security_event, log_error

# Get logger for this module
logger = logging.getLogger('codea_auth_server')


def get_user_roles(user):
    """
    Get roles for a user.
    
    Args:
        user: User object
        
    Returns:
        list: List of user roles
    """
    try:
        if hasattr(user, 'roles'):
            # If roles is a JSON field or string, parse it
            if isinstance(user.roles, str):
                try:
                    return json.loads(user.roles)
                except (json.JSONDecodeError, TypeError):
                    return [user.roles] if user.roles else []
            elif isinstance(user.roles, list):
                return user.roles
            else:
                return []
        return []
    except Exception as e:
        logger.error(f"Error getting user roles: {str(e)}")
        return []


def has_role(user, role):
    """
    Check if user has a specific role.
    
    Args:
        user: User object
        role: Role to check for
        
    Returns:
        bool: True if user has the role, False otherwise
    """
    try:
        user_roles = get_user_roles(user)
        return role in user_roles
    except Exception as e:
        logger.error(f"Error checking user role: {str(e)}")
        return False


def has_any_role(user, roles):
    """
    Check if user has any of the specified roles.
    
    Args:
        user: User object
        roles: List of roles to check for
        
    Returns:
        bool: True if user has any of the roles, False otherwise
    """
    try:
        user_roles = get_user_roles(user)
        return any(role in user_roles for role in roles)
    except Exception as e:
        logger.error(f"Error checking user roles: {str(e)}")
        return False


def has_all_roles(user, roles):
    """
    Check if user has all of the specified roles.
    
    Args:
        user: User object
        roles: List of roles to check for
        
    Returns:
        bool: True if user has all of the roles, False otherwise
    """
    try:
        user_roles = get_user_roles(user)
        return all(role in user_roles for role in roles)
    except Exception as e:
        logger.error(f"Error checking user roles: {str(e)}")
        return False


def role_required(required_role):
    """
    Decorator that requires a specific role for the view.
    
    Args:
        required_role: The role required to access the view
        
    Returns:
        Decorated view function that checks for role
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            try:
                if not request.user.is_authenticated:
                    log_security_event(
                        'role_auth_failed',
                        'WARNING',
                        'User not authenticated for role check',
                        {'ip_address': request.META.get('REMOTE_ADDR')}
                    )
                    return JsonResponse({'error': 'Authentication required'}, status=401)
                
                if not has_role(request.user, required_role):
                    log_security_event(
                        'role_auth_failed',
                        'WARNING',
                        f'User {request.user.username} lacks required role: {required_role}',
                        {
                            'user_id': str(request.user.id),
                            'username': request.user.username,
                            'required_role': required_role,
                            'user_roles': get_user_roles(request.user),
                            'ip_address': request.META.get('REMOTE_ADDR')
                        }
                    )
                    return JsonResponse({
                        'error': f'Role required: {required_role}',
                        'required_role': required_role,
                        'user_roles': get_user_roles(request.user)
                    }, status=403)
                
                # Log successful role check
                log_auth_event(
                    'role_check_success',
                    user_id=str(request.user.id),
                    ip_address=request.META.get('REMOTE_ADDR'),
                    additional_data={
                        'username': request.user.username,
                        'required_role': required_role,
                        'user_roles': get_user_roles(request.user)
                    }
                )
                
                return view_func(request, *args, **kwargs)
                
            except Exception as e:
                log_error(e, 'role_required_decorator')
                return JsonResponse({'error': 'Role check error'}, status=500)
        
        return wrapper
    return decorator


def any_role_required(required_roles):
    """
    Decorator that requires any of the specified roles for the view.
    
    Args:
        required_roles: List of roles, user must have at least one
        
    Returns:
        Decorated view function that checks for roles
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            try:
                if not request.user.is_authenticated:
                    log_security_event(
                        'role_auth_failed',
                        'WARNING',
                        'User not authenticated for role check',
                        {'ip_address': request.META.get('REMOTE_ADDR')}
                    )
                    return JsonResponse({'error': 'Authentication required'}, status=401)
                
                if not has_any_role(request.user, required_roles):
                    log_security_event(
                        'role_auth_failed',
                        'WARNING',
                        f'User {request.user.username} lacks any required role: {required_roles}',
                        {
                            'user_id': str(request.user.id),
                            'username': request.user.username,
                            'required_roles': required_roles,
                            'user_roles': get_user_roles(request.user),
                            'ip_address': request.META.get('REMOTE_ADDR')
                        }
                    )
                    return JsonResponse({
                        'error': f'One of these roles required: {", ".join(required_roles)}',
                        'required_roles': required_roles,
                        'user_roles': get_user_roles(request.user)
                    }, status=403)
                
                # Log successful role check
                log_auth_event(
                    'role_check_success',
                    user_id=str(request.user.id),
                    ip_address=request.META.get('REMOTE_ADDR'),
                    additional_data={
                        'username': request.user.username,
                        'required_roles': required_roles,
                        'user_roles': get_user_roles(request.user)
                    }
                )
                
                return view_func(request, *args, **kwargs)
                
            except Exception as e:
                log_error(e, 'any_role_required_decorator')
                return JsonResponse({'error': 'Role check error'}, status=500)
        
        return wrapper
    return decorator


def all_roles_required(required_roles):
    """
    Decorator that requires all of the specified roles for the view.
    
    Args:
        required_roles: List of roles, user must have all
        
    Returns:
        Decorated view function that checks for roles
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            try:
                if not request.user.is_authenticated:
                    log_security_event(
                        'role_auth_failed',
                        'WARNING',
                        'User not authenticated for role check',
                        {'ip_address': request.META.get('REMOTE_ADDR')}
                    )
                    return JsonResponse({'error': 'Authentication required'}, status=401)
                
                if not has_all_roles(request.user, required_roles):
                    log_security_event(
                        'role_auth_failed',
                        'WARNING',
                        f'User {request.user.username} lacks all required roles: {required_roles}',
                        {
                            'user_id': str(request.user.id),
                            'username': request.user.username,
                            'required_roles': required_roles,
                            'user_roles': get_user_roles(request.user),
                            'ip_address': request.META.get('REMOTE_ADDR')
                        }
                    )
                    return JsonResponse({
                        'error': f'All of these roles required: {", ".join(required_roles)}',
                        'required_roles': required_roles,
                        'user_roles': get_user_roles(request.user)
                    }, status=403)
                
                # Log successful role check
                log_auth_event(
                    'role_check_success',
                    user_id=str(request.user.id),
                    ip_address=request.META.get('REMOTE_ADDR'),
                    additional_data={
                        'username': request.user.username,
                        'required_roles': required_roles,
                        'user_roles': get_user_roles(request.user)
                    }
                )
                
                return view_func(request, *args, **kwargs)
                
            except Exception as e:
                log_error(e, 'all_roles_required_decorator')
                return JsonResponse({'error': 'Role check error'}, status=500)
        
        return wrapper
    return decorator


def drf_role_required(required_role):
    """
    DRF-style decorator for role-based access control.
    
    Args:
        required_role: The role required to access the view
        
    Returns:
        Decorated view function that requires the role
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not has_role(request.user, required_role):
                return Response(
                    {
                        'error': f'Role required: {required_role}',
                        'required_role': required_role,
                        'user_roles': get_user_roles(request.user)
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def drf_any_role_required(required_roles):
    """
    DRF-style decorator for role-based access control (any role).
    
    Args:
        required_roles: List of roles, user must have at least one
        
    Returns:
        Decorated view function that requires any of the roles
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not has_any_role(request.user, required_roles):
                return Response(
                    {
                        'error': f'One of these roles required: {", ".join(required_roles)}',
                        'required_roles': required_roles,
                        'user_roles': get_user_roles(request.user)
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator
