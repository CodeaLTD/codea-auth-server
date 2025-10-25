"""
User management API views for the Codea Auth Server.

This module handles user registration, profile management,
and user-related operations.
"""

from queue import Empty
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiExample
from drf_spectacular.types import OpenApiTypes
import logging

from codea_auth_server.logging_utils import log_auth_event, log_security_event, log_request_info, log_error, log_message, log_database_operation
from .jwt_utils import jwt_required, jwt_optional
from .role_utils import get_user_roles, has_role, has_any_role, has_all_roles

# Get logger for this module
logger = logging.getLogger('codea_auth_server')



@extend_schema(
    tags=['Authentication'],
    summary='User Registration',
    description='Register a new user account with username, email, and password',
    request={
        'application/x-www-form-urlencoded': {
            'type': 'object',
            'properties': {
                'username': {
                    'type': 'string',
                    'description': 'Unique username for the account',
                    'example': 'john_doe'
                },
                'email': {
                    'type': 'string',
                    'format': 'email',
                    'description': 'User email address',
                    'example': 'john@example.com'
                },
                'password': {
                    'type': 'string',
                    'format': 'password',
                    'description': 'User password',
                    'example': 'securepassword123'
                },
                'first_name': {
                    'type': 'string',
                    'description': 'User first name (optional)',
                    'example': 'John'
                },
                'last_name': {
                    'type': 'string',
                    'description': 'User last name (optional)',
                    'example': 'Doe'
                },
                'roles': {
                    'type': 'string',
                    'description': 'Comma-separated list of roles (optional)',
                    'example': 'general-user,taxapp-user'
                }
            },
            'required': ['username', 'email', 'password']
        }
    },
    responses={
        201: {
            'description': 'User registered successfully',
            'content': {
                'application/json': {
                    'example': {
                        'message': 'User registered successfully',
                        'user_id': 1,
                        'username': 'john_doe'
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - validation error',
            'content': {
                'application/json': {
                    'examples': {
                        'missing_fields': {
                            'summary': 'Missing required fields',
                            'value': {
                                'error': 'Username, email, and password are required'
                            }
                        },
                        'username_exists': {
                            'summary': 'Username already exists',
                            'value': {
                                'error': 'Username already exists'
                            }
                        },
                        'email_exists': {
                            'summary': 'Email already exists',
                            'value': {
                                'error': 'Email already exists'
                            }
                        }
                    }
                }
            }
        },
        500: {
            'description': 'Internal server error',
            'content': {
                'application/json': {
                    'example': {
                        'error': 'Internal server error'
                    }
                }
            }
        }
    }
)
@require_http_methods(["POST"])
def register_view(request):
    """
    User registration endpoint.
    
    Creates a new user account with the provided credentials.
    Username and email must be unique across the system.
    """
    try:
        log_message("User registration attempt started", "INFO")
        log_request_info(request)
        
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        roles = request.POST.get('roles', '')
        
        if not username or not email or not password:
            log_security_event(
                'invalid_registration_attempt',
                'WARNING',
                'Missing required registration fields',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return JsonResponse({'error': 'Username, email, and password are required'}, status=400)
        
        # Check if user already exists
        from django.contrib.auth import get_user_model
        if get_user_model().objects.filter(username=username).exists():
            log_security_event(
                'duplicate_username_registration',
                'WARNING',
                f'Registration attempt with existing username: {username}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return JsonResponse({'error': 'Username already exists'}, status=400)
        
        if get_user_model().objects.filter(email=email).exists():
            log_security_event(
                'duplicate_email_registration',
                'WARNING',
                f'Registration attempt with existing email: {email}',
                {'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return JsonResponse({'error': 'Email already exists'}, status=400)
        
        # Create new user
        user = get_user_model().objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            roles=roles
        )
        
        log_database_operation('CREATE', 'User', str(user.id), {
            'username': username,
            'email': email
        })
        
        log_auth_event(
            'user_registered',
            user_id=str(user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={'username': username, 'email': email}
        )
        
        log_message(f"User {username} registered successfully", "INFO")
        
        return JsonResponse({
            'message': 'User registered successfully',
            'user_id': user.id,
            'username': user.username
        }, status=201)
        
    except Exception as e:
        log_error(e, 'register_view', {
            'username': request.POST.get('username'),
            'email': request.POST.get('email'),
            'ip_address': request.META.get('REMOTE_ADDR')
        })
        return JsonResponse({'error': 'Internal server error'}, status=500)


@extend_schema(
    tags=['Users'],
    summary='Get User Profile',
    description='Get current user profile information (JWT authentication required)',
    responses={
        200: {
            'description': 'Profile retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'user_id': 1,
                        'username': 'john_doe',
                        'email': 'john@example.com',
                        'first_name': 'John',
                        'last_name': 'Doe',
                        'roles': ['general-user', 'taxapp-user'],
                        'date_joined': '2024-01-01T00:00:00Z',
                        'last_login': '2024-01-01T12:00:00Z',
                        'is_active': True
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
def profile_view(request):
    """
    Get user profile information with JWT authentication.
    """
    try:
        log_message(f"Profile requested by user {request.user.username}", "INFO")
        log_request_info(request)
        
        profile_data = {
            'user_id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'roles': request.user.roles,
            'date_joined': request.user.date_joined.isoformat(),
            'last_login': request.user.last_login.isoformat() if request.user.last_login else None,
            'is_active': request.user.is_active,
        }
        
        log_message(f"Profile data retrieved for user {request.user.username}", "INFO")
        
        return Response(profile_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'profile_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@require_http_methods(["PUT"])
def update_profile_view(request):
    """
    Update user profile information.
    """
    try:
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)
        
        log_message(f"Profile update requested by user {request.user.username}", "INFO")
        log_request_info(request)
        
        # Get updated fields
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        roles = request.POST.get('roles')
        
        updated_fields = []
        
        if first_name is not None:
            request.user.first_name = first_name
            updated_fields.append('first_name')
        
        if last_name is not None:
            request.user.last_name = last_name
            updated_fields.append('last_name')
        
        if email is not None:
            from django.contrib.auth import get_user_model
            if get_user_model().objects.filter(email=email).exclude(id=request.user.id).exists():
                return JsonResponse({'error': 'Email already exists'}, status=400)
            request.user.email = email
            updated_fields.append('email')
        
        if roles is not None or len(roles) > 0:
            request.user.roles = roles
            updated_fields.append('roles')

        if updated_fields:
            request.user.save()
            
            log_database_operation('UPDATE', 'User', str(request.user.id), {
                'updated_fields': updated_fields
            })
            
            log_auth_event(
                'profile_updated',
                user_id=str(request.user.id),
                ip_address=request.META.get('REMOTE_ADDR'),
                additional_data={
                    'username': request.user.username,
                    'updated_fields': updated_fields
                }
            )
            
            log_message(f"Profile updated for user {request.user.username}: {', '.join(updated_fields)}", "INFO")
        
        return JsonResponse({
            'message': 'Profile updated successfully',
            'updated_fields': updated_fields
        })
        
    except Exception as e:
        log_error(e, 'update_profile_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return JsonResponse({'error': 'Internal server error'}, status=500)


@require_http_methods(["GET"])
def user_list_view(request):
    """
    List all users (admin only).
    """
    try:
        if not request.user.is_authenticated or not request.user.is_staff:
            return JsonResponse({'error': 'Admin access required'}, status=403)
        
        log_message(f"User list requested by admin {request.user.username}", "INFO")
        log_request_info(request)
        
        from django.contrib.auth import get_user_model
        users = get_user_model().objects.all().values('id', 'username', 'email', 'first_name', 'last_name','roles' ,'is_active', 'date_joined')
        users_list = list(users)
        
        log_message(f"User list returned {len(users_list)} users", "INFO")
        
        return JsonResponse({
            'users': users_list,
            'count': len(users_list)
        })
        
    except Exception as e:
        log_error(e, 'user_list_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return JsonResponse({'error': 'Internal server error'}, status=500)


@extend_schema(
    tags=['Users'],
    summary='Check User Role',
    description='Check if the current user has a specific role (JWT authentication required)',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'role': {'type': 'string', 'description': 'Role to check for'}
            },
            'required': ['role']
        }
    },
    responses={
        200: {
            'description': 'Role check completed',
            'content': {
                'application/json': {
                    'example': {
                        'has_role': True,
                        'user_id': 1,
                        'username': 'john_doe'
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - missing role parameter',
            'content': {
                'application/json': {
                    'example': {'error': 'Role parameter is required'}
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
def check_role_view(request):
    """
    Check if the current user has a specific role.
    """
    try:
        log_message(f"Role check requested by user {request.user.username}", "INFO")
        log_request_info(request)
        
        role = request.data.get('role')
        
        if not role:
            return Response({'error': 'Role parameter is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        has_specific_role = has_role(request.user, role)
        
        # Log role check
        log_auth_event(
            'role_check_requested',
            user_id=str(request.user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={
                'username': request.user.username,
                'checked_role': role,
                'has_role': has_specific_role
            }
        )
        
        log_message(f"Role check for user {request.user.username}: {role} = {has_specific_role}", "INFO")
        
        return Response({
            'has_role': has_specific_role,
            'role': role,
            'user_id': request.user.id,
            'username': request.user.username
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'check_role_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Users'],
    summary='Check User Roles (Any)',
    description='Check if the current user has any of the specified roles (JWT authentication required)',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'roles': {
                    'type': 'array',
                    'items': {'type': 'string'},
                    'description': 'List of roles to check for (user needs at least one)'
                }
            },
            'required': ['roles']
        }
    },
    responses={
        200: {
            'description': 'Role check completed',
            'content': {
                'application/json': {
                    'example': {
                        'has_any_role': True,
                        'checked_roles': ['admin', 'moderator'],
                        'user_roles': ['admin', 'user'],
                        'user_id': 1,
                        'username': 'john_doe'
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - missing roles parameter',
            'content': {
                'application/json': {
                    'example': {'error': 'Roles parameter is required'}
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
def check_any_role_view(request):
    """
    Check if the current user has any of the specified roles.
    """
    try:
        log_message(f"Any role check requested by user {request.user.username}", "INFO")
        log_request_info(request)
        
        roles = request.data.get('roles')
        
        if not roles or not isinstance(roles, list):
            return Response({'error': 'Roles parameter is required and must be a list'}, status=status.HTTP_400_BAD_REQUEST)
        
        user_roles = get_user_roles(request.user)
        has_any_specified_role = has_any_role(request.user, roles)
        
        # Log role check
        log_auth_event(
            'any_role_check_requested',
            user_id=str(request.user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={
                'username': request.user.username,
                'checked_roles': roles,
                'has_any_role': has_any_specified_role,
                'user_roles': user_roles
            }
        )
        
        log_message(f"Any role check for user {request.user.username}: {roles} = {has_any_specified_role}", "INFO")
        
        return Response({
            'has_any_role': has_any_specified_role,
            'checked_roles': roles,
            'user_roles': user_roles,
            'user_id': request.user.id,
            'username': request.user.username
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'check_any_role_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Users'],
    summary='Check User Roles (All)',
    description='Check if the current user has all of the specified roles (JWT authentication required)',
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'roles': {
                    'type': 'array',
                    'items': {'type': 'string'},
                    'description': 'List of roles to check for (user needs all)'
                }
            },
            'required': ['roles']
        }
    },
    responses={
        200: {
            'description': 'Role check completed',
            'content': {
                'application/json': {
                    'example': {
                        'has_all_roles': True,
                        'checked_roles': ['admin', 'moderator'],
                        'user_roles': ['admin', 'moderator', 'user'],
                        'user_id': 1,
                        'username': 'john_doe'
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - missing roles parameter',
            'content': {
                'application/json': {
                    'example': {'error': 'Roles parameter is required'}
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
def check_all_roles_view(request):
    """
    Check if the current user has all of the specified roles.
    """
    try:
        log_message(f"All roles check requested by user {request.user.username}", "INFO")
        log_request_info(request)
        
        roles = request.data.get('roles')
        
        if not roles or not isinstance(roles, list):
            return Response({'error': 'Roles parameter is required and must be a list'}, status=status.HTTP_400_BAD_REQUEST)
        
        user_roles = get_user_roles(request.user)
        has_all_specified_roles = has_all_roles(request.user, roles)
        
        # Log role check
        log_auth_event(
            'all_roles_check_requested',
            user_id=str(request.user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={
                'username': request.user.username,
                'checked_roles': roles,
                'has_all_roles': has_all_specified_roles,
                'user_roles': user_roles
            }
        )
        
        log_message(f"All roles check for user {request.user.username}: {roles} = {has_all_specified_roles}", "INFO")
        
        return Response({
            'has_all_roles': has_all_specified_roles,
            'checked_roles': roles,
            'user_roles': user_roles,
            'user_id': request.user.id,
            'username': request.user.username
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'check_all_roles_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Users'],
    summary='Get User Roles',
    description='Get all roles for the current user (JWT authentication required)',
    responses={
        200: {
            'description': 'User roles retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'user_roles': ['admin', 'user'],
                        'user_id': 1,
                        'username': 'john_doe'
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
def get_user_roles_view(request):
    """
    Get all roles for the current user.
    """
    try:
        log_message(f"User roles requested by user {request.user.username}", "INFO")
        log_request_info(request)
        
        user_roles = get_user_roles(request.user)
        
        # Log role retrieval
        log_auth_event(
            'user_roles_retrieved',
            user_id=str(request.user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={
                'username': request.user.username,
                'user_roles': user_roles
            }
        )
        
        log_message(f"User roles retrieved for user {request.user.username}: {user_roles}", "INFO")
        
        return Response({
            'user_roles': user_roles,
            'user_id': request.user.id,
            'username': request.user.username
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'get_user_roles_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Users'],
    summary='Update User Profile',
    description='Update current user profile information (JWT authentication required)',
    request={
        'application/x-www-form-urlencoded': {
            'type': 'object',
            'properties': {
                'email': {
                    'type': 'string',
                    'format': 'email',
                    'description': 'Updated email address',
                    'example': 'newemail@example.com'
                },
                'first_name': {
                    'type': 'string',
                    'description': 'Updated first name',
                    'example': 'Jane'
                },
                'last_name': {
                    'type': 'string',
                    'description': 'Updated last name',
                    'example': 'Smith'
                },
                'roles': {
                    'type': 'string',
                    'description': 'Updated comma-separated list of roles',
                    'example': 'general-user,admin'
                }
            }
        }
    },
    responses={
        200: {
            'description': 'Profile updated successfully',
            'content': {
                'application/json': {
                    'example': {
                        'message': 'Profile updated successfully',
                        'user_id': 1,
                        'username': 'john_doe',
                        'email': 'newemail@example.com',
                        'first_name': 'Jane',
                        'last_name': 'Smith',
                        'roles': ['general-user', 'admin']
                    }
                }
            }
        },
        400: {
            'description': 'Bad request - validation error',
            'content': {
                'application/json': {
                    'examples': {
                        'email_exists': {
                            'summary': 'Email already exists',
                            'value': {
                                'error': 'Email already exists'
                            }
                        },
                        'invalid_data': {
                            'summary': 'Invalid data provided',
                            'value': {
                                'error': 'Invalid data provided'
                            }
                        }
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
@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_profile_view(request):
    """
    Update current user profile information.
    
    Allows authenticated users to update their email, first name, last name, and roles.
    Email must be unique across the system.
    """
    try:
        log_message(f"Profile update attempt by user {request.user.username}", "INFO")
        log_request_info(request)
        
        # Get data from request
        email = request.data.get('email') or request.POST.get('email')
        first_name = request.data.get('first_name') or request.POST.get('first_name')
        last_name = request.data.get('last_name') or request.POST.get('last_name')
        roles = request.data.get('roles') or request.POST.get('roles')
        
        # Check if email is being updated and if it already exists
        if email and email != request.user.email:
            from django.contrib.auth import get_user_model
            if get_user_model().objects.filter(email=email).exclude(id=request.user.id).exists():
                log_security_event(
                    'duplicate_email_update',
                    'WARNING',
                    f'Profile update attempt with existing email: {email}',
                    {'ip_address': request.META.get('REMOTE_ADDR'), 'user_id': str(request.user.id)}
                )
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Update user fields
        if email is not None:
            request.user.email = email
        if first_name is not None:
            request.user.first_name = first_name
        if last_name is not None:
            request.user.last_name = last_name
        if roles is not None:
            request.user.roles = roles
        
        # Save the user
        request.user.save()
        
        # Log the update
        log_database_operation('UPDATE', 'User', str(request.user.id), {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'roles': roles
        })
        
        log_auth_event(
            'user_profile_updated',
            user_id=str(request.user.id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={
                'username': request.user.username,
                'updated_fields': {
                    'email': email,
                    'first_name': first_name,
                    'last_name': last_name,
                    'roles': roles
                }
            }
        )
        
        log_message(f"Profile updated for user {request.user.username}", "INFO")
        
        return Response({
            'message': 'Profile updated successfully',
            'user_id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'roles': request.user.roles.split(',') if request.user.roles else []
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'update_profile_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Users'],
    summary='Delete User Profile',
    description='Delete current user profile and account (JWT authentication required)',
    responses={
        200: {
            'description': 'Profile deleted successfully',
            'content': {
                'application/json': {
                    'example': {
                        'message': 'Profile deleted successfully',
                        'user_id': 1,
                        'username': 'john_doe'
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
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_profile_view(request):
    """
    Delete current user profile and account.
    
    Permanently deletes the authenticated user's account and all associated data.
    This action cannot be undone.
    """
    try:
        log_message(f"Profile deletion attempt by user {request.user.username}", "WARNING")
        log_request_info(request)
        
        user_id = request.user.id
        username = request.user.username
        
        # Log the deletion attempt
        log_auth_event(
            'user_profile_deletion_attempt',
            user_id=str(user_id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={
                'username': username,
                'email': request.user.email
            }
        )
        
        # Delete the user
        request.user.delete()
        
        # Log the successful deletion
        log_database_operation('DELETE', 'User', str(user_id), {
            'username': username,
            'email': request.user.email if hasattr(request.user, 'email') else None
        })
        
        log_auth_event(
            'user_profile_deleted',
            user_id=str(user_id),
            ip_address=request.META.get('REMOTE_ADDR'),
            additional_data={
                'username': username
            }
        )
        
        log_message(f"Profile deleted for user {username}", "WARNING")
        
        return Response({
            'message': 'Profile deleted successfully',
            'user_id': user_id,
            'username': username
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'delete_profile_view', {'user_id': str(request.user.id) if request.user.is_authenticated else None})
        return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
