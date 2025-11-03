"""
API Rate Limiting views for the Codea Auth Server.

This module provides rate limiting status and information endpoints.
"""

from drf_spectacular.utils import extend_schema
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
import logging
import time
from django.core.cache import cache
from django.conf import settings

from codea_auth_server.logging_utils import log_request_info, log_message, log_error

# Get logger for this module
logger = logging.getLogger('codea_auth_server')


@extend_schema(
    tags=['API Rate Limiter'],
    summary='API Rate Limiter Status',
    description='Get rate limit information and status for the current user or IP address',
    responses={
        200: {
            'description': 'Rate limit information retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'rate_limit_enabled': True,
                        'current_usage': {
                            'requests': 45,
                            'limit': 100,
                            'remaining': 55,
                            'reset_at': 1640995260.0
                        },
                        'limits': {
                            'per_minute': 60,
                            'per_hour': 1000,
                            'per_day': 10000
                        },
                        'identifier': {
                            'type': 'ip_address',
                            'value': '127.0.0.1'
                        },
                        'timestamp': 1640995200.0
                    }
                }
            }
        }
    }
)
@api_view(['GET'])
@authentication_classes([])  # No authentication required
@permission_classes([AllowAny])  # Allow any user
def apiLimiter(request):
    """
    Get rate limit status and information for the current request.
    """
    try:
        log_message("API rate limiter status requested", "INFO")
        log_request_info(request)
        
        # Get client identifier (IP address or user ID)
        client_ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        identifier_type = 'user_id' if request.user.is_authenticated else 'ip_address'
        identifier_value = str(request.user.id) if request.user.is_authenticated else client_ip
        
        # Check if rate limiting is configured in settings
        rest_framework_settings = getattr(settings, 'REST_FRAMEWORK', {})
        throttle_classes = rest_framework_settings.get('DEFAULT_THROTTLE_CLASSES', [])
        rate_limit_enabled = len(throttle_classes) > 0 if throttle_classes else False
        
        # Get rate limit configuration (if available)
        throttle_settings = rest_framework_settings.get('DEFAULT_THROTTLE_RATES', {})
        
        # Parse throttle settings and extract limits
        def parse_rate_limit(rate_str):
            """Parse rate limit string like '60/minute' or '500/hour' and return (value, period)."""
            try:
                if isinstance(rate_str, (int, float)):
                    return int(rate_str), 'minute'
                parts = rate_str.split('/')
                value = int(parts[0])
                period = parts[1].lower().strip() if len(parts) > 1 else 'minute'
                return value, period
            except (ValueError, AttributeError, IndexError):
                return None, None
        
        # Get appropriate rate limit based on authentication status
        if request.user.is_authenticated:
            user_rate = throttle_settings.get('user', '500/hour')
            value, period = parse_rate_limit(user_rate)
            # Parse user rate (typically per hour)
            per_hour = value if period in ['hour', 'h'] else (value * 60 if period in ['minute', 'min'] else value)
            per_minute = value if period in ['minute', 'min'] else (per_hour // 60 if per_hour else 60)
            per_day = per_hour * 24 if per_hour else 10000
        else:
            anon_rate = throttle_settings.get('anon', '60/minute')
            value, period = parse_rate_limit(anon_rate)
            # Parse anonymous rate (typically per minute)
            per_minute = value if period in ['minute', 'min'] else (value // 60 if period in ['hour', 'h'] else value)
            per_hour = value if period in ['hour', 'h'] else (per_minute * 60 if per_minute else 500)
            per_day = per_hour * 24 if per_hour else 10000
        
        # Set limits based on configuration
        if rate_limit_enabled:
            default_limits = {
                'per_minute': per_minute or 60,
                'per_hour': per_hour or 500,
                'per_day': per_day or 10000
            }
        else:
            default_limits = {}
        
        # Try to get current rate limit usage from cache (if rate limiting is active)
        current_usage = None
        if rate_limit_enabled:
            # DRF stores throttle history in cache with format: 'throttle_{scope}_{ident}'
            throttle_scope = 'user' if request.user.is_authenticated else 'anon'
            throttle_ident = str(request.user.id) if request.user.is_authenticated else client_ip
            
            # DRF's throttle classes use cache keys like: 'throttle_anon_127.0.0.1'
            # They store a list of timestamps representing request history
            throttle_key = f'throttle_{throttle_scope}_{throttle_ident}'
            throttle_history = cache.get(throttle_key, [])
            
            # Get the active limit and period
            if not request.user.is_authenticated:
                # Anonymous users: use per_minute limit
                active_limit = per_minute
                active_period_seconds = 60
            else:
                # Authenticated users: use per_hour limit
                active_limit = per_hour
                active_period_seconds = 3600
            
            # Calculate current usage from throttle history
            current_time = time.time()
            if isinstance(throttle_history, list):
                # Count requests within the active period
                cutoff_time = current_time - active_period_seconds
                recent_requests = [t for t in throttle_history if isinstance(t, (int, float)) and t > cutoff_time]
                request_count = len(recent_requests)
            else:
                # Fallback if history format is unexpected
                request_count = 0
            
            # Calculate remaining requests
            remaining = max(0, active_limit - request_count)
            
            # Calculate reset time (next period boundary)
            if active_period_seconds == 60:
                reset_at = current_time + (60 - (current_time % 60))
            else:
                reset_at = current_time + (3600 - (current_time % 3600))
            
            current_usage = {
                'requests': request_count,
                'limit': active_limit,
                'remaining': remaining,
                'reset_at': reset_at
            }
        else:
            # Rate limiting not configured
            current_usage = {
                'requests': 0,
                'limit': 'unlimited',
                'remaining': 'unlimited',
                'reset_at': None
            }
        
        rate_limit_info = {
            'rate_limit_enabled': rate_limit_enabled,
            'current_usage': current_usage,
            'limits': default_limits,
            'identifier': {
                'type': identifier_type,
                'value': identifier_value
            },
            'timestamp': time.time(),
            'note': 'Rate limiting configuration is handled via REST Framework throttling classes' if rate_limit_enabled else 'Rate limiting is not currently configured'
        }
        
        log_message(f"API rate limiter status provided: enabled={rate_limit_enabled}", "INFO")
        
        return Response(rate_limit_info, status=status.HTTP_200_OK)
        
    except Exception as e:
        log_error(e, 'apiLimiter')
        return Response(
            {'error': 'Failed to retrieve rate limit information'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

