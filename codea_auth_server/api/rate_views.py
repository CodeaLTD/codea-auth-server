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
    tags=['API Management'],
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
        rate_limit_enabled = getattr(settings, 'REST_FRAMEWORK', {}).get('DEFAULT_THROTTLE_CLASSES', None) is not None
        
        # Get rate limit configuration (if available)
        throttle_settings = getattr(settings, 'REST_FRAMEWORK', {}).get('DEFAULT_THROTTLE_RATES', {})
        
        # Parse throttle settings and set default limits
        def parse_rate_limit(rate_str):
            """Parse rate limit string like '100/min' or '1000/hour' and return the number."""
            try:
                if isinstance(rate_str, (int, float)):
                    return int(rate_str)
                return int(rate_str.split('/')[0])
            except (ValueError, AttributeError):
                return None
        
        user_rate = throttle_settings.get('user', '100/min')
        anonymous_rate = throttle_settings.get('anon', '60/min')
        rate_str = user_rate if request.user.is_authenticated else anonymous_rate
        
        # Default limits if not configured
        default_limits = {
            'per_minute': parse_rate_limit(rate_str) or 60,
            'per_hour': parse_rate_limit(throttle_settings.get('user', '1000/hour')) or 1000,
            'per_day': parse_rate_limit(throttle_settings.get('user', '10000/day')) or 10000
        }
        
        # Try to get current rate limit usage from cache (if rate limiting is active)
        current_usage = None
        if rate_limit_enabled:
            # Construct cache keys for rate limiting
            minute_key = f"rate_limit:{identifier_value}:minute"
            hour_key = f"rate_limit:{identifier_value}:hour"
            day_key = f"rate_limit:{identifier_value}:day"
            
            # Get current counts (these would be set by rate limiting middleware/throttle classes)
            minute_count = cache.get(minute_key, 0)
            hour_count = cache.get(hour_key, 0)
            day_count = cache.get(day_key, 0)
            
            # Use the most restrictive limit for display
            current_usage = {
                'requests': max(minute_count, hour_count, day_count),
                'limit': int(default_limits['per_minute']),
                'remaining': max(0, int(default_limits['per_minute']) - minute_count),
                'reset_at': time.time() + 60  # Approximate reset time
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
            'limits': default_limits if rate_limit_enabled else {},
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

