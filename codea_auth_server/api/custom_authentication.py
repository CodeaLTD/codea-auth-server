"""
Custom authentication classes for the Codea Auth Server.

This module provides custom authentication that allows certain endpoints
to bypass authentication errors.
"""

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import SessionAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed


class OptionalJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication that doesn't raise exceptions for health endpoints.
    
    This allows health check endpoints to work without authentication even if
    an invalid token is provided in the request.
    """
    
    def authenticate(self, request):
        """
        Override authenticate to not raise exceptions for health endpoints.
        """
        # List of paths that should bypass authentication errors
        bypass_paths = [
            '/api/health/',
            '/api/health/detailed/',
            '/api/health/metrics/',
            '/api/health/status/',
        ]
        
        # Check if current path should bypass authentication
        if any(request.path.startswith(path) for path in bypass_paths):
            # Try to authenticate, but don't raise exceptions
            try:
                return super().authenticate(request)
            except Exception:
                # Return None to allow anonymous access for health endpoints
                return None
        
        # For other endpoints, use normal authentication
        return super().authenticate(request)


class OptionalSessionAuthentication(SessionAuthentication):
    """
    Custom Session authentication that doesn't raise exceptions for health endpoints.
    """
    
    def authenticate(self, request):
        """
        Override authenticate to not raise exceptions for health endpoints.
        """
        # List of paths that should bypass authentication errors
        bypass_paths = [
            '/api/health/',
            '/api/health/detailed/',
            '/api/health/metrics/',
            '/api/health/status/',
        ]
        
        # Check if current path should bypass authentication
        if any(request.path.startswith(path) for path in bypass_paths):
            # Try to authenticate, but don't raise exceptions
            try:
                return super().authenticate(request)
            except Exception:
                # Return None to allow anonymous access
                return None
        
        # For other endpoints, use normal authentication
        return super().authenticate(request)

