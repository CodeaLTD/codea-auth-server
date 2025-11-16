"""
Middleware for request logging and monitoring.

This middleware automatically logs all HTTP requests with timing information,
which is useful for monitoring and performance analysis on Render.
"""

import time
import logging
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger('codea_auth_server')


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Middleware that logs all HTTP requests with response times.
    
    This is especially useful for Render deployment where logs are captured
    from stdout/stderr.
    """
    
    def process_request(self, request):
        """Store the start time of the request."""
        request._start_time = time.time()
        return None
    
    def process_response(self, request, response):
        """Log the request details and response time."""
        if hasattr(request, '_start_time'):
            duration = time.time() - request._start_time
            status_code = response.status_code
            client_ip = self._get_client_ip(request)
            
            # Determine log level based on status code
            if status_code >= 500:
                log_level = logger.error
            elif status_code >= 400:
                log_level = logger.warning
            else:
                log_level = logger.info
            
            # Log all requests with status code (including health checks)
            log_message = (
                f"{request.method} {request.path} - "
                f"HTTP {status_code} - "
                f"Duration: {duration:.3f}s - "
                f"IP: {client_ip}"
            )
            
            # Use appropriate log level based on status code
            log_level(log_message)
            
            # Log slow requests as warnings
            if duration > 1.0:
                logger.warning(
                    f"Slow request detected: {request.method} {request.path} "
                    f"HTTP {status_code} - "
                    f"took {duration:.3f}s"
                )
        
        return response
    
    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

