"""
Health and system monitoring API views for the Codea Auth Server.

This module handles health checks, system status,
and monitoring endpoints.
"""

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.db import connection
from django.core.cache import cache
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiExample
from drf_spectacular.types import OpenApiTypes
import logging
import time
import psutil
import os

from codea_auth_server.logging_utils import log_request_info, log_error, log_message

# Get logger for this module
logger = logging.getLogger('codea_auth_server')


@extend_schema(
    tags=['Health'],
    summary='Basic Health Check',
    description='Simple health check endpoint to verify the server is running. Optimized for uptime monitors.',
    responses={
        200: {
            'description': 'Server is healthy',
            'content': {
                'application/json': {
                    'example': {
                        'status': 'healthy',
                        'message': 'Auth server is running',
                        'timestamp': 1640995200.0
                    }
                }
            }
        }
    }
)
@api_view(['GET'])
@permission_classes([AllowAny])
def health_check_view(request):
    """
    Basic health check endpoint optimized for uptime monitors.
    Lightweight, fast, and reliable - no heavy operations or logging.
    """
    # Minimal response - no logging to ensure fast response for uptime monitors
    return Response({
        'status': 'ok',
        'message': 'Auth server is running',
        'timestamp': time.time()
    }, status=status.HTTP_200_OK)


@extend_schema(
    tags=['Health'],
    summary='Detailed Health Check',
    description='Comprehensive health check with system metrics, database status, and cache status',
    responses={
        200: {
            'description': 'Detailed health information',
            'content': {
                'application/json': {
                    'example': {
                        'status': 'healthy',
                        'timestamp': 1640995200.0,
                        'services': {
                            'database': 'healthy',
                            'cache': 'healthy'
                        },
                        'system_metrics': {
                            'cpu_percent': 15.2,
                            'memory': {
                                'total': 8589934592,
                                'available': 4294967296,
                                'percent': 50.0
                            },
                            'disk': {
                                'total': 107374182400,
                                'free': 53687091200,
                                'percent': 50.0
                            }
                        }
                    }
                }
            }
        },
        500: {
            'description': 'Server error',
            'content': {
                'application/json': {
                    'example': {
                        'error': 'Health check failed'
                    }
                }
            }
        }
    }
)
@api_view(['GET'])
@permission_classes([AllowAny])
def detailed_health_view(request):
    """
    Detailed health check with system metrics.
    """
    try:
        log_message("Detailed health check requested", "INFO")
        log_request_info(request)
        
        # Check database connection
        db_status = "healthy"
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
        except Exception as e:
            db_status = "unhealthy"
            log_message(f"Database health check failed: {str(e)}", "ERROR")
        
        # Check cache (if available)
        cache_status = "healthy"
        try:
            cache.set('health_check', 'test', 10)
            if cache.get('health_check') != 'test':
                cache_status = "unhealthy"
        except Exception as e:
            cache_status = "unhealthy"
            log_message(f"Cache health check failed: {str(e)}", "ERROR")
        
        # Get system metrics
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            system_metrics = {
                'cpu_percent': cpu_percent,
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent
                },
                'disk': {
                    'total': disk.total,
                    'free': disk.free,
                    'percent': (disk.used / disk.total) * 100
                }
            }
        except Exception as e:
            log_message(f"System metrics collection failed: {str(e)}", "WARNING")
            system_metrics = None
        
        overall_status = "healthy" if db_status == "healthy" and cache_status == "healthy" else "degraded"
        
        health_data = {
            'status': overall_status,
            'timestamp': time.time(),
            'services': {
                'database': db_status,
                'cache': cache_status
            },
            'system_metrics': system_metrics
        }
        
        log_message(f"Detailed health check completed: {overall_status}", "INFO")
        
        return Response(health_data)
        
    except Exception as e:
        log_error(e, 'detailed_health_view')
        return Response({'error': 'Health check failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Health'],
    summary='System Metrics',
    description='Detailed system metrics for monitoring and performance analysis',
    responses={
        200: {
            'description': 'System metrics data',
            'content': {
                'application/json': {
                    'example': {
                        'timestamp': 1640995200.0,
                        'uptime': 86400.0,
                        'process': {
                            'pid': 1234,
                            'cpu_percent': 2.5,
                            'memory_percent': 1.2,
                            'memory_info': {
                                'rss': 12345678,
                                'vms': 98765432
                            }
                        },
                        'system': {
                            'cpu_count': 8,
                            'cpu_percent': 15.2,
                            'memory': {
                                'total': 8589934592,
                                'available': 4294967296,
                                'percent': 50.0
                            },
                            'disk': {
                                'total': 107374182400,
                                'free': 53687091200,
                                'used': 53687091200
                            }
                        }
                    }
                }
            }
        },
        500: {
            'description': 'Server error',
            'content': {
                'application/json': {
                    'example': {
                        'error': 'Metrics collection failed'
                    }
                }
            }
        }
    }
)
@api_view(['GET'])
@permission_classes([AllowAny])
def metrics_view(request):
    """
    System metrics endpoint for monitoring.
    """
    try:
        log_message("Metrics requested", "INFO")
        log_request_info(request)
        
        # Get basic system information
        metrics = {
            'timestamp': time.time(),
            'uptime': time.time() - psutil.boot_time(),
            'process': {
                'pid': os.getpid(),
                'cpu_percent': psutil.Process().cpu_percent(),
                'memory_percent': psutil.Process().memory_percent(),
                'memory_info': psutil.Process().memory_info()._asdict()
            },
            'system': {
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory()._asdict(),
                'disk': psutil.disk_usage('/')._asdict()
            }
        }
        
        log_message("Metrics collected successfully", "INFO")
        
        return Response(metrics)
        
    except Exception as e:
        log_error(e, 'metrics_view')
        return Response({'error': 'Metrics collection failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    tags=['Health'],
    summary='Application Status',
    description='Application status and configuration information',
    responses={
        200: {
            'description': 'Application status data',
            'content': {
                'application/json': {
                    'example': {
                        'application': 'Codea Auth Server',
                        'version': '1.0.0',
                        'environment': 'development',
                        'debug_mode': True,
                        'database_engine': 'django.db.backends.sqlite3',
                        'installed_apps_count': 7,
                        'middleware_count': 8,
                        'timestamp': 1640995200.0
                    }
                }
            }
        },
        500: {
            'description': 'Server error',
            'content': {
                'application/json': {
                    'example': {
                        'error': 'Status check failed'
                    }
                }
            }
        }
    }
)
@api_view(['GET'])
@permission_classes([AllowAny])
def status_view(request):
    """
    Application status endpoint.
    """
    try:
        log_message("Status requested", "INFO")
        log_request_info(request)
        
        # Get Django settings info
        from django.conf import settings
        
        status_data = {
            'application': 'Codea Auth Server',
            'version': '1.0.0',
            'environment': 'development' if settings.DEBUG else 'production',
            'debug_mode': settings.DEBUG,
            'database_engine': settings.DATABASES['default']['ENGINE'],
            'installed_apps_count': len(settings.INSTALLED_APPS),
            'middleware_count': len(settings.MIDDLEWARE),
            'timestamp': time.time()
        }
        
        log_message("Status information provided", "INFO")
        
        return Response(status_data)
        
    except Exception as e:
        log_error(e, 'status_view')
        return Response({'error': 'Status check failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
