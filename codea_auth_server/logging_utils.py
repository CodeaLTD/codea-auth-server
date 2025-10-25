"""
Logging utilities for the Codea Auth Server.

This module provides convenient logging functions and configurations
for different parts of the authentication system.
"""

from email import message
import logging
from typing import Optional, Dict, Any
from datetime import datetime

# Get loggers for different components
logger = logging.getLogger('codea_auth_server')
auth_logger = logging.getLogger('auth')
django_logger = logging.getLogger('django')


def log_message(message: str, severity: str = 'INFO') -> None:
    """
    Simple logging function with message and severity level.
    
    Args:
        message: The log message
        severity: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    timestamped_message = f"[{timestamp}] {message}"
    log_level = getattr(logging, severity.upper(), logging.INFO)
    logger.log(log_level, timestamped_message)



def log_auth_event(event_type: str, user_id: Optional[str] = None, 
                   ip_address: Optional[str] = None, 
                   additional_data: Optional[Dict[str, Any]] = None) -> None:
    """
    Log authentication-related events.
    
    Args:
        event_type: Type of auth event (e.g., 'login', 'logout', 'failed_login')
        user_id: ID of the user (if applicable)
        ip_address: IP address of the request
        additional_data: Additional data to log
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_data = {
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip_address,
        'timestamp': timestamp,
    }
    
    if additional_data:
        log_data.update(additional_data)
    
    auth_logger.info(f"[{timestamp}] Auth event: {event_type}", extra=log_data)


def log_security_event(event_type: str, severity: str = 'WARNING',
                      details: Optional[str] = None,
                      additional_data: Optional[Dict[str, Any]] = None) -> None:
    """
    Log security-related events.
    
    Args:
        event_type: Type of security event
        severity: Severity level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        details: Additional details about the event
        additional_data: Additional data to log
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_data = {
        'event_type': event_type,
        'severity': severity,
        'details': details,
        'timestamp': timestamp,
    }
    
    if additional_data:
        log_data.update(additional_data)
    
    log_level = getattr(logging, severity.upper(), logging.WARNING)
    auth_logger.log(log_level, f"[{timestamp}] Security event: {event_type}", extra=log_data)


def log_request_info(request, response=None, processing_time: Optional[float] = None) -> None:
    """
    Log request information for debugging and monitoring.
    
    Args:
        request: Django request object
        response: Django response object (optional)
        processing_time: Time taken to process the request (optional)
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_data = {
        'method': request.method,
        'path': request.path,
        'user_agent': request.META.get('HTTP_USER_AGENT', 'Unknown'),
        'ip_address': request.META.get('REMOTE_ADDR', 'Unknown'),
        'user': str(request.user) if hasattr(request, 'user') and request.user.is_authenticated else 'Anonymous',
        'timestamp': timestamp,
    }
    
    if response:
        log_data['status_code'] = response.status_code
    
    if processing_time:
        log_data['processing_time'] = f"{processing_time:.3f}s"
    
    logger.info(f"[{timestamp}] Request processed: {request.method} {request.path}", extra=log_data)


def log_database_operation(operation: str, model: str, 
                          record_id: Optional[str] = None,
                          additional_data: Optional[Dict[str, Any]] = None) -> None:
    """
    Log database operations for auditing.
    
    Args:
        operation: Type of operation (CREATE, READ, UPDATE, DELETE)
        model: Model name
        record_id: ID of the record (if applicable)
        additional_data: Additional data to log
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_data = {
        'operation': operation,
        'model': model,
        'record_id': record_id,
        'timestamp': timestamp,
    }
    
    if additional_data:
        log_data.update(additional_data)
    
    logger.debug(f"[{timestamp}] Database operation: {operation} on {model}", extra=log_data)


def log_error(error: Exception, context: Optional[str] = None,
              additional_data: Optional[Dict[str, Any]] = None) -> None:
    """
    Log errors with context information.
    
    Args:
        error: Exception object
        context: Context where the error occurred
        additional_data: Additional data to log
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_data = {
        'error_type': type(error).__name__,
        'error_message': str(error),
        'context': context,
        'timestamp': timestamp,
    }
    
    if additional_data:
        log_data.update(additional_data)
    
    logger.error(f"[{timestamp}] Error in {context or 'unknown context'}: {error}", 
                extra=log_data, exc_info=True)
