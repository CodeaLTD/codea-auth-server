"""
Production settings for codea_auth_server project.

These settings are used when ENVIRONMENT='production'.
"""

import os
from .base import *

# SECURITY WARNING: keep the secret key used in production secret!
# In production, set DJANGO_SECRET_KEY environment variable
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("DJANGO_SECRET_KEY environment variable must be set in production!")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# ALLOWED_HOSTS configuration
# Supports both environment variable and automatic Render.com detection
env_hosts = os.environ.get('ALLOWED_HOSTS', '').split(',') if os.environ.get('ALLOWED_HOSTS') else []
env_hosts = [host.strip() for host in env_hosts if host.strip()]  # Remove empty strings

if not env_hosts:
    # Default to localhost if no environment variable is set
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '.onrender.com']
else:
    # Use environment variable hosts and ensure Render.com is included
    ALLOWED_HOSTS = env_hosts
    # Add .onrender.com if not already present (supports all Render subdomains)
    if '.onrender.com' not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append('.onrender.com')

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

# PostgreSQL for production
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'codea_auth'),
        'USER': os.environ.get('DB_USER', 'codea_user'),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
        'OPTIONS': {
            'connect_timeout': 10,
        },
    }
}

# CORS Configuration
# https://github.com/adamchainz/django-cors-headers

# Default localhost origins for local development/testing
default_origins = [
    "http://localhost:3000",  # React development server
    "http://127.0.0.1:3000",
    "http://localhost:8080",  # Vue development server
    "http://127.0.0.1:8080",
    "http://localhost:4200",  # Angular development server
    "http://127.0.0.1:4200",
    "http://localhost:8000",  # Django development server
    "http://127.0.0.1:8000",
]

# Additional origins from environment variable (comma-separated)
env_origins = os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') if os.environ.get('CORS_ALLOWED_ORIGINS') else []
env_origins = [origin.strip() for origin in env_origins if origin.strip()]  # Remove empty strings

# Combine default localhost origins with environment-specified origins
CORS_ALLOWED_ORIGINS = default_origins + env_origins

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_ALL_ORIGINS = False  # Never allow all origins in production

# JWT Configuration - Update SIGNING_KEY
SIMPLE_JWT['SIGNING_KEY'] = SECRET_KEY

# Google OAuth Configuration
# https://developers.google.com/identity/protocols/oauth2
# All values MUST be set via environment variables in production

GOOGLE_OAUTH_CONFIG = {
    'CLIENT_ID': os.environ.get('GOOGLE_CLIENT_ID'),
    'CLIENT_SECRET': os.environ.get('GOOGLE_CLIENT_SECRET'),
    'REDIRECT_URI': os.environ.get('GOOGLE_REDIRECT_URI'),
    'SCOPE': 'openid email profile',
    'AUTH_URL': 'https://accounts.google.com/o/oauth2/v2/auth',
    'TOKEN_URL': 'https://oauth2.googleapis.com/token',
    'USER_INFO_URL': 'https://www.googleapis.com/oauth2/v2/userinfo',
}

# Validate required Google OAuth configuration
if not GOOGLE_OAUTH_CONFIG['CLIENT_ID']:
    raise ValueError("GOOGLE_CLIENT_ID environment variable must be set in production!")
if not GOOGLE_OAUTH_CONFIG['CLIENT_SECRET']:
    raise ValueError("GOOGLE_CLIENT_SECRET environment variable must be set in production!")
if not GOOGLE_OAUTH_CONFIG['REDIRECT_URI']:
    raise ValueError("GOOGLE_REDIRECT_URI environment variable must be set in production!")

# Google OAuth Token Encryption Key
# MUST be set via environment variable in production
GOOGLE_TOKEN_ENCRYPTION_KEY = os.environ.get('GOOGLE_TOKEN_ENCRYPTION_KEY')
if not GOOGLE_TOKEN_ENCRYPTION_KEY:
    raise ValueError("GOOGLE_TOKEN_ENCRYPTION_KEY environment variable must be set in production!")

# Update Swagger servers for production
# Use API_BASE_URL from environment if provided, otherwise use default production URL
api_base_url = os.environ.get('API_BASE_URL', 'https://codea-auth-server.onrender.com')
SPECTACULAR_SETTINGS['SERVERS'] = [
    {'url': api_base_url, 'description': 'Production server'},
]

# Security settings for production
SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'False').lower() == 'true'
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
CSRF_COOKIE_SECURE = os.environ.get('CSRF_COOKIE_SECURE', 'False').lower() == 'true'
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Production Logging Configuration
# Logs to both console (for Render monitoring) and files (for backup/analysis)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {asctime} {name} {message}',
            'style': '{',
        },
        'detailed': {
            'format': '[{asctime}] {levelname} in {name}: {message}',
            'style': '{',
        },
    },
    'handlers': {
        # Console handlers for Render (stdout/stderr)
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'detailed',
            'stream': 'ext://sys.stdout',
        },
        'console_error': {
            'level': 'ERROR',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'stream': 'ext://sys.stderr',
        },
        # File handlers for backup and analysis
        'file_info': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': LOGS_DIR / 'info.log',
            'formatter': 'detailed',
        },
        'file_error': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': LOGS_DIR / 'error.log',
            'formatter': 'verbose',
        },
        'file_auth': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': LOGS_DIR / 'auth.log',
            'formatter': 'detailed',
        },
        'file_debug': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': LOGS_DIR / 'debug.log',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'console_error', 'file_info', 'file_error'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'console_error', 'file_info', 'file_error'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console_error', 'file_error'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['console_error', 'file_error'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['console', 'file_debug'],
            'level': 'WARNING',  # Reduce DB query logging in production
            'propagate': False,
        },
        'codea_auth_server': {
            'handlers': ['console', 'console_error', 'file_info', 'file_error', 'file_debug'],
            'level': 'INFO',
            'propagate': False,
        },
        'auth': {
            'handlers': ['console', 'file_auth'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

