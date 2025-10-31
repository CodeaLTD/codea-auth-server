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

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',') if os.environ.get('ALLOWED_HOSTS') else []
if not ALLOWED_HOSTS:
    # In production without ALLOWED_HOSTS set, default to localhost
    ALLOWED_HOSTS = ['localhost', '127.0.0.1']

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

# CORS origins should be set via environment variable in production
CORS_ALLOWED_ORIGINS = os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') if os.environ.get('CORS_ALLOWED_ORIGINS') else []

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

# Update Swagger servers for production if provided
if 'API_BASE_URL' in os.environ:
    SPECTACULAR_SETTINGS['SERVERS'] = [
        {'url': os.environ.get('API_BASE_URL'), 'description': 'Production server'},
    ]

# Security settings for production
SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'False').lower() == 'true'
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
CSRF_COOKIE_SECURE = os.environ.get('CSRF_COOKIE_SECURE', 'False').lower() == 'true'
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

