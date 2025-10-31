"""
Development settings for codea_auth_server project.

These settings are used when ENVIRONMENT is not set to 'production'.
"""

import os
from cryptography.fernet import Fernet
from .base import *

# SECURITY WARNING: keep the secret key used in production secret!
# In production, set DJANGO_SECRET_KEY environment variable
# Generate a new key with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-1l1mts+sy7wse&7=6758c56&khhcto-zzv&uw7c-qbq15&n-^!')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',') if os.environ.get('ALLOWED_HOSTS') else []

# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

# SQLite3 for development
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# CORS Configuration
# https://github.com/adamchainz/django-cors-headers

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # React development server
    "http://127.0.0.1:3000",
    "http://localhost:8080",  # Vue development server
    "http://127.0.0.1:8080",
    "http://localhost:4200",  # Angular development server
    "http://127.0.0.1:4200",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_ALL_ORIGINS = True  # Allow all origins in development

# JWT Configuration - Update SIGNING_KEY
SIMPLE_JWT['SIGNING_KEY'] = SECRET_KEY

# Google OAuth Configuration
# https://developers.google.com/identity/protocols/oauth2

GOOGLE_OAUTH_CONFIG = {
    'CLIENT_ID': os.environ.get('GOOGLE_CLIENT_ID'),
    'CLIENT_SECRET': os.environ.get('GOOGLE_CLIENT_SECRET'),
    'REDIRECT_URI': os.environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:8000/api/auth/google/auth/'),
    'SCOPE': 'openid email profile',
    'AUTH_URL': 'https://accounts.google.com/o/oauth2/v2/auth',
    'TOKEN_URL': 'https://oauth2.googleapis.com/token',
    'USER_INFO_URL': 'https://www.googleapis.com/oauth2/v2/userinfo',
}

# Google OAuth Token Encryption Key
# Generate a key with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
if 'GOOGLE_TOKEN_ENCRYPTION_KEY' in os.environ:
    GOOGLE_TOKEN_ENCRYPTION_KEY = os.environ['GOOGLE_TOKEN_ENCRYPTION_KEY']
else:
    # Generate a temporary key for development (NOT for production!)
    GOOGLE_TOKEN_ENCRYPTION_KEY = Fernet.generate_key().decode()

