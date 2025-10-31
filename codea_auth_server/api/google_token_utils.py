"""
Google OAuth token management utilities for production-ready token handling.

This module provides utilities for:
- Encrypted storage of refresh tokens
- Token rotation management
- Handling revoked Google tokens
- Automatic token refresh
"""

import requests
from django.utils import timezone
from django.contrib.auth.models import User
from .models import UserProfile
from codea_auth_server.logging_utils import log_error, log_message
import logging

logger = logging.getLogger('codea_auth_server')


def get_or_create_user_profile(user):
    """
    Get or create a UserProfile for a user.
    
    Args:
        user: User instance
    
    Returns:
        UserProfile instance
    """
    profile, created = UserProfile.objects.get_or_create(user=user)
    return profile


def store_google_token(user, refresh_token, google_user_id=None, picture_url=None):
    """
    Store encrypted Google refresh token for a user.
    
    Args:
        user: User instance
        refresh_token: Google refresh token to store
        google_user_id: Optional Google user ID
        picture_url: Optional Google picture URL
    
    Returns:
        bool: True if successful
    """
    try:
        profile = get_or_create_user_profile(user)
        profile.set_encrypted_refresh_token(refresh_token)
        if google_user_id:
            profile.google_user_id = google_user_id
        if picture_url:
            profile.google_picture_url = picture_url
        profile.save()
        log_message(f"Google refresh token stored for user {user.username}", "INFO")
        return True
    except Exception as e:
        log_error(e, 'store_google_token', {'user_id': str(user.id)})
        return False


def get_stored_refresh_token(user):
    """
    Retrieve and decrypt the stored Google refresh token for a user.
    
    Args:
        user: User instance
    
    Returns:
        str or None: Decrypted refresh token
    """
    try:
        if not hasattr(user, 'profile'):
            return None
        
        profile = user.profile
        return profile.get_encrypted_refresh_token()
    except Exception as e:
        log_error(e, 'get_stored_refresh_token', {'user_id': str(user.id)})
        return None


def refresh_google_access_token(refresh_token, client_id, client_secret):
    """
    Refresh Google OAuth access token.
    
    Args:
        refresh_token: Google refresh token
        client_id: OAuth client ID
        client_secret: OAuth client secret
    
    Returns:
        tuple: (access_token, new_refresh_token) or (None, None) if failed
    """
    try:
        token_url = 'https://oauth2.googleapis.com/token'
        
        data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }
        
        response = requests.post(token_url, data=data)
        
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access_token')
            new_refresh_token = token_data.get('refresh_token', refresh_token)
            return access_token, new_refresh_token
        elif response.status_code == 400:
            error_data = response.json()
            if error_data.get('error') == 'invalid_grant':
                # Token has been revoked
                log_message("Google refresh token has been revoked", "WARNING")
                return None, None
        else:
            log_message(f"Failed to refresh Google token: {response.status_code}", "ERROR")
            return None, None
    except Exception as e:
        log_error(e, 'refresh_google_access_token')
        return None, None


def handle_revoked_token(user):
    """
    Handle revoked Google token by clearing stored credentials.
    
    Args:
        user: User instance
    """
    try:
        if hasattr(user, 'profile'):
            profile = user.profile
            profile.google_refresh_token = None
            profile.last_refresh = None
            profile.save()
            log_message(f"Cleared revoked Google token for user {user.username}", "WARNING")
    except Exception as e:
        log_error(e, 'handle_revoked_token', {'user_id': str(user.id)})


def auto_refresh_google_token(user, client_id, client_secret):
    """
    Automatically refresh Google access token if expired.
    
    Args:
        user: User instance
        client_id: OAuth client ID
        client_secret: OAuth client secret
    
    Returns:
        str or None: New access token or None if failed
    """
    try:
        if not hasattr(user, 'profile'):
            return None
        
        profile = user.profile
        
        # Check if token needs rotation
        if profile.is_token_expired(expiration_hours=24):
            refresh_token = profile.get_encrypted_refresh_token()
            if not refresh_token:
                return None
            
            access_token, new_refresh_token = refresh_google_access_token(
                refresh_token, client_id, client_secret
            )
            
            if access_token:
                # Store the new refresh token if Google provided one
                if new_refresh_token and new_refresh_token != refresh_token:
                    profile.set_encrypted_refresh_token(new_refresh_token)
                    profile.tokens_rotated_at = timezone.now()
                
                profile.update_last_refresh()
                log_message(f"Auto-refreshed Google token for user {user.username}", "INFO")
                return access_token
            else:
                # Token was revoked
                handle_revoked_token(user)
                return None
        
        return None
    except Exception as e:
        log_error(e, 'auto_refresh_google_token', {'user_id': str(user.id)})
        return None


