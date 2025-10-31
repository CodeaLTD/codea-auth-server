"""
User profile models for storing Google OAuth tokens and related data.

This module extends the User model with additional fields for production-ready
Google OAuth integration.
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from cryptography.fernet import Fernet
from django.conf import settings
import base64
import os
import json
import logging

logger = logging.getLogger('codea_auth_server')


# Add roles property to User model via monkey patching
@property
def user_roles(self):
    """Get user roles as a list."""
    try:
        if hasattr(self, '_roles_cache'):
            # Check if roles exist in the database via a custom field or OneToOne
            profile = getattr(self, 'profile', None)
            if profile and hasattr(profile, 'roles_storage'):
                roles_str = profile.roles_storage
                if roles_str:
                    try:
                        return json.loads(roles_str)
                    except (json.JSONDecodeError, TypeError):
                        return [roles_str] if roles_str else []
            # Check if there's a roles field (would require a migration)
            if hasattr(self, 'roles'):
                roles_attr = getattr(self, 'roles')
                if isinstance(roles_attr, str):
                    try:
                        return json.loads(roles_attr)
                    except (json.JSONDecodeError, TypeError):
                        return [roles_attr] if roles_attr else []
                elif isinstance(roles_attr, list):
                    return roles_attr
        return []
    except Exception:
        return []

def set_user_roles(self, roles):
    """Set user roles."""
    try:
        # Convert list to string if needed
        if isinstance(roles, list):
            roles_str = json.dumps(roles)
        else:
            roles_str = roles
        
        # Try to store in profile
        profile, created = self.profile if hasattr(self, 'profile') else (None, False)
        if not profile:
            profile = UserProfile.objects.get_or_create(user=self)[0]
        
        if hasattr(profile, 'roles_storage'):
            profile.roles_storage = roles_str
            profile.save(update_fields=['roles_storage'])
    except Exception as e:
        # Log error without exposing sensitive data
        logger.error(f"Error setting user roles for user {self.id}: {type(e).__name__}", exc_info=False)

# Monkey patch User model to add roles property
User.add_to_class('roles', user_roles)
User.add_to_class('set_roles', set_user_roles)


def get_encryption_key():
    """
    Get or generate encryption key for Fernet encryption.
    """
    if not hasattr(settings, 'GOOGLE_TOKEN_ENCRYPTION_KEY'):
        # Generate a key if not set (for development only)
        key = Fernet.generate_key()
        settings.GOOGLE_TOKEN_ENCRYPTION_KEY = key.decode()
    
    return settings.GOOGLE_TOKEN_ENCRYPTION_KEY.encode()


class UserProfile(models.Model):
    """
    Extended user profile for Google OAuth token management.
    
    Fields:
    - user: One-to-one relationship with User
    - google_refresh_token: Encrypted Google refresh token
    - last_refresh: Timestamp of last token refresh
    - google_user_id: Google user ID
    - tokens_rotated_at: Timestamp of last token rotation
    - roles_storage: JSON string storing user roles
    """
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    google_refresh_token = models.TextField(blank=True, null=True, help_text='Encrypted Google refresh token')
    last_refresh = models.DateTimeField(null=True, blank=True, help_text='Last time tokens were refreshed')
    google_user_id = models.CharField(max_length=255, blank=True, null=True, help_text='Google user ID')
    tokens_rotated_at = models.DateTimeField(null=True, blank=True, help_text='Last token rotation timestamp')
    google_picture_url = models.URLField(max_length=500, blank=True, null=True, help_text='Google profile picture URL')
    roles_storage = models.TextField(blank=True, null=True, default='[]', help_text='JSON string storing user roles')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_profile'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
    
    def get_encrypted_refresh_token(self):
        """
        Decrypt and return the Google refresh token.
        """
        if not self.google_refresh_token:
            return None
        
        try:
            encryption_key = get_encryption_key()
            f = Fernet(encryption_key)
            encrypted_token = base64.urlsafe_b64decode(self.google_refresh_token.encode())
            decrypted_token = f.decrypt(encrypted_token)
            return decrypted_token.decode()
        except Exception as e:
            # Log error without exposing token or sensitive data
            # Using exc_info=False to avoid logging local variables (decrypted_token) in traceback
            logger.error(f"Error decrypting Google refresh token for user {self.user.id}: {type(e).__name__}", exc_info=False)
            return None
    
    def set_encrypted_refresh_token(self, token):
        """
        Encrypt and store the Google refresh token.
        """
        try:
            encryption_key = get_encryption_key()
            f = Fernet(encryption_key)
            encrypted_token = f.encrypt(token.encode())
            self.google_refresh_token = base64.urlsafe_b64encode(encrypted_token).decode()
        except Exception as e:
            # Log error without exposing token or sensitive data
            # Using exc_info=False to avoid logging local variables (token, encrypted_token) in traceback
            logger.error(f"Error encrypting Google refresh token for user {self.user.id}: {type(e).__name__}", exc_info=False)
            raise
    
    def update_last_refresh(self):
        """
        Update the last refresh timestamp.
        """
        self.last_refresh = timezone.now()
        self.save(update_fields=['last_refresh'])
    
    def is_token_expired(self, expiration_hours=24):
        """
        Check if the refresh token needs rotation.
        
        Args:
            expiration_hours: Hours before token is considered expired
        
        Returns:
            bool: True if token is expired
        """
        if not self.last_refresh:
            return True
        
        expiration_time = self.last_refresh + timezone.timedelta(hours=expiration_hours)
        return timezone.now() > expiration_time
    
    def __str__(self):
        return f"{self.user.username} - Profile"


