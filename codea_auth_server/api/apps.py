"""
Django app configuration for the API app.
"""
from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'codea_auth_server.api'
    
    def ready(self):
        """
        App ready callback.
        Using standard DRF authentication classes.
        """
        import logging
        logger = logging.getLogger(__name__)
        logger.info("="*50)
        logger.info("ApiConfig.ready() called - Using standard authentication")
        logger.info("="*50)

