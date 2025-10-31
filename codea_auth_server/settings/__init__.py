"""
Django settings module.

This module automatically loads the appropriate settings based on the ENVIRONMENT
environment variable:
- 'production' -> loads settings.prod
- anything else -> loads settings.dev
"""

import os

ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development').lower()

if ENVIRONMENT == 'production':
    from .prod import *
else:
    from .dev import *


