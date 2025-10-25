"""
API package for the Codea Auth Server.

This package contains all API views organized by functionality:
- auth_views: Authentication endpoints (JWT and legacy)
- user_views: User management and role checking endpoints  
- health_views: Health and monitoring endpoints
- docs_views: API documentation endpoints
- jwt_utils: JWT utility classes and functions
- role_utils: Role checking utility functions

Note: Views are imported directly in urls.py to avoid circular import issues
during Django app loading.
"""
