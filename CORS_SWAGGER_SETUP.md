# CORS and Swagger Setup Guide

This guide explains how to set up and use CORS and Swagger documentation for the Codea Auth Server.

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Run database migrations:
```bash
python manage.py migrate
```

3. Create a superuser (optional):
```bash
python manage.py createsuperuser
```

4. Start the development server:
```bash
python manage.py runserver
```

## CORS Configuration

CORS (Cross-Origin Resource Sharing) is configured to allow requests from common development servers:

- `http://localhost:3000` (React)
- `http://127.0.0.1:3000`
- `http://localhost:8080` (Vue)
- `http://127.0.0.1:8080`
- `http://localhost:4200` (Angular)
- `http://127.0.0.1:4200`

In development mode (`DEBUG=True`), all origins are allowed. In production, only the specified origins are allowed.

## API Documentation

The API documentation is available at the following endpoints:

### Swagger UI
- **URL**: `http://localhost:8000/api/docs/swagger/`
- **Description**: Interactive API documentation with a user-friendly interface
- **Features**: 
  - Try out API endpoints directly
  - View request/response examples
  - Authentication support

### ReDoc
- **URL**: `http://localhost:8000/api/docs/redoc/`
- **Description**: Clean, responsive API documentation
- **Features**:
  - Better for reading and understanding API structure
  - Mobile-friendly interface

### OpenAPI Schema
- **URL**: `http://localhost:8000/api/docs/schema/`
- **Description**: Raw OpenAPI 3.0 schema in JSON format
- **Use case**: For generating client SDKs or importing into other tools

### API Information
- **URL**: `http://localhost:8000/api/docs/`
- **Description**: Basic API information and endpoint overview

## Available API Endpoints

### Authentication
- `POST /api/auth/login/` - User login
- `POST /api/auth/logout/` - User logout
- `POST /api/auth/refresh-token/` - Refresh JWT token (placeholder)
- `POST /api/auth/change-password/` - Change user password

### User Management
- `POST /api/users/register/` - User registration
- `GET /api/users/profile/` - Get user profile
- `PUT /api/users/profile/update/` - Update user profile
- `GET /api/users/list/` - List all users (admin only)

### Health & Monitoring
- `GET /api/health/` - Basic health check
- `GET /api/health/detailed/` - Detailed health check with metrics
- `GET /api/health/metrics/` - System metrics
- `GET /api/health/status/` - Application status

## Testing the API

### Using Swagger UI
1. Navigate to `http://localhost:8000/api/docs/swagger/`
2. Click on any endpoint to expand it
3. Click "Try it out" to test the endpoint
4. Fill in the required parameters
5. Click "Execute" to send the request

### Using curl
```bash
# Health check
curl http://localhost:8000/api/health/

# User registration
curl -X POST http://localhost:8000/api/users/register/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&email=test@example.com&password=testpass123"

# User login
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass123"
```

## Configuration

### CORS Settings
To modify CORS settings, edit `codea_auth_server/settings.py`:

```python
# Add more allowed origins
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "https://yourdomain.com",  # Add your production domain
]

# Allow credentials (cookies, authorization headers)
CORS_ALLOW_CREDENTIALS = True
```

### Swagger Settings
To customize Swagger documentation, modify the `SPECTACULAR_SETTINGS` in `settings.py`:

```python
SPECTACULAR_SETTINGS = {
    'TITLE': 'Your API Title',
    'DESCRIPTION': 'Your API Description',
    'VERSION': '1.0.0',
    # ... other settings
}
```

## Troubleshooting

### Common Issues

1. **Import errors**: Make sure all dependencies are installed:
   ```bash
   pip install -r requirements.txt
   ```

2. **CORS errors**: Check that your frontend URL is in the `CORS_ALLOWED_ORIGINS` list

3. **Swagger not loading**: Ensure `drf_spectacular` is in `INSTALLED_APPS` and `MIDDLEWARE`

4. **Authentication issues**: Make sure you're logged in before accessing protected endpoints

### Development Tips

- Use the Swagger UI for testing API endpoints during development
- Check the browser's developer console for CORS errors
- Monitor the Django logs for detailed error information
- Use the health check endpoints to verify system status

## Production Considerations

1. **Security**: Disable `CORS_ALLOW_ALL_ORIGINS` in production
2. **HTTPS**: Use HTTPS in production for secure API communication
3. **Authentication**: Implement proper JWT token management
4. **Rate Limiting**: Consider adding rate limiting for API endpoints
5. **Monitoring**: Set up proper logging and monitoring for production use
