# codea-auth-server

The codea-auth-server is an internal authentication server developed by Codea, a company known for its creative coding tools. This server facilitates secure user authentication and authorization for Codea's applications and services.

Swagger UI: http://localhost:8000/docs/ 
ReDoc: http://localhost:8000/redoc/
OpenAPI Schema: http://localhost:8000/schema/
## Logging Configuration

This project includes comprehensive logging configuration to help with debugging, monitoring, and security auditing.

### Log Files

The logging system creates several log files in the `logs/` directory:

- **`debug.log`** - Detailed debug information including database queries
- **`info.log`** - General application information and events
- **`error.log`** - Error messages and exceptions
- **`auth.log`** - Authentication and security-related events

### Log Levels

- **DEBUG** - Detailed information for diagnosing problems
- **INFO** - General information about application flow
- **WARNING** - Something unexpected happened but the application is still working
- **ERROR** - A serious problem occurred
- **CRITICAL** - A very serious error occurred

### Using Logging in Your Code

#### Basic Logging

```python
import logging

# Get a logger for your module
logger = logging.getLogger('codea_auth_server')

# Log messages
logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message")
logger.critical("Critical message")
```

#### Authentication Logging

```python
from codea_auth_server.logging_utils import log_auth_event, log_security_event

# Log successful login
log_auth_event('login_success', user_id='123', ip_address='192.168.1.1')

# Log security event
log_security_event('failed_login_attempt', 'WARNING', 'Invalid credentials')
```

#### Request Logging

```python
from codea_auth_server.logging_utils import log_request_info

# Log request information
log_request_info(request, response, processing_time=0.123)
```

### Example API Endpoints

The project includes example endpoints that demonstrate logging usage:

- `POST /api/auth/login/` - User login with comprehensive logging
- `POST /api/auth/logout/` - User logout with logging
- `GET /api/health/` - Health check with logging

### Development vs Production

- **Development**: Logs are written to both console and files
- **Production**: Logs are written to files only (console logging disabled)

### Log Rotation

For production deployments, consider setting up log rotation to prevent log files from growing too large. You can use tools like `logrotate` on Linux systems.

### Security Considerations

- Log files may contain sensitive information - ensure proper file permissions
- Consider encrypting log files in production
- Regularly review and archive old log files
- Be careful not to log passwords or other sensitive data

## Getting Started

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run migrations:
   ```bash
   python manage.py migrate
   ```

3. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```

4. Start the development server:
   ```bash
   python manage.py runserver
   ```

5. Check the logs directory for log files:
   ```bash
   ls logs/
   ```
