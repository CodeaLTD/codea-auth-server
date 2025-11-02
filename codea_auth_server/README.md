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

## CORS Configuration

CORS (Cross-Origin Resource Sharing) is configured to allow requests from common development servers:

- `http://localhost:3000` (React)
- `http://127.0.0.1:3000`
- `http://localhost:8080` (Vue)
- `http://127.0.0.1:8080`
- `http://localhost:4200` (Angular)
- `http://127.0.0.1:4200`

In development mode (`DEBUG=True`), all origins are allowed. In production, only the specified origins are allowed.

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

### Development vs Production

- **Development**: Logs are written to both console and files
- **Production**: Logs are written to files only (console logging disabled)

## Production Considerations

1. **Security**: Disable `CORS_ALLOW_ALL_ORIGINS` in production
2. **HTTPS**: Use HTTPS in production for secure API communication
3. **Authentication**: Implement proper JWT token management
4. **Rate Limiting**: Consider adding rate limiting for API endpoints
5. **Monitoring**: Set up proper logging and monitoring for production use

### Log Rotation

For production deployments, consider setting up log rotation to prevent log files from growing too large. You can use tools like `logrotate` on Linux systems. --NOT DONE

### Security Considerations

- Log files may contain sensitive information - ensure proper file permissions ---NOT DONE
- Consider encrypting log files in production --NOT DONE
- Regularly review and archive old log files --NOT DONE
- Be careful not to log passwords or other sensitive data --CHECK


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

### 2. Run the Server from PyCharm

You have several options:

#### **Option A: Use PyCharm Terminal (Easiest)**
1. Click the **Terminal** tab at the bottom of PyCharm
2. Run:
   ```bash
   python manage.py runserver 127.0.0.1:8000
   ```

#### **Option B: Configure a Run Configuration**
1. Go to **Run** → **Edit Configurations...**
2. Click **+** button
3. Select **Python**
4. Configure:
   - **Name**: `Codea Auth Server`
   - **Script path**: `C:\Users\Maria Vlahova\Desktop\workspace\codea\codea-auth-server\manage.py`
   - **Parameters**: `runserver 127.0.0.1:8000`
   - **Python interpreter**: `venv\Scripts\python.exe`
   - **Working directory**: `C:\Users\Maria Vlahova\Desktop\workspace\codea\codea-auth-server`
5. Click **OK** and run with ▶️

## 🌐 API Endpoints

Once your server is running at `http://localhost:8000`:

### Documentation
- **Swagger UI**: http://localhost:8000/docs/
- **ReDoc**: http://localhost:8000/redoc/
- **OpenAPI Schema**: http://localhost:8000/schema/

## GOOGLE AUTH

- manual testing - GOOGLE_AUTH_MANUAL_TEST.md

## Environment Variables

The application uses environment variables to configure settings for different environments (development and production). Settings are automatically loaded from `codea_auth_server/settings/dev.py` for development and `codea_auth_server/settings/prod.py` for production based on the `ENVIRONMENT` variable.

### Development Environment Variables

These are optional in development mode as they have default values:

```bash
# Environment type (defaults to 'development' if not set)
ENVIRONMENT=development

# Django secret key (has insecure default for development only)
DJANGO_SECRET_KEY=your-secret-key-here

# Allowed hosts (comma-separated, optional)
ALLOWED_HOSTS=localhost,127.0.0.1

# Google OAuth Configuration (optional - has defaults for development)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/auth/google/auth/

# Google Token Encryption Key (auto-generated if not set)
GOOGLE_TOKEN_ENCRYPTION_KEY=your-encryption-key-here
```

**Note**: In development, if `GOOGLE_TOKEN_ENCRYPTION_KEY` is not set, a temporary key will be auto-generated (not suitable for production).

### Production Environment Variables

These are **REQUIRED** for production deployment:

```bash
# Environment type - MUST be set to 'production'
ENVIRONMENT=production

# Django secret key - REQUIRED
# Generate with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
DJANGO_SECRET_KEY=your-secure-production-secret-key

# Allowed hosts (comma-separated) - RECOMMENDED
ALLOWED_HOSTS=yourdomain.com,api.yourdomain.com

# Database Configuration
DB_NAME=codea_auth                    # Optional, defaults to 'codea_auth'
DB_USER=codea_user                     # Optional, defaults to 'codea_user'
DB_PASSWORD=your-secure-db-password    # REQUIRED
DB_HOST=localhost                      # Optional, defaults to 'localhost'
DB_PORT=5432                           # Optional, defaults to '5432'

# CORS Configuration - RECOMMENDED
# Comma-separated list of allowed origins
CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# Google OAuth Configuration - REQUIRED
GOOGLE_CLIENT_ID=your-production-google-client-id
GOOGLE_CLIENT_SECRET=your-production-google-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/api/auth/google/auth/

# Google Token Encryption Key - REQUIRED
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
GOOGLE_TOKEN_ENCRYPTION_KEY=your-production-encryption-key

# API Base URL for Swagger Documentation - Optional
API_BASE_URL=https://api.yourdomain.com

# Security Settings - Optional (all default to 'False', set to 'true' if using HTTPS)
SECURE_SSL_REDIRECT=true                # Redirect HTTP to HTTPS
SESSION_COOKIE_SECURE=true              # Send cookies only over HTTPS
CSRF_COOKIE_SECURE=true                 # Send CSRF cookies only over HTTPS
```

### Setting Environment Variables

#### Linux/macOS:
```bash
export ENVIRONMENT=production
export DJANGO_SECRET_KEY=your-secret-key
export DB_PASSWORD=secure-password
export ALLOWED_HOSTS=yourdomain.com
# ... set other variables
```

#### Windows (PowerShell):
```powershell
$env:ENVIRONMENT="production"
$env:DJANGO_SECRET_KEY="your-secret-key"
$env:DB_PASSWORD="secure-password"
$env:ALLOWED_HOSTS="yourdomain.com"
# ... set other variables
```

#### Using .env file:
Create a `.env` file in the project root (make sure to add it to `.gitignore`):

```env
ENVIRONMENT=production
DJANGO_SECRET_KEY=your-secret-key
DB_PASSWORD=secure-password
ALLOWED_HOSTS=yourdomain.com
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/api/auth/google/auth/
GOOGLE_TOKEN_ENCRYPTION_KEY=your-encryption-key
CORS_ALLOWED_ORIGINS=https://yourdomain.com
```

Then load it before running (requires `python-dotenv` package):
```bash
python -m pip install python-dotenv
# Or add python-dotenv to requirements.txt
```

## Running Docker

### Development:
```bash
docker-compose up -d
```

### Production:
```bash
# Set required environment variables
export ENVIRONMENT=production
export DJANGO_SECRET_KEY=your-secret-key
export DB_PASSWORD=secure-password
export ALLOWED_HOSTS=yourdomain.com
export GOOGLE_CLIENT_ID=your-google-client-id
export GOOGLE_CLIENT_SECRET=your-google-client-secret
export GOOGLE_REDIRECT_URI=https://yourdomain.com/api/auth/google/auth/
export GOOGLE_TOKEN_ENCRYPTION_KEY=your-encryption-key
export CORS_ALLOWED_ORIGINS=https://yourdomain.com

# Start containers
docker-compose up -d
```

Alternatively, you can use a `.env` file with Docker Compose (it automatically loads `.env` files).

###Docker image is built directly by Render when we deployed in the moment . we won`t use additional registry
###Render build command is Docker Entrypoint + cmd from dockerfile


### FOR DB
-Avoid using the Render database superuser credentials for your Django app — use the newly created one instead.
-Always use SSL mode = require when connecting externally.
-Never expose passwords in code or logs.