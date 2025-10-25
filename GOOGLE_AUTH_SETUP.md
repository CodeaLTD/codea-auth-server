# Google OAuth Authentication Setup

This document explains how to set up and use Google OAuth authentication with the Codea Auth Server.

## Overview

The Google OAuth integration provides secure authentication using Google accounts. Users can sign in with their Google credentials and receive JWT tokens for API access.

## Setup Instructions

### 1. Google Cloud Console Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API and Google OAuth2 API
4. Go to "Credentials" in the API & Services section
5. Create OAuth 2.0 Client IDs
6. Set the authorized redirect URI to: `http://localhost:8000/api/auth/google/callback/`
7. Note down the Client ID and Client Secret

### 2. Django Settings Configuration

Update your `settings.py` file with your Google OAuth credentials:

```python
GOOGLE_OAUTH_CONFIG = {
    'CLIENT_ID': 'your-actual-google-client-id',
    'CLIENT_SECRET': 'your-actual-google-client-secret',
    'REDIRECT_URI': 'http://localhost:8000/api/auth/google/callback/',
    'SCOPE': 'openid email profile',
    'AUTH_URL': 'https://accounts.google.com/o/oauth2/v2/auth',
    'TOKEN_URL': 'https://oauth2.googleapis.com/token',
    'USER_INFO_URL': 'https://www.googleapis.com/oauth2/v2/userinfo',
}
```

### 3. Install Required Dependencies

The Google OAuth implementation uses the `requests` library, which should already be available. If not, install it:

```bash
pip install requests
```

## API Endpoints

### 1. Get Google OAuth URL
**GET** `/api/auth/google/url/`

Generates a Google OAuth authorization URL.

**Query Parameters:**
- `redirect_uri` (optional): Custom redirect URI
- `state` (optional): State parameter for CSRF protection

**Response:**
```json
{
    "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...",
    "state": "random_state_string"
}
```

### 2. Google OAuth Callback
**POST** `/api/auth/google/callback/`

Handles the Google OAuth callback and authenticates the user.

**Request Body:**
```json
{
    "code": "4/0AX4XfWh...",
    "state": "google_auth_1234567890",
    "redirect_uri": "http://localhost:8000/api/auth/google/callback/"
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "username": "user@gmail.com",
        "email": "user@gmail.com",
        "first_name": "John",
        "last_name": "Doe",
        "is_active": true,
        "date_joined": "2024-01-01T00:00:00Z"
    },
    "is_new_user": false,
    "google_id": "123456789",
    "picture": "https://lh3.googleusercontent.com/..."
}
```

### 3. Get Google OAuth Configuration
**GET** `/api/auth/google/config/`

Returns the Google OAuth configuration for frontend integration.

**Response:**
```json
{
    "client_id": "your-google-client-id",
    "redirect_uri": "http://localhost:8000/api/auth/google/callback/",
    "scope": "openid email profile",
    "auth_url": "https://accounts.google.com/o/oauth2/v2/auth"
}
```

### 4. Check Google OAuth Status
**GET** `/api/auth/google/status/`

Checks the Google OAuth service status and configuration.

**Response:**
```json
{
    "status": "active",
    "client_id_configured": true,
    "redirect_uri": "http://localhost:8000/api/auth/google/callback/",
    "google_services_accessible": true,
    "scope": "openid email profile"
}
```

## Frontend Integration

### 1. Redirect to Google OAuth

```javascript
// Get the Google OAuth URL
const response = await fetch('/api/auth/google/url/');
const data = await response.json();

// Redirect user to Google
window.location.href = data.auth_url;
```

### 2. Handle the Callback

```javascript
// Extract the authorization code from the URL
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

// Send the code to your backend
const response = await fetch('/api/auth/google/callback/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        code: code,
        state: state
    })
});

const authData = await response.json();

// Store the tokens
localStorage.setItem('access_token', authData.access);
localStorage.setItem('refresh_token', authData.refresh);
```

## Security Features

- **State Parameter**: CSRF protection using state parameter
- **Token Validation**: Validates Google access tokens
- **User Creation**: Automatically creates users on first Google login
- **JWT Integration**: Returns JWT tokens for API authentication
- **Comprehensive Logging**: All authentication events are logged
- **Error Handling**: Proper error responses for all failure scenarios

## User Management

- Users are automatically created on first Google login
- Email is used as the username
- User information is updated on subsequent logins
- Users can be managed through the standard user management endpoints

## Troubleshooting

### Common Issues

1. **"Google authentication failed"**
   - Check that your Client ID and Client Secret are correct
   - Verify the redirect URI matches exactly
   - Ensure Google APIs are enabled in Google Cloud Console

2. **"Failed to exchange authorization code"**
   - Check that the authorization code is valid and not expired
   - Verify the redirect URI matches the one used in the authorization request

3. **"Google services not accessible"**
   - Check your internet connection
   - Verify Google APIs are not blocked by firewall

### Logs

Check the following log files for detailed information:
- `logs/auth.log` - Authentication events
- `logs/error.log` - Error messages
- `logs/info.log` - General information

## Testing

You can test the Google OAuth integration using:

1. **Status Check**: `GET /api/auth/google/status/`
2. **Configuration**: `GET /api/auth/google/config/`
3. **URL Generation**: `GET /api/auth/google/url/`
4. **Full Flow**: Use a frontend application to test the complete OAuth flow
