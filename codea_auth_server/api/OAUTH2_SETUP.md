# OAuth 2.0 Setup Guide

This document explains how to configure and use the OAuth 2.0 endpoints in the Codea Auth Server.

## Overview

The server implements three standard OAuth 2.0 endpoints:

1. **`/api/oauth2/authorize/`** - Authorization endpoint (browser-facing)
2. **`/api/oauth2/token/`** - Token endpoint (server-to-server)
3. **`/api/oauth2/userinfo/`** - UserInfo endpoint (resource API)

## Configuration

### 1. Add OAuth 2.0 Configuration to Settings

Add the following to your Django settings file (e.g., `settings/base.py`):

```python
# OAuth 2.0 Configuration
OAUTH2_CONFIG = {
    # Token expiry times (in seconds)
    'AUTHORIZATION_CODE_EXPIRY': 600,      # 10 minutes
    'ACCESS_TOKEN_EXPIRY': 3600,           # 1 hour
    'REFRESH_TOKEN_EXPIRY': 2592000,       # 30 days
    
    # Registered OAuth 2.0 clients
    'REGISTERED_CLIENTS': {
        'my_web_app': {
            'client_secret': 'your-secure-client-secret-here',
            'redirect_uris': [
                'http://localhost:3000/callback',
                'https://myapp.com/auth/callback'
            ],
            'grant_types': ['authorization_code', 'refresh_token'],
            'name': 'My Web Application'
        },
        'my_mobile_app': {
            'client_secret': 'another-secure-secret',
            'redirect_uris': [
                'myapp://callback',
                'http://localhost:8081/callback'
            ],
            'grant_types': ['authorization_code', 'refresh_token', 'password'],
            'name': 'My Mobile App'
        },
        'trusted_server': {
            'client_secret': 'server-to-server-secret',
            'redirect_uris': ['http://localhost:8080/callback'],
            'grant_types': ['client_credentials'],
            'name': 'Backend Service'
        }
    }
}
```

### 2. Generate Secure Client Secrets

Use Python to generate secure random secrets:

```python
import secrets
print(secrets.token_urlsafe(32))
```

## Grant Types

### 1. Authorization Code Flow (Recommended for Web Apps)

This is the most secure OAuth 2.0 flow for web applications.

**Step 1: Redirect user to authorization endpoint**

```
GET /api/oauth2/authorize/?
    response_type=code&
    client_id=my_web_app&
    redirect_uri=http://localhost:3000/callback&
    scope=read%20write&
    state=random_state_value
```

**Step 2: User authenticates (POST credentials)**

```
POST /api/oauth2/authorize/
Content-Type: application/x-www-form-urlencoded

response_type=code&
client_id=my_web_app&
redirect_uri=http://localhost:3000/callback&
username=john_doe&
password=secret_password&
state=random_state_value
```

**Step 3: Server redirects back with authorization code**

```
HTTP/1.1 302 Found
Location: http://localhost:3000/callback?code=abc123xyz&state=random_state_value
```

**Step 4: Exchange authorization code for access token**

```
POST /api/oauth2/token/
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=abc123xyz&
redirect_uri=http://localhost:3000/callback&
client_id=my_web_app&
client_secret=your-secure-client-secret-here
```

**Response:**

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_xyz...",
  "scope": "read write"
}
```

### 2. Refresh Token Grant

When the access token expires, use the refresh token to get a new one:

```
POST /api/oauth2/token/
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=refresh_token_xyz...&
client_id=my_web_app&
client_secret=your-secure-client-secret-here
```

### 3. Password Grant (Trusted Clients Only)

For trusted first-party applications (mobile apps):

```
POST /api/oauth2/token/
Content-Type: application/x-www-form-urlencoded

grant_type=password&
username=john_doe&
password=secret_password&
scope=read%20write&
client_id=my_mobile_app&
client_secret=another-secure-secret
```

### 4. Client Credentials Grant (Machine-to-Machine)

For server-to-server communication:

```
POST /api/oauth2/token/
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
scope=read&
client_id=trusted_server&
client_secret=server-to-server-secret
```

## Using the Access Token

### Get User Information

Once you have an access token, use it to access protected resources:

```
GET /api/oauth2/userinfo/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

**Response:**

```json
{
  "sub": "12345",
  "email": "john@example.com",
  "name": "John Doe",
  "preferred_username": "john_doe",
  "given_name": "John",
  "family_name": "Doe",
  "email_verified": true,
  "roles": ["user", "admin"],
  "updated_at": 1640995200
}
```

### Access Other Protected Endpoints

Use the Bearer token with any protected endpoint:

```
GET /api/users/profile/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

## Security Best Practices

### 1. Use HTTPS in Production

Always use HTTPS for OAuth 2.0 endpoints in production to prevent token interception.

### 2. Store Client Secrets Securely

- Never commit client secrets to version control
- Use environment variables or secret management services
- Rotate secrets regularly

### 3. Validate Redirect URIs

The server validates redirect URIs against registered values to prevent authorization code interception.

### 4. Use State Parameter

Always use the `state` parameter for CSRF protection in the authorization code flow.

### 5. Token Storage

**Client-side (Browser):**
- Store access tokens in memory (JavaScript variables)
- Store refresh tokens in httpOnly cookies or secure storage

**Mobile Apps:**
- Use secure storage (Keychain on iOS, KeyStore on Android)

**Server-side:**
- Store tokens securely in database or secure cache

### 6. Token Expiry

- Access tokens: Short-lived (1 hour default)
- Refresh tokens: Long-lived (30 days default)
- Authorization codes: Very short-lived (10 minutes default)

## Example Client Implementation (JavaScript)

```javascript
// Step 1: Redirect to authorization endpoint
function initiateOAuth() {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'my_web_app',
    redirect_uri: 'http://localhost:3000/callback',
    scope: 'read write',
    state: generateRandomState() // Store this in sessionStorage
  });
  
  window.location.href = `http://localhost:8000/api/oauth2/authorize/?${params}`;
}

// Step 2: Handle callback
async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  
  // Verify state matches what you stored
  if (state !== sessionStorage.getItem('oauth_state')) {
    throw new Error('Invalid state parameter');
  }
  
  // Exchange code for tokens
  const response = await fetch('http://localhost:8000/api/oauth2/token/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: 'http://localhost:3000/callback',
      client_id: 'my_web_app',
      client_secret: 'your-secure-client-secret-here'
    })
  });
  
  const tokens = await response.json();
  // Store tokens securely
  sessionStorage.setItem('access_token', tokens.access_token);
  sessionStorage.setItem('refresh_token', tokens.refresh_token);
}

// Step 3: Use access token
async function getUserInfo() {
  const accessToken = sessionStorage.getItem('access_token');
  
  const response = await fetch('http://localhost:8000/api/oauth2/userinfo/', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  return await response.json();
}

// Helper: Generate random state
function generateRandomState() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const state = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  sessionStorage.setItem('oauth_state', state);
  return state;
}
```

## Testing with cURL

### Authorization Code Flow

```bash
# Step 1: Get authorization code (in browser or with credentials)
curl -X POST "http://localhost:8000/api/oauth2/authorize/" \
  -d "response_type=code" \
  -d "client_id=my_web_app" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "username=john_doe" \
  -d "password=secret_password" \
  -d "scope=read write" \
  -d "state=test_state"

# Step 2: Exchange code for token
curl -X POST "http://localhost:8000/api/oauth2/token/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=my_web_app" \
  -d "client_secret=your-secure-client-secret-here"

# Step 3: Get user info
curl -X GET "http://localhost:8000/api/oauth2/userinfo/" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Password Grant

```bash
curl -X POST "http://localhost:8000/api/oauth2/token/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "username=john_doe" \
  -d "password=secret_password" \
  -d "client_id=my_mobile_app" \
  -d "client_secret=another-secure-secret"
```

## Troubleshooting

### "invalid_client" Error

- Check that client_id and client_secret are correct
- Verify client is registered in OAUTH2_CONFIG

### "invalid_redirect_uri" Error

- Ensure redirect_uri exactly matches one registered for the client
- Check for trailing slashes, protocol (http vs https), etc.

### "invalid_grant" Error

- Authorization code may have expired (10 minute default)
- Code may have already been used
- Refresh token may be invalid or expired

### "access_denied" Error

- Check username and password are correct
- User account may be inactive

## Production Considerations

### 1. Use Database for Storage

Replace in-memory dictionaries with database models:

```python
# models.py
from django.db import models

class OAuth2Client(models.Model):
    client_id = models.CharField(max_length=255, unique=True)
    client_secret = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    redirect_uris = models.JSONField()
    grant_types = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

class OAuth2AuthorizationCode(models.Model):
    code = models.CharField(max_length=255, unique=True)
    client = models.ForeignKey(OAuth2Client, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    redirect_uri = models.URLField()
    scope = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)
```

### 2. Implement Consent Screen

Add a consent screen where users explicitly grant permissions to third-party applications.

### 3. Add Scope Validation

Implement fine-grained permission scopes (e.g., `read:profile`, `write:posts`).

### 4. Rate Limiting

Implement rate limiting on token endpoint to prevent brute force attacks.

### 5. Audit Logging

Log all token issuances and revocations for security auditing.

## References

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

