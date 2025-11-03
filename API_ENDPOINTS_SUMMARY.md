# Codea Auth Server - Complete API Endpoints Summary

This document provides a comprehensive summary of all available API endpoints in the Codea Auth Server.

**Base URL:** All API endpoints are prefixed with `/api/` (except documentation and admin)

---

## 📊 Quick Statistics

- **Total Active Endpoints:** 36
- **Total Documentation Endpoints:** 3
- **Total System Endpoints:** 2 (Admin + Homepage)

---

## 🔐 Authentication Endpoints

### Google OAuth Authentication (6 endpoints)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/auth/google/login/` | Redirect to Google OAuth login page | No |
| `GET/POST` | `/api/auth/google/auth/` | Google OAuth callback handler | No |
| `POST` | `/api/auth/google/verify/` | Verify Google authentication token | No |
| `GET` | `/api/auth/google/me/` | Get current user info (Google auth) | Yes |
| `POST` | `/api/auth/google/logout/` | Logout (Google auth) | Yes |
| `POST` | `/api/auth/google/refresh/` | Refresh Google authentication token | No |

**Swagger Tags:** `Google Login`, `Google Auth Callback`, `Google Verify`, `Google Me`, `Google Logout`, `Google Refresh`

---

### JWT Authentication (6 endpoints) - ⭐ Recommended

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/auth/jwt/login/` | Login with username/password (returns JWT) | No |
| `POST` | `/api/auth/jwt/refresh/` | Refresh JWT access token | No |
| `POST` | `/api/auth/jwt/verify/` | Verify JWT token validity | No |
| `GET` | `/api/auth/jwt/me/` | Get current user info (Who am I?) | Yes |
| `POST` | `/api/auth/jwt/logout/` | Logout (invalidate JWT) | No |
| `POST` | `/api/auth/jwt/register/` | Register new user account | No |

**Swagger Tags:** `JWT Login`, `JWT Refresh`, `JWT Verify`, `JWT Me`, `JWT Logout`, `User Registration`

---

### OAuth 2.0 Authorization Server (3 endpoints) - 🆕

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET/POST` | `/api/oauth2/authorize/` | OAuth 2.0 authorization endpoint (browser-facing) | No |
| `POST` | `/api/oauth2/token/` | OAuth 2.0 token endpoint (server-to-server) | No* |
| `GET/POST` | `/api/oauth2/userinfo/` | OAuth 2.0 UserInfo endpoint (resource API) | Yes (Bearer) |

*Token endpoint requires client authentication (client_id + client_secret)

**Swagger Tags:** `OAuth 2.0 Authorize`, `OAuth 2.0 Token`, `OAuth 2.0 UserInfo`

**Grant Types Supported:**
- `authorization_code` - Standard OAuth 2.0 flow
- `refresh_token` - Token refresh
- `password` - Resource Owner Password Credentials
- `client_credentials` - Machine-to-machine authentication

---

## 👤 User Management Endpoints (9 endpoints)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/users/profile/` | Get current user's profile | Yes |
| `GET` | `/api/users/profile/by-username/` | Get user profile by username (Admin only) | Yes (Admin) |
| `PUT/PATCH` | `/api/users/profile/update/` | Update current user's profile | Yes |
| `DELETE` | `/api/users/profile/delete/` | Delete current user's profile | Yes |
| `GET` | `/api/users/list/` | List all users (Admin only) | Yes (Admin) |
| `POST` | `/api/users/roles/check/` | Check if user has a specific role | Yes |
| `POST` | `/api/users/roles/check-any/` | Check if user has any of specified roles | Yes |
| `POST` | `/api/users/roles/check-all/` | Check if user has all specified roles | Yes |
| `GET` | `/api/users/roles/` | Get all roles for current user | Yes |

**Swagger Tags:** `User Profile`, `User Profile by Username`, `Update Profile`, `Delete Profile`, `Check Role`, `Check Any Role`, `Check All Roles`, `Get User Roles`

---

## 🏥 Health & Monitoring Endpoints (4 endpoints)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/health/` | Basic health check | No |
| `GET` | `/api/health/detailed/` | Detailed health check with system metrics | No |
| `GET` | `/api/health/metrics/` | System metrics and performance data | No |
| `GET` | `/api/health/status/` | Application status information | No |

**Swagger Tags:** `Health Check`, `Detailed Health`, `System Metrics`, `Application Status`

---

## ⚙️ API Management Endpoints (1 endpoint)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/limiter/` | API rate limiting information/configuration | No |

**Swagger Tag:** `API Rate Limiter`

---

## 📚 Documentation Endpoints (3 endpoints)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/schema/` | OpenAPI schema (JSON) | No |
| `GET` | `/docs/` | Swagger UI documentation | No |
| `GET` | `/redoc/` | ReDoc documentation | No |

**Note:** These endpoints are NOT prefixed with `/api/`

---

## 🛠️ System Endpoints (2 endpoints)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/admin/` | Django admin panel | Yes (Admin) |
| `GET` | `/` | Homepage (welcome message) | No |

---

## 📋 Complete Endpoint List by Category

### Authentication (15 endpoints)
1. `GET /api/auth/google/login/`
2. `GET/POST /api/auth/google/auth/`
3. `POST /api/auth/google/verify/`
4. `GET /api/auth/google/me/`
5. `POST /api/auth/google/logout/`
6. `POST /api/auth/google/refresh/`
7. `POST /api/auth/jwt/login/`
8. `POST /api/auth/jwt/refresh/`
9. `POST /api/auth/jwt/verify/`
10. `GET /api/auth/jwt/me/`
11. `POST /api/auth/jwt/logout/`
12. `POST /api/auth/jwt/register/`
13. `GET/POST /api/oauth2/authorize/`
14. `POST /api/oauth2/token/`
15. `GET/POST /api/oauth2/userinfo/`

### User Management (9 endpoints)
16. `GET /api/users/profile/`
17. `GET /api/users/profile/by-username/`
18. `PUT/PATCH /api/users/profile/update/`
19. `DELETE /api/users/profile/delete/`
20. `GET /api/users/list/`
21. `POST /api/users/roles/check/`
22. `POST /api/users/roles/check-any/`
23. `POST /api/users/roles/check-all/`
24. `GET /api/users/roles/`

### Health & Monitoring (4 endpoints)
25. `GET /api/health/`
26. `GET /api/health/detailed/`
27. `GET /api/health/metrics/`
28. `GET /api/health/status/`

### API Management (1 endpoint)
29. `GET /api/limiter/`

### Documentation (3 endpoints)
30. `GET /schema/`
31. `GET /docs/`
32. `GET /redoc/`

### System (2 endpoints)
33. `GET /admin/`
34. `GET /`

---

## 🔑 Authentication Methods

The server supports multiple authentication methods:

1. **JWT Bearer Tokens** (Recommended)
   - Use `Authorization: Bearer <token>` header
   - Obtain via `/api/auth/jwt/login/`
   - Refresh via `/api/auth/jwt/refresh/`

2. **OAuth 2.0 Access Tokens**
   - Use `Authorization: Bearer <token>` header
   - Obtain via OAuth 2.0 flow (`/api/oauth2/authorize/` → `/api/oauth2/token/`)

3. **Session Authentication**
   - Django session-based authentication
   - Used for Google OAuth flow

---

## 📝 Notes

- All endpoints return JSON responses (except redirects and HTML documentation)
- Error responses follow standard HTTP status codes
- All endpoints are documented in Swagger/OpenAPI format
- Each endpoint has its own section in Swagger UI
- Health endpoints are public (no authentication required)
- Most endpoints require authentication unless specified

---

## 🔗 Quick Links

- **Swagger UI:** `/docs/`
- **ReDoc:** `/redoc/`
- **OpenAPI Schema:** `/schema/`
- **Health Check:** `/api/health/`

---

## 📖 Additional Documentation

- **OAuth 2.0 Setup Guide:** See `codea_auth_server/api/OAUTH2_SETUP.md`
- **API Documentation:** Available via Swagger UI at `/docs/`

---

**Last Updated:** Generated from current URL configuration  
**Total Endpoints:** 36 active API endpoints + 5 system/documentation endpoints = **41 total endpoints**

