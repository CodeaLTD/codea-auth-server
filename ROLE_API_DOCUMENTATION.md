# Role Checking API Documentation

This document describes the role checking API endpoints for the Codea Auth Server. These endpoints allow you to check if a user has specific roles and manage role-based access control.

## Overview

The role checking system provides several endpoints to:
- Check if a user has a specific role
- Check if a user has any of multiple roles
- Check if a user has all of multiple roles
- Get all roles for a user

All endpoints require JWT authentication.

## Authentication

All role checking endpoints require a valid JWT token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

## API Endpoints

### 1. Check Single Role

**Endpoint:** `POST /api/users/roles/check/`

**Description:** Check if the current user has a specific role.

**Request Body:**
```json
{
    "role": "admin"
}
```

**Response:**
```json
{
    "has_role": true,
    "role": "admin",
    "user_roles": ["admin", "user"],
    "user_id": 1,
    "username": "john_doe"
}
```

**Example Usage:**
```bash
curl -X POST "http://localhost:8000/api/users/roles/check/" \
  -H "Authorization: Bearer <your_jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

### 2. Check Any Role

**Endpoint:** `POST /api/users/roles/check-any/`

**Description:** Check if the current user has any of the specified roles.

**Request Body:**
```json
{
    "roles": ["admin", "moderator", "editor"]
}
```

**Response:**
```json
{
    "has_any_role": true,
    "checked_roles": ["admin", "moderator", "editor"],
    "user_roles": ["admin", "user"],
    "user_id": 1,
    "username": "john_doe"
}
```

**Example Usage:**
```bash
curl -X POST "http://localhost:8000/api/users/roles/check-any/" \
  -H "Authorization: Bearer <your_jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{"roles": ["admin", "moderator"]}'
```

### 3. Check All Roles

**Endpoint:** `POST /api/users/roles/check-all/`

**Description:** Check if the current user has all of the specified roles.

**Request Body:**
```json
{
    "roles": ["admin", "moderator"]
}
```

**Response:**
```json
{
    "has_all_roles": false,
    "checked_roles": ["admin", "moderator"],
    "user_roles": ["admin", "user"],
    "user_id": 1,
    "username": "john_doe"
}
```

**Example Usage:**
```bash
curl -X POST "http://localhost:8000/api/users/roles/check-all/" \
  -H "Authorization: Bearer <your_jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{"roles": ["admin", "moderator"]}'
```

### 4. Get User Roles

**Endpoint:** `GET /api/users/roles/`

**Description:** Get all roles for the current user.

**Response:**
```json
{
    "user_roles": ["admin", "user"],
    "user_id": 1,
    "username": "john_doe"
}
```

**Example Usage:**
```bash
curl -X GET "http://localhost:8000/api/users/roles/" \
  -H "Authorization: Bearer <your_jwt_token>"
```

## Error Responses

### 400 Bad Request
```json
{
    "error": "Role parameter is required"
}
```

### 401 Unauthorized
```json
{
    "error": "Authentication required"
}
```

### 403 Forbidden
```json
{
    "error": "Role required: admin",
    "required_role": "admin",
    "user_roles": ["user"]
}
```

### 500 Internal Server Error
```json
{
    "error": "Internal server error"
}
```

## Role Management

### Setting User Roles

Roles are stored in the user's `roles` field. You can set roles during user registration or update them via the profile update endpoint.

**During Registration:**
```json
{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "securepassword",
    "first_name": "John",
    "last_name": "Doe",
    "roles": ["admin", "user"]
}
```

**Updating Roles:**
```json
{
    "roles": ["admin", "moderator", "user"]
}
```

### Role Format

Roles can be stored as:
- A JSON string: `'["admin", "user"]'`
- A list: `["admin", "user"]`
- A single string: `"admin"` (will be converted to `["admin"]`)

## Using Role Decorators

You can also use role decorators in your Django views for server-side role checking:

```python
from .role_utils import role_required, any_role_required, all_roles_required

@role_required('admin')
def admin_only_view(request):
    # This view requires 'admin' role
    pass

@any_role_required(['admin', 'moderator'])
def moderator_view(request):
    # This view requires either 'admin' or 'moderator' role
    pass

@all_roles_required(['admin', 'superuser'])
def super_admin_view(request):
    # This view requires both 'admin' and 'superuser' roles
    pass
```

## Frontend Integration

### JavaScript Example

```javascript
// Check if user has admin role
async function checkUserRole(role) {
    const response = await fetch('/api/users/roles/check/', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ role: role })
    });
    
    const data = await response.json();
    return data.has_role;
}

// Check if user has any of multiple roles
async function checkAnyRole(roles) {
    const response = await fetch('/api/users/roles/check-any/', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ roles: roles })
    });
    
    const data = await response.json();
    return data.has_any_role;
}

// Get all user roles
async function getUserRoles() {
    const response = await fetch('/api/users/roles/', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`
        }
    });
    
    const data = await response.json();
    return data.user_roles;
}
```

### React Example

```jsx
import React, { useState, useEffect } from 'react';

function RoleChecker() {
    const [userRoles, setUserRoles] = useState([]);
    const [hasAdminRole, setHasAdminRole] = useState(false);

    useEffect(() => {
        // Get user roles on component mount
        fetchUserRoles();
    }, []);

    const fetchUserRoles = async () => {
        try {
            const response = await fetch('/api/users/roles/', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`
                }
            });
            const data = await response.json();
            setUserRoles(data.user_roles);
            setHasAdminRole(data.user_roles.includes('admin'));
        } catch (error) {
            console.error('Error fetching user roles:', error);
        }
    };

    const checkRole = async (role) => {
        try {
            const response = await fetch('/api/users/roles/check/', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ role })
            });
            const data = await response.json();
            return data.has_role;
        } catch (error) {
            console.error('Error checking role:', error);
            return false;
        }
    };

    return (
        <div>
            <h3>User Roles: {userRoles.join(', ')}</h3>
            {hasAdminRole && <p>You have admin privileges!</p>}
        </div>
    );
}
```

## Security Considerations

1. **JWT Token Security**: Always use HTTPS in production and store JWT tokens securely
2. **Role Validation**: Always validate roles on the server side, not just the client side
3. **Logging**: All role checks are logged for security auditing
4. **Token Expiration**: JWT tokens have expiration times, handle token refresh appropriately

## Common Use Cases

1. **Admin Panel Access**: Check if user has 'admin' role before showing admin features
2. **Content Moderation**: Check if user has 'moderator' role for content management
3. **Feature Flags**: Use roles to enable/disable features for different user types
4. **API Access Control**: Use role decorators to protect API endpoints
5. **UI Conditional Rendering**: Show/hide UI elements based on user roles

## Testing

You can test the role checking APIs using the Swagger documentation at:
- `http://localhost:8000/api/docs/swagger/`

Or using tools like Postman, curl, or any HTTP client that supports JWT authentication.
