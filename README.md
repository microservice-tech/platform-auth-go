# Platform Auth Go

Reusable Go authentication library for platform microservices. Provides JWT validation and 3-legged authentication enforcement (Identity + Permissions + Entitlements).

## Features

- **JWT Validation**: Validate gateway-signed internal JWTs
- **3-Legged Auth**: Identity (who) + Permissions (what actions) + Entitlements (what's enabled)
- **Middleware**: Easy-to-use HTTP middleware for gorilla/mux, chi, or standard lib
- **Flexible Configuration**: Simple config struct
- **Zero External Service Calls**: All auth data in JWT, no network calls needed

## Installation

```bash
go get github.com/microservice-tech/platform-auth-go
```

## Quick Start

```go
package main

import (
    "net/http"
    "github.com/gorilla/mux"
    platformauth "github.com/microservice-tech/platform-auth-go"
    "github.com/microservice-tech/platform-auth-go/middleware"
)

func main() {
    // Initialize validator
    validator, err := platformauth.NewValidator(platformauth.Config{
        PublicKeyPath:    "/keys/gateway-public.pem",
        ExpectedIssuer:   "platform-gateway",
        ExpectedAudience: "internal-services",
    })
    if err != nil {
        panic(err)
    }

    // Create middleware
    jwtMiddleware := middleware.NewJWT(validator)

    // Setup router
    router := mux.NewRouter()

    // Apply auth middleware to protected routes
    api := router.PathPrefix("/api").Subrouter()
    api.Use(jwtMiddleware.Handler)
    api.Use(middleware.RequireModule("notifications_module"))

    // Add permission check
    api.Handle("/admin",
        middleware.RequirePermission("can_manage_notifications")(
            http.HandlerFunc(adminHandler),
        ),
    ).Methods("GET")
}
```

## The Three-Axis Security Model

```
Access Granted = Permission AND Entitlement
```

### Axis 1: Identity (Keycloak)
**Question**: "Who are you?"
**Answers**: user_id, tenant_id

### Axis 2: Permissions (Roles)
**Question**: "What actions can you perform?"
**Answers**: Roles like "admin", "user", "viewer"

### Axis 3: Entitlements (Subscriptions)
**Question**: "What did your tenant pay for?"
**Answers**: enabled_modules, enabled_features, limits

## Middleware Functions

### JWT Validation
Validates the gateway-signed JWT and adds claims to request context:

```go
api.Use(jwtMiddleware.Handler)
```

### Module Enforcement
Checks if tenant has enabled module (returns 402 Payment Required if not):

```go
api.Use(middleware.RequireModule("billing_module"))
```

### Feature Enforcement
Checks if tenant has enabled feature (returns 402 Payment Required if not):

```go
api.Use(middleware.RequireFeature("api_access"))
```

### Permission Enforcement
Checks if user has required permission from their roles (returns 403 Forbidden if not):

```go
api.Handle("/users", middleware.RequirePermission("can_manage_users")(handler))
```

### Role Enforcement
Checks if user has specific role (returns 403 Forbidden if not):

```go
api.Handle("/admin", middleware.RequireRole("admin")(handler))
```

### Limit Enforcement
Checks if tenant's limit meets minimum requirement (returns 402 Payment Required if not):

```go
api.Use(middleware.RequireLimit("api_calls", 1000))
```

## Accessing Claims

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := middleware.GetClaims(r.Context())
    if !ok {
        http.Error(w, "Unauthorized", 401)
        return
    }

    userID := claims.UserID
    tenantID := claims.TenantID
    roles := claims.Roles
    modules := claims.EnabledModules
    features := claims.EnabledFeatures
    apiCallLimit := claims.GetLimit("api_calls")
}
```

## Custom Permission Mapping

By default, permissions are mapped by role. You can customize this:

```go
middleware.RolePermissions = map[string][]string{
    "admin": {"can_manage_users", "can_view_billing"},
    "user": {"can_view_own_data"},
}
```

## Error Handling

The library returns standard HTTP error codes:

- **401 Unauthorized**: Missing or invalid JWT
- **403 Forbidden**: User lacks required permission/role
- **402 Payment Required**: Tenant lacks required module/feature/limit

## Testing

Mock JWT for testing:

```go
import "github.com/microservice-tech/platform-auth-go/testing"

claims := &platformauth.Claims{
    UserID: "test-user",
    TenantID: "test-tenant",
    Roles: []string{"admin"},
    EnabledModules: []string{"billing_module"},
}

token := testing.GenerateTestToken(claims, privateKey)
```

## License

MIT
