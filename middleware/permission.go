package middleware

import (
	"net/http"

	platformauth "github.com/microservice-tech/platform-auth-go"
)

// RequirePermission returns middleware that checks for a specific permission
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaims(r.Context())
			if !ok {
				http.Error(w, "Forbidden: no claims in context", http.StatusForbidden)
				return
			}

			if !claims.HasPermission(permission) {
				http.Error(w, "Forbidden: missing permission "+permission, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns middleware that checks for a specific role
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaims(r.Context())
			if !ok {
				http.Error(w, "Forbidden: no claims in context", http.StatusForbidden)
				return
			}

			if !claims.HasRole(role) {
				http.Error(w, "Forbidden: missing role "+role, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SetRolePermissions allows services to customize role-to-permission mapping
func SetRolePermissions(mapping map[string][]string) {
	platformauth.SetRolePermissions(mapping)
}
