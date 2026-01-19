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
				respondJSON(w, http.StatusForbidden, "no claims in context")
				return
			}

			if !claims.HasPermission(permission) {
				respondJSON(w, http.StatusForbidden, "missing permission "+permission)
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
				respondJSON(w, http.StatusForbidden, "no claims in context")
				return
			}

			if !claims.HasRole(role) {
				respondJSON(w, http.StatusForbidden, "missing role "+role)
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
