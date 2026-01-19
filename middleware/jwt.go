package middleware

import (
	"context"
	"net/http"

	platformauth "github.com/microservice-tech/platform-auth-go"
)

// JWT validates JWT tokens and adds claims to context
type JWT struct {
	validator *platformauth.Validator
}

// NewJWT creates a new JWT middleware
func NewJWT(validator *platformauth.Validator) *JWT {
	return &JWT{validator: validator}
}

// Handler wraps an http.Handler with JWT validation
func (m *JWT) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token, err := platformauth.ExtractBearerToken(authHeader)
		if err != nil {
			respondJSON(w, http.StatusUnauthorized, err.Error())
			return
		}

		claims, err := m.validator.ValidateToken(token)
		if err != nil {
			respondJSON(w, http.StatusUnauthorized, "invalid token: "+err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
