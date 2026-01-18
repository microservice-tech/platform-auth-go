package middleware

import (
	"context"

	platformauth "github.com/microservice-tech/platform-auth-go"
)

type contextKey string

const ClaimsContextKey contextKey = "claims"

// GetClaims extracts claims from request context
func GetClaims(ctx context.Context) (*platformauth.Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*platformauth.Claims)
	return claims, ok
}
