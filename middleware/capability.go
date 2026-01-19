package middleware

import (
	"net/http"
)

// RequireModule returns middleware that checks for an enabled module
func RequireModule(module string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaims(r.Context())
			if !ok {
				respondJSON(w, http.StatusPaymentRequired, "no claims in context")
				return
			}

			if !claims.HasModule(module) {
				respondJSON(w, http.StatusPaymentRequired, "module "+module+" not enabled")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireFeature returns middleware that checks for an enabled feature
func RequireFeature(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaims(r.Context())
			if !ok {
				respondJSON(w, http.StatusPaymentRequired, "no claims in context")
				return
			}

			if !claims.HasFeature(feature) {
				respondJSON(w, http.StatusPaymentRequired, "feature "+feature+" not enabled")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireLimit returns middleware that checks if a limit is above a threshold
func RequireLimit(limitKey string, minValue int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaims(r.Context())
			if !ok {
				respondJSON(w, http.StatusPaymentRequired, "no claims in context")
				return
			}

			if claims.GetLimit(limitKey) < minValue {
				respondJSON(w, http.StatusPaymentRequired, "insufficient limit for "+limitKey)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
