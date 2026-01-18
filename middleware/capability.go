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
				http.Error(w, "Payment Required: no claims in context", http.StatusPaymentRequired)
				return
			}

			if !claims.HasModule(module) {
				http.Error(w, "Payment Required: module "+module+" not enabled", http.StatusPaymentRequired)
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
				http.Error(w, "Payment Required: no claims in context", http.StatusPaymentRequired)
				return
			}

			if !claims.HasFeature(feature) {
				http.Error(w, "Payment Required: feature "+feature+" not enabled", http.StatusPaymentRequired)
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
				http.Error(w, "Payment Required: no claims in context", http.StatusPaymentRequired)
				return
			}

			if claims.GetLimit(limitKey) < minValue {
				http.Error(w, "Payment Required: insufficient limit for "+limitKey, http.StatusPaymentRequired)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
