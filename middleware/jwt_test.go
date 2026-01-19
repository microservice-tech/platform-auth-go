package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	platformauth "github.com/microservice-tech/platform-auth-go"
)

func generateTestKeys(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	tmpDir := t.TempDir()
	publicKeyPath := filepath.Join(tmpDir, "public.pem")

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	return privateKey, publicKeyPath
}

func createTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims *platformauth.Claims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return tokenString
}

func TestJWT_Handler(t *testing.T) {
	privateKey, publicKeyPath := generateTestKeys(t)

	validator, err := platformauth.NewValidator(platformauth.Config{
		PublicKeyPath:    publicKeyPath,
		ExpectedIssuer:   "platform-gateway",
		ExpectedAudience: "internal-services",
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	jwtMiddleware := NewJWT(validator)

	validClaims := &platformauth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "platform-gateway",
			Audience:  jwt.ClaimStrings{"internal-services"},
			Subject:   "user-123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UserID:          "user-123",
		TenantID:        "tenant-456",
		Roles:           []string{"admin"},
		EnabledModules:  []string{"users_module"},
		EnabledFeatures: []string{"feature1"},
	}

	tests := []struct {
		name           string
		authHeader     string
		wantStatusCode int
		checkClaims    bool
	}{
		{
			name:           "valid token",
			authHeader:     "Bearer " + createTestToken(t, privateKey, validClaims),
			wantStatusCode: http.StatusOK,
			checkClaims:    true,
		},
		{
			name:           "missing authorization header",
			authHeader:     "",
			wantStatusCode: http.StatusUnauthorized,
			checkClaims:    false,
		},
		{
			name:           "invalid bearer format",
			authHeader:     "InvalidFormat",
			wantStatusCode: http.StatusUnauthorized,
			checkClaims:    false,
		},
		{
			name:           "invalid token",
			authHeader:     "Bearer invalid.token.here",
			wantStatusCode: http.StatusUnauthorized,
			checkClaims:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test handler that checks for claims in context
			var capturedClaims *platformauth.Claims
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				claims := r.Context().Value(ClaimsContextKey)
				if claims != nil {
					capturedClaims = claims.(*platformauth.Claims)
				}
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with JWT middleware
			handler := jwtMiddleware.Handler(testHandler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Record response
			rr := httptest.NewRecorder()

			// Serve request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.wantStatusCode {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, tt.wantStatusCode)
			}

			// Check claims in context if applicable
			if tt.checkClaims {
				if capturedClaims == nil {
					t.Errorf("claims not found in context")
					return
				}

				if capturedClaims.UserID != validClaims.UserID {
					t.Errorf("UserID = %v, want %v", capturedClaims.UserID, validClaims.UserID)
				}

				if capturedClaims.TenantID != validClaims.TenantID {
					t.Errorf("TenantID = %v, want %v", capturedClaims.TenantID, validClaims.TenantID)
				}
			}
		})
	}
}

func TestNewJWT(t *testing.T) {
	_, publicKeyPath := generateTestKeys(t)

	validator, err := platformauth.NewValidator(platformauth.Config{
		PublicKeyPath:    publicKeyPath,
		ExpectedIssuer:   "platform-gateway",
		ExpectedAudience: "internal-services",
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	middleware := NewJWT(validator)

	if middleware == nil {
		t.Errorf("NewJWT() returned nil")
	}
}
