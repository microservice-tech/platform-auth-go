package platformauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateTestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey, string) {
	t.Helper()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create temp directory for test keys
	tmpDir := t.TempDir()
	publicKeyPath := filepath.Join(tmpDir, "public.pem")

	// Write public key to file
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

	return privateKey, &privateKey.PublicKey, publicKeyPath
}

func createTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims *Claims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return tokenString
}

func TestNewValidator(t *testing.T) {
	_, _, publicKeyPath := generateTestKeys(t)

	tests := []struct {
		name      string
		config    Config
		wantError bool
	}{
		{
			name: "valid configuration",
			config: Config{
				PublicKeyPath:    publicKeyPath,
				ExpectedIssuer:   "platform-gateway",
				ExpectedAudience: "internal-services",
			},
			wantError: false,
		},
		{
			name: "missing public key file",
			config: Config{
				PublicKeyPath:    "/nonexistent/key.pem",
				ExpectedIssuer:   "platform-gateway",
				ExpectedAudience: "internal-services",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewValidator(tt.config)
			if tt.wantError {
				if err == nil {
					t.Errorf("NewValidator() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewValidator() unexpected error: %v", err)
				return
			}

			if validator == nil {
				t.Errorf("NewValidator() returned nil validator")
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	privateKey, _, publicKeyPath := generateTestKeys(t)

	validator, err := NewValidator(Config{
		PublicKeyPath:    publicKeyPath,
		ExpectedIssuer:   "platform-gateway",
		ExpectedAudience: "internal-services",
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	tests := []struct {
		name      string
		claims    *Claims
		issuer    string
		audience  []string
		wantError error
	}{
		{
			name: "valid token",
			claims: &Claims{
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
				Limits:          map[string]int{"max_users": 100},
			},
			wantError: nil,
		},
		{
			name: "expired token",
			claims: &Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "platform-gateway",
					Audience:  jwt.ClaimStrings{"internal-services"},
					Subject:   "user-123",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				},
				UserID:   "user-123",
				TenantID: "tenant-456",
			},
			wantError: ErrTokenExpired,
		},
		{
			name: "invalid issuer",
			claims: &Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "wrong-issuer",
					Audience:  jwt.ClaimStrings{"internal-services"},
					Subject:   "user-123",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
				UserID:   "user-123",
				TenantID: "tenant-456",
			},
			wantError: ErrInvalidIssuer,
		},
		{
			name: "invalid audience",
			claims: &Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "platform-gateway",
					Audience:  jwt.ClaimStrings{"wrong-audience"},
					Subject:   "user-123",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
				UserID:   "user-123",
				TenantID: "tenant-456",
			},
			wantError: ErrInvalidAudience,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := createTestToken(t, privateKey, tt.claims)

			claims, err := validator.ValidateToken(tokenString)

			if tt.wantError != nil {
				if err == nil {
					t.Errorf("ValidateToken() expected error %v, got nil", tt.wantError)
					return
				}
				if err != tt.wantError {
					t.Errorf("ValidateToken() expected error %v, got %v", tt.wantError, err)
				}
				return
			}

			if err != nil {
				t.Errorf("ValidateToken() unexpected error: %v", err)
				return
			}

			if claims == nil {
				t.Errorf("ValidateToken() returned nil claims")
				return
			}

			if claims.UserID != tt.claims.UserID {
				t.Errorf("ValidateToken() UserID = %v, want %v", claims.UserID, tt.claims.UserID)
			}

			if claims.TenantID != tt.claims.TenantID {
				t.Errorf("ValidateToken() TenantID = %v, want %v", claims.TenantID, tt.claims.TenantID)
			}
		})
	}
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	_, _, publicKeyPath := generateTestKeys(t)

	validator, err := NewValidator(Config{
		PublicKeyPath:    publicKeyPath,
		ExpectedIssuer:   "platform-gateway",
		ExpectedAudience: "internal-services",
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	// Generate a different private key to sign the token
	wrongPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate wrong private key: %v", err)
	}

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "platform-gateway",
			Audience:  jwt.ClaimStrings{"internal-services"},
			Subject:   "user-123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UserID:   "user-123",
		TenantID: "tenant-456",
	}

	tokenString := createTestToken(t, wrongPrivateKey, claims)

	_, err = validator.ValidateToken(tokenString)
	if err == nil {
		t.Errorf("ValidateToken() expected signature error, got nil")
	}
	// Signature errors should result in validation failure
	// The validator may return ErrInvalidSignature or ErrInvalidToken
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantToken  string
		wantError  error
	}{
		{
			name:       "valid bearer token",
			authHeader: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
			wantToken:  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
			wantError:  nil,
		},
		{
			name:       "case insensitive bearer",
			authHeader: "bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
			wantToken:  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
			wantError:  nil,
		},
		{
			name:       "empty header",
			authHeader: "",
			wantToken:  "",
			wantError:  ErrMissingToken,
		},
		{
			name:       "missing bearer prefix",
			authHeader: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token",
			wantToken:  "",
			wantError:  ErrInvalidToken,
		},
		{
			name:       "wrong auth scheme",
			authHeader: "Basic dXNlcjpwYXNz",
			wantToken:  "",
			wantError:  ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractBearerToken(tt.authHeader)

			if tt.wantError != nil {
				if err == nil {
					t.Errorf("ExtractBearerToken() expected error %v, got nil", tt.wantError)
					return
				}
				if err != tt.wantError {
					t.Errorf("ExtractBearerToken() expected error %v, got %v", tt.wantError, err)
				}
				return
			}

			if err != nil {
				t.Errorf("ExtractBearerToken() unexpected error: %v", err)
				return
			}

			if token != tt.wantToken {
				t.Errorf("ExtractBearerToken() = %v, want %v", token, tt.wantToken)
			}
		})
	}
}
