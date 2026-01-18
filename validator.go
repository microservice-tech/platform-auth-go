package platformauth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingToken     = errors.New("missing authorization token")
	ErrInvalidToken     = errors.New("invalid token")
	ErrInvalidIssuer    = errors.New("invalid token issuer")
	ErrInvalidAudience  = errors.New("invalid token audience")
	ErrTokenExpired     = errors.New("token has expired")
	ErrInvalidSignature = errors.New("invalid token signature")
)

// Config holds JWT validator configuration
type Config struct {
	PublicKeyPath    string
	ExpectedIssuer   string
	ExpectedAudience string
}

// Validator validates gateway-signed JWTs
type Validator struct {
	publicKey *rsa.PublicKey
	issuer    string
	audience  string
}

// NewValidator creates a new JWT validator
func NewValidator(cfg Config) (*Validator, error) {
	keyData, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &Validator{
		publicKey: publicKey,
		issuer:    cfg.ExpectedIssuer,
		audience:  cfg.ExpectedAudience,
	}, nil
}

// ValidateToken validates a JWT and returns its claims
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.publicKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, ErrInvalidSignature
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Validate issuer
	if claims.Issuer != v.issuer {
		return nil, ErrInvalidIssuer
	}

	// Validate audience
	audienceValid := false
	for _, aud := range claims.Audience {
		if aud == v.audience {
			audienceValid = true
			break
		}
	}
	if !audienceValid {
		return nil, ErrInvalidAudience
	}

	return claims, nil
}

// ExtractBearerToken extracts the token from an Authorization header value
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingToken
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrInvalidToken
	}

	return parts[1], nil
}
