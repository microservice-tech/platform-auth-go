package platformauth

import "github.com/golang-jwt/jwt/v5"

// Claims represents the JWT claims from the platform gateway's internal JWT.
// This contains all three axes of the security model:
//   - Axis 1 (Identity): UserID, TenantID
//   - Axis 2 (Permissions): Roles
//   - Axis 3 (Entitlements): EnabledModules, EnabledFeatures, Limits
type Claims struct {
	jwt.RegisteredClaims
	UserID          string         `json:"user_id"`
	TenantID        string         `json:"tenant_id"`
	Roles           []string       `json:"roles"`
	EnabledModules  []string       `json:"enabled_modules"`
	EnabledFeatures []string       `json:"enabled_features"`
	Limits          map[string]int `json:"limits"`
}

// HasRole checks if the claims contain a specific role
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasModule checks if the claims contain a specific enabled module
func (c *Claims) HasModule(module string) bool {
	for _, m := range c.EnabledModules {
		if m == module {
			return true
		}
	}
	return false
}

// HasFeature checks if the claims contain a specific enabled feature
func (c *Claims) HasFeature(feature string) bool {
	for _, f := range c.EnabledFeatures {
		if f == feature {
			return true
		}
	}
	return false
}

// GetLimit returns the limit value for a given key, or 0 if not found
func (c *Claims) GetLimit(key string) int {
	if c.Limits == nil {
		return 0
	}
	return c.Limits[key]
}

// HasPermission checks if any of the user's roles grant the specified permission
// Uses the global RolePermissions map for role-to-permission mapping
func (c *Claims) HasPermission(permission string) bool {
	for _, role := range c.Roles {
		if perms, ok := defaultRolePermissions[role]; ok {
			for _, p := range perms {
				if p == permission {
					return true
				}
			}
		}
	}
	return false
}

// defaultRolePermissions maps roles to their permissions
// Services can override this with their own mapping
var defaultRolePermissions = map[string][]string{
	"admin":       {"can_manage_users", "can_view_users", "can_delete_users", "can_manage_notifications"},
	"manager":     {"can_view_users"},
	"user":        {},
	"super_admin": {"can_manage_users", "can_view_users", "can_delete_users", "can_manage_tenants", "can_manage_notifications"},
}

// SetRolePermissions allows services to customize role-to-permission mapping
func SetRolePermissions(mapping map[string][]string) {
	defaultRolePermissions = mapping
}

// GetRolePermissions returns the current role-to-permission mapping
func GetRolePermissions() map[string][]string {
	return defaultRolePermissions
}
