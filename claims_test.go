package platformauth

import "testing"

func TestClaims_HasRole(t *testing.T) {
	claims := &Claims{
		Roles: []string{"admin", "user", "manager"},
	}

	tests := []struct {
		name string
		role string
		want bool
	}{
		{"has admin role", "admin", true},
		{"has user role", "user", true},
		{"has manager role", "manager", true},
		{"does not have super_admin role", "super_admin", false},
		{"does not have empty role", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claims.HasRole(tt.role); got != tt.want {
				t.Errorf("Claims.HasRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClaims_HasModule(t *testing.T) {
	claims := &Claims{
		EnabledModules: []string{"users_module", "billing", "analytics"},
	}

	tests := []struct {
		name   string
		module string
		want   bool
	}{
		{"has users_module", "users_module", true},
		{"has billing", "billing", true},
		{"has analytics", "analytics", true},
		{"does not have projects", "projects", false},
		{"does not have empty module", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claims.HasModule(tt.module); got != tt.want {
				t.Errorf("Claims.HasModule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClaims_HasFeature(t *testing.T) {
	claims := &Claims{
		EnabledFeatures: []string{"feature1", "feature2", "feature3"},
	}

	tests := []struct {
		name    string
		feature string
		want    bool
	}{
		{"has feature1", "feature1", true},
		{"has feature2", "feature2", true},
		{"has feature3", "feature3", true},
		{"does not have feature4", "feature4", false},
		{"does not have empty feature", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claims.HasFeature(tt.feature); got != tt.want {
				t.Errorf("Claims.HasFeature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClaims_GetLimit(t *testing.T) {
	claims := &Claims{
		Limits: map[string]int{
			"max_users":    100,
			"max_projects": 50,
			"max_storage":  1000,
		},
	}

	tests := []struct {
		name string
		key  string
		want int
	}{
		{"get max_users", "max_users", 100},
		{"get max_projects", "max_projects", 50},
		{"get max_storage", "max_storage", 1000},
		{"get non-existent limit", "max_something", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claims.GetLimit(tt.key); got != tt.want {
				t.Errorf("Claims.GetLimit() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClaims_GetLimit_NilMap(t *testing.T) {
	claims := &Claims{
		Limits: nil,
	}

	if got := claims.GetLimit("max_users"); got != 0 {
		t.Errorf("Claims.GetLimit() with nil map = %v, want 0", got)
	}
}

func TestClaims_HasPermission(t *testing.T) {
	tests := []struct {
		name       string
		claims     *Claims
		permission string
		want       bool
	}{
		{
			name:       "admin has can_manage_users",
			claims:     &Claims{Roles: []string{"admin"}},
			permission: "can_manage_users",
			want:       true,
		},
		{
			name:       "admin has can_view_users",
			claims:     &Claims{Roles: []string{"admin"}},
			permission: "can_view_users",
			want:       true,
		},
		{
			name:       "admin has can_delete_users",
			claims:     &Claims{Roles: []string{"admin"}},
			permission: "can_delete_users",
			want:       true,
		},
		{
			name:       "manager has can_view_users",
			claims:     &Claims{Roles: []string{"manager"}},
			permission: "can_view_users",
			want:       true,
		},
		{
			name:       "manager does not have can_manage_users",
			claims:     &Claims{Roles: []string{"manager"}},
			permission: "can_manage_users",
			want:       false,
		},
		{
			name:       "user does not have can_view_users",
			claims:     &Claims{Roles: []string{"user"}},
			permission: "can_view_users",
			want:       false,
		},
		{
			name:       "super_admin has all permissions",
			claims:     &Claims{Roles: []string{"super_admin"}},
			permission: "can_manage_tenants",
			want:       true,
		},
		{
			name:       "multiple roles - admin wins",
			claims:     &Claims{Roles: []string{"user", "admin"}},
			permission: "can_manage_users",
			want:       true,
		},
		{
			name:       "unknown role has no permissions",
			claims:     &Claims{Roles: []string{"unknown_role"}},
			permission: "can_manage_users",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.claims.HasPermission(tt.permission); got != tt.want {
				t.Errorf("Claims.HasPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetRolePermissions(t *testing.T) {
	// Save original permissions
	original := GetRolePermissions()
	defer SetRolePermissions(original)

	// Set custom permissions
	custom := map[string][]string{
		"custom_role": {"custom_permission1", "custom_permission2"},
	}
	SetRolePermissions(custom)

	// Verify custom permissions are set
	claims := &Claims{Roles: []string{"custom_role"}}
	if !claims.HasPermission("custom_permission1") {
		t.Errorf("Custom permission1 not found after SetRolePermissions")
	}
	if !claims.HasPermission("custom_permission2") {
		t.Errorf("Custom permission2 not found after SetRolePermissions")
	}

	// Verify old permissions are gone
	if claims.HasPermission("can_manage_users") {
		t.Errorf("Old permission still exists after SetRolePermissions")
	}
}

func TestGetRolePermissions(t *testing.T) {
	perms := GetRolePermissions()

	if perms == nil {
		t.Errorf("GetRolePermissions() returned nil")
	}

	if len(perms) == 0 {
		t.Errorf("GetRolePermissions() returned empty map")
	}

	// Verify default roles exist
	expectedRoles := []string{"admin", "manager", "user", "super_admin"}
	for _, role := range expectedRoles {
		if _, ok := perms[role]; !ok {
			t.Errorf("GetRolePermissions() missing expected role: %s", role)
		}
	}
}
