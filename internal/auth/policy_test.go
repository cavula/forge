package auth

import (
	"testing"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
)

func TestRoleActionMatrix(t *testing.T) {
	actions := []Action{ReadMetadata, WriteResource, ManageIdentity, "", "unknown", "state.read", "secret.read", "run.approve"}
	for _, tc := range []struct {
		role forgev1.Role
		want [8]bool
	}{
		{forgev1.Role_ROLE_ADMIN, [8]bool{true, true, true}},
		{forgev1.Role_ROLE_WRITER, [8]bool{true, true}},
		{forgev1.Role_ROLE_READER, [8]bool{true}},
		{forgev1.Role_ROLE_UNSPECIFIED, [8]bool{}},
		{forgev1.Role(-1), [8]bool{}},
		{forgev1.Role(999), [8]bool{}},
	} {
		for i, action := range actions {
			if got := Allows(tc.role, action); got != tc.want[i] {
				t.Errorf("Allows(%v, %q) = %v, want %v", tc.role, action, got, tc.want[i])
			}
		}
	}
}
