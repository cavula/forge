// Package auth defines the internal authorization policy. Authentication and
// authorized membership resolution must precede policy evaluation.
package auth

import forgev1 "github.com/cavula/forge/gen/go/forge/v1"

// Action identifies an explicitly supported operation, not a route or RPC name.
type Action string

const (
	ReadMetadata   Action = "metadata.read"
	WriteResource  Action = "resource.write"
	ManageIdentity Action = "identity.manage"
)

// Allows evaluates a current, verified organization membership's role. It does
// not authenticate a caller or authorize organization selection. Ordinary
// resource permissions exclude state, secrets, credentials and run approval.
// Teams confer no additional permissions; unrecognized roles/actions deny.
func Allows(role forgev1.Role, action Action) bool {
	switch role {
	case forgev1.Role_ROLE_ADMIN:
		return action == ReadMetadata || action == WriteResource || action == ManageIdentity
	case forgev1.Role_ROLE_WRITER:
		return action == ReadMetadata || action == WriteResource
	case forgev1.Role_ROLE_READER:
		return action == ReadMetadata
	default:
		return false
	}
}
