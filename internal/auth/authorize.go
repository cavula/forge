package auth

import (
	"context"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"github.com/cavula/forge/internal/database"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithMembership authorizes an operation using current membership held FOR SHARE
// through commit. The preliminary lookup supplies only an organization and user
// selector; its role is never reused as operation authority. Callers must provide
// an OIDC/session-verified identity, not construct one from request fields.
func WithMembership(ctx context.Context, pool *pgxpool.Pool, identity VerifiedIdentity, orgHint string, action Action, operation func(pgx.Tx, *forgev1.User) error) error {
	if operation == nil || (action != ReadMetadata && action != WriteResource && action != ManageIdentity) {
		return errMembership
	}
	resolved, err := ResolveMembership(ctx, pool, identity, orgHint)
	if err != nil {
		return errMembership
	}
	var operationErr error
	err = database.WithOrg(ctx, pool, resolved.OrgId, func(tx pgx.Tx) error {
		// Only the authorized tenant context belongs in the resource transaction.
		if _, err := tx.Exec(ctx, `SELECT set_config('forge.auth_issuer','',true),
 set_config('forge.auth_subject','',true),set_config('forge.login_state_hash','',true),
 set_config('forge.login_binding_hash','',true),set_config('forge.browser_session_hash','',true)`); err != nil {
			return errMembership
		}
		current := &forgev1.User{}
		var role string
		err := tx.QueryRow(ctx, `SELECT id::text,org_id::text,issuer,subject,display_name,role
 FROM users WHERE org_id=$1 AND id=$2 AND issuer=$3 AND subject=$4 FOR SHARE`,
			resolved.OrgId, resolved.Id, identity.issuer, identity.subject).
			Scan(&current.Id, &current.OrgId, &current.OidcIssuer, &current.OidcSubject, &current.DisplayName, &role)
		current.Role = membershipRole(role)
		if err != nil || !Allows(current.Role, action) {
			return errMembership
		}
		operationErr = operation(tx, current)
		return operationErr
	})
	if err != nil {
		if operationErr != nil {
			return operationErr
		}
		return errMembership
	}
	return nil
}
