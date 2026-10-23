package auth

import (
	"context"
	"errors"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errMembership = errors.New("organization membership unavailable")

// ResolveMembership selects an existing membership for an OIDC-verified
// principal. The organization hint never establishes tenant authority. Callers
// must re-resolve each operation and pass only the result's organization to
// WithOrg; identity verification alone does not confer a role or membership.
func ResolveMembership(ctx context.Context, pool *pgxpool.Pool, identity VerifiedIdentity, orgHint string) (*forgev1.User, error) {
	var org pgtype.UUID
	if pool == nil || identity.issuer == "" || identity.subject == "" || org.Scan(orgHint) != nil || !org.Valid || org.String() != orgHint {
		return nil, errMembership
	}
	tx, err := beginResolution(ctx, pool, identity)
	if err != nil {
		return nil, errMembership
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	user := &forgev1.User{}
	var role string
	err = tx.QueryRow(ctx, `SELECT id::text, org_id::text, issuer, subject, display_name, role
 FROM users WHERE org_id=$1 AND issuer=$2 AND subject=$3`, orgHint, identity.issuer, identity.subject).
		Scan(&user.Id, &user.OrgId, &user.OidcIssuer, &user.OidcSubject, &user.DisplayName, &role)
	user.Role = membershipRole(role)
	if err != nil || user.Role == forgev1.Role_ROLE_UNSPECIFIED {
		return nil, errMembership
	}
	if tx.Commit(ctx) != nil {
		return nil, errMembership
	}
	return user, nil
}

func beginResolution(ctx context.Context, pool *pgxpool.Pool, identity VerifiedIdentity) (pgx.Tx, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, errMembership
	}
	// Clear inherited tenant context before installing verified-principal context.
	if _, err = tx.Exec(ctx, "SELECT set_config('forge.org_id', '', true)"); err == nil {
		_, err = tx.Exec(ctx, `SELECT set_config('forge.auth_issuer',$1,true),
 set_config('forge.auth_subject',$2,true)`, identity.issuer, identity.subject)
	}
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, errMembership
	}
	return tx, nil
}

func membershipRole(role string) forgev1.Role {
	switch role {
	case "admin":
		return forgev1.Role_ROLE_ADMIN
	case "writer":
		return forgev1.Role_ROLE_WRITER
	case "reader":
		return forgev1.Role_ROLE_READER
	default:
		return forgev1.Role_ROLE_UNSPECIFIED
	}
}
