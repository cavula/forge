// Package database establishes the organization boundary for database access.
package database

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithOrg scopes every operation to one transaction. The setting is transaction
// local so pooled connections cannot carry an organization's identity forward.
// orgID must come from authenticated authorization context, never a request field.
func WithOrg(ctx context.Context, pool *pgxpool.Pool, orgID string, fn func(pgx.Tx) error) error {
	var id pgtype.UUID
	if err := id.Scan(orgID); err != nil || !id.Valid {
		return errors.New("invalid organization identifier")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, "SELECT set_config('forge.org_id', $1, true)", orgID); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// StackExists uses an explicit tenant predicate as defense in depth alongside RLS.
func StackExists(ctx context.Context, tx pgx.Tx, orgID, stackID string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM stacks WHERE org_id = $1 AND id = $2)", orgID, stackID).Scan(&exists)
	return exists, err
}
