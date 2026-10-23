package database

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Storage assertions use the runtime role. This owner is reserved for teardown
// of exact fixture tenants when runtime hard deletion is intentionally revoked.
func storageFixtureOwner(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL required for migration-owner fixture cleanup")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal("fixture owner unavailable")
	}
	t.Cleanup(pool.Close)
	var safe bool
	err = pool.QueryRow(ctx, `SELECT NOT r.rolsuper AND NOT r.rolbypassrls
 AND c.relowner=r.oid AND c.relrowsecurity AND c.relforcerowsecurity
 FROM pg_roles r CROSS JOIN pg_class c
 WHERE r.rolname=current_user AND c.oid='stacks'::regclass`).Scan(&safe)
	if err != nil || !safe {
		t.Fatal("actual nonsuperuser NOBYPASSRLS stack owner with FORCE RLS required for fixture cleanup")
	}
	return pool
}
