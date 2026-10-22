package database

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTenantIsolation(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL integration")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1 // Every operation reuses the same physical connection.
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var unsafe bool
	if err := pool.QueryRow(ctx, "SELECT rolsuper OR rolbypassrls OR EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner=current_user) FROM pg_roles WHERE rolname = current_user").Scan(&unsafe); err != nil {
		t.Fatal(err)
	}
	if unsafe {
		t.Fatal("integration test must use nonowner, non-superuser NOBYPASSRLS runtime role")
	}
	orgA, orgB := "10000000-0000-0000-0000-000000000001", "10000000-0000-0000-0000-000000000002"
	id := "20000000-0000-0000-0000-000000000001"
	within := func(t *testing.T, org string, fn func(pgx.Tx) error) {
		t.Helper()
		if err := WithOrg(ctx, pool, org, fn); err != nil {
			t.Fatal(err)
		}
	}
	for _, org := range []string{orgA, orgB} {
		within(t, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "INSERT INTO orgs(id,name) VALUES($1,'isolation test') ON CONFLICT DO NOTHING", org)
			return err
		})
	}
	// Every entity has a positive same-tenant fixture and read/write boundary tests.
	entities := []struct {
		table, insert string
		args          []any
	}{
		{"orgs", "INSERT INTO orgs(id,name) VALUES($1,'forbidden')", []any{orgA}},
		{"users", "INSERT INTO users(org_id,id,issuer,subject,display_name) VALUES($1,$2,'https://issuer.test','subject','user')", []any{orgA, id}},
		{"teams", "INSERT INTO teams(org_id,id,name) VALUES($1,$2,'team')", []any{orgA, id}},
		{"stacks", "INSERT INTO stacks(org_id,id,name) VALUES($1,$2,'stack')", []any{orgA, id}},
		{"runs", "INSERT INTO runs(org_id,id,stack_id) VALUES($1,$2,$2)", []any{orgA, id}},
		{"state_versions", "INSERT INTO state_versions(org_id,id,stack_id,serial,ciphertext,wrapped_dek,nonce,key_id) VALUES($1,$2,$2,0,'cipher','wrapped','123456789012','key')", []any{orgA, id}},
		{"policies", "INSERT INTO policies(org_id,id,name,source) VALUES($1,$2,'policy','package test')", []any{orgA, id}},
		{"secrets", "INSERT INTO secrets(org_id,id,name,ciphertext,wrapped_dek,nonce,key_id) VALUES($1,$2,'secret','cipher','wrapped','123456789012','key')", []any{orgA, id}},
		{"audit_events", "INSERT INTO audit_events(org_id,id,actor_id,stack_id,action) VALUES($1,$2,$2,$2,'test')", []any{orgA, id}},
	}
	// Seed complete resources for both tenants, preserving dependency order.
	for _, e := range entities {
		if e.table == "orgs" {
			continue
		}
		for _, org := range []string{orgA, orgB} {
			args := append([]any(nil), e.args...)
			args[0] = org
			within(t, org, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, e.insert+" ON CONFLICT DO NOTHING", args...); return err })
		}
	}
	for _, e := range entities {
		t.Run(e.table, func(t *testing.T) {
			column := "org_id"
			if e.table == "orgs" {
				column = "id"
			}
			query := "SELECT count(*) FROM " + e.table + " WHERE " + column + "=$1"
			for _, boundary := range [][2]string{{orgA, orgB}, {orgB, orgA}} {
				own, other := boundary[0], boundary[1]
				within(t, own, func(tx pgx.Tx) error {
					var n int
					if err := tx.QueryRow(ctx, query, own).Scan(&n); err != nil {
						return err
					}
					if n < 1 {
						t.Fatal("own tenant fixture invisible")
					}
					return nil
				})
				within(t, own, func(tx pgx.Tx) error {
					var n int
					if err := tx.QueryRow(ctx, query, other).Scan(&n); err != nil {
						return err
					}
					if n != 0 {
						t.Fatal("cross-tenant read exposed data")
					}
					return nil
				})
				args := append([]any(nil), e.args...)
				args[0] = other
				requireSQLState(t, WithOrg(ctx, pool, own, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, e.insert, args...); return err }), "42501")
			}
			// Missing context denies reads and writes on the same physical connection.
			var n int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+e.table).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Fatal("transaction-local tenant leaked")
			}
			_, err := pool.Exec(ctx, e.insert, e.args...)
			requireSQLState(t, err, "42501")
		})
	}
	within(t, orgA, func(tx pgx.Tx) error {
		found, err := StackExists(ctx, tx, orgA, id)
		if err != nil {
			return err
		}
		if !found {
			t.Fatal("own stack missing")
		}
		return nil
	})
	within(t, orgB, func(tx pgx.Tx) error {
		found, err := StackExists(ctx, tx, orgA, id)
		if err != nil {
			return err
		}
		if found {
			t.Fatal("explicit org query bypassed RLS")
		}
		return nil
	})
	within(t, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO stacks(org_id,id,name) VALUES($1,'50000000-0000-0000-0000-000000000001','a-only') ON CONFLICT DO NOTHING", orgA)
		return err
	})
	requireSQLState(t, WithOrg(ctx, pool, orgB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO runs(org_id,id,stack_id) VALUES($1,'40000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001')", orgB)
		return err
	}), "23503")
	requireSQLState(t, WithOrg(ctx, pool, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE stacks SET org_id=$1 WHERE id=$2", orgB, id)
		return err
	}), "42501")
	sentinel := errors.New("rollback")
	err = WithOrg(ctx, pool, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO teams(org_id,id,name) VALUES($1,'30000000-0000-0000-0000-000000000001','rollback')", orgA)
		if err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal("callback error not preserved")
	}
	within(t, orgA, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM teams WHERE org_id=$1 AND name='rollback'", orgA).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatal("rollback committed data")
		}
		return nil
	})
	for _, sql := range []string{"UPDATE audit_events SET action='tamper'", "DELETE FROM audit_events", "TRUNCATE audit_events"} {
		requireSQLState(t, WithOrg(ctx, pool, orgA, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql); return err }), "42501")
	}
	if err := WithOrg(ctx, pool, "invalid", func(pgx.Tx) error { t.Fatal("invalid org callback invoked"); return nil }); err == nil {
		t.Fatal("invalid org accepted")
	}
}

func requireSQLState(t *testing.T, err error, code string) {
	t.Helper()
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != code {
		t.Fatalf("expected SQLSTATE %s, got %v", code, err)
	}
}
