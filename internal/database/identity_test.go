package database

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIdentityConstraints(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL integration")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var safe bool
	if err := pool.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolbypassrls AND
 NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner=current_user)
 FROM pg_roles WHERE rolname=current_user`).Scan(&safe); err != nil || !safe {
		t.Fatalf("runtime role required: safe=%v err=%v", safe, err)
	}
	if err := pool.QueryRow(ctx, "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='team_memberships'::regclass").Scan(&safe); err != nil || !safe {
		t.Fatalf("membership RLS must be enabled and forced: safe=%v err=%v", safe, err)
	}
	orgs := []string{"11000000-0000-0000-0000-000000000001", "11000000-0000-0000-0000-000000000002"}
	unique := []string{"22000000-0000-0000-0000-000000000001", "22000000-0000-0000-0000-000000000002"}
	id := "33000000-0000-0000-0000-000000000001"
	for i, org := range orgs {
		err := WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
			queries := []struct {
				sql  string
				args []any
			}{
				{"INSERT INTO orgs(id,name) VALUES($1,'identity test') ON CONFLICT DO NOTHING", []any{org}},
				{"INSERT INTO users(org_id,id,issuer,subject,display_name) VALUES($1,$2,'https://identity.test','shared','test') ON CONFLICT (org_id,id) DO UPDATE SET role=DEFAULT", []any{org, id}},
				{"INSERT INTO users(org_id,id,issuer,subject,display_name) VALUES($1,$2,'https://identity.test','unique','unique') ON CONFLICT DO NOTHING", []any{org, unique[i]}},
				{"INSERT INTO teams(org_id,id,name) VALUES($1,$2,'shared'),($1,$3,'unique') ON CONFLICT DO NOTHING", []any{org, id, unique[i]}},
				{"INSERT INTO team_memberships(org_id,team_id,user_id) VALUES($1,$2,$2) ON CONFLICT DO NOTHING", []any{org, id}},
			}
			for _, q := range queries {
				if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
					return err
				}
			}
			var role string
			if err := tx.QueryRow(ctx, "SELECT role FROM users WHERE org_id=$1 AND id=$2", org, id).Scan(&role); err != nil {
				return err
			}
			if role != "reader" {
				t.Fatal("membership must default to reader")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	rollback := errors.New("rollback test writes")
	for i, org := range orgs {
		other := orgs[1-i]
		for _, tc := range []struct {
			name, sql, code string
			args            []any
		}{
			{"foreign user", "INSERT INTO team_memberships VALUES($1,$2,$3)", "23503", []any{org, id, unique[1-i]}},
			{"foreign team", "INSERT INTO team_memberships VALUES($1,$2,$3)", "23503", []any{org, unique[1-i], id}},
			{"duplicate", "INSERT INTO team_memberships VALUES($1,$2,$2)", "23505", []any{org, id}},
			{"move tenant", "UPDATE team_memberships SET org_id=$1 WHERE org_id=$2", "42501", []any{other, org}},
			{"null role", "UPDATE users SET role=NULL WHERE org_id=$1 AND id=$2", "23502", []any{org, id}},
			{"unknown role", "UPDATE users SET role='owner' WHERE org_id=$1 AND id=$2", "23514", []any{org, id}},
			{"role case", "UPDATE users SET role='ADMIN' WHERE org_id=$1 AND id=$2", "23514", []any{org, id}},
			{"empty role", "UPDATE users SET role='' WHERE org_id=$1 AND id=$2", "23514", []any{org, id}},
		} {
			t.Run(org+"/"+tc.name, func(t *testing.T) {
				err := WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, tc.sql, tc.args...)
					return err
				})
				requireSQLState(t, err, tc.code)
			})
		}
		err := WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
			for _, sql := range []string{"UPDATE team_memberships SET user_id=user_id WHERE org_id=$1", "DELETE FROM team_memberships WHERE org_id=$1"} {
				tag, err := tx.Exec(ctx, sql, other)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 0 {
					t.Fatal("cross-tenant mutation succeeded")
				}
			}
			for _, role := range []string{"admin", "writer", "reader"} {
				if _, err := tx.Exec(ctx, "UPDATE users SET role=$1 WHERE org_id=$2 AND id=$3", role, org, id); err != nil {
					return err
				}
			}
			for _, sql := range []string{"UPDATE team_memberships SET user_id=$3 WHERE org_id=$1 AND team_id=$2", "DELETE FROM team_memberships WHERE org_id=$1 AND team_id=$2 AND user_id=$3"} {
				tag, err := tx.Exec(ctx, sql, org, id, unique[i])
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					t.Fatal("own membership mutation failed")
				}
			}
			return rollback
		})
		if !errors.Is(err, rollback) {
			t.Fatalf("expected rollback: %v", err)
		}
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM team_memberships").Scan(&count); err != nil || count != 0 {
			t.Fatalf("tenant context leaked after rollback: count=%d err=%v", count, err)
		}
	}
}
