package auth

import (
	"context"
	"errors"
	"os"
	"testing"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"github.com/cavula/forge/internal/database"
	"github.com/cavula/forge/internal/testutil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMembershipInputAndRoleFailures(t *testing.T) {
	for _, role := range []string{"", "ADMIN", "owner", "reader ", "unknown"} {
		if membershipRole(role) != forgev1.Role_ROLE_UNSPECIFIED {
			t.Fatal("unknown persisted role granted authority")
		}
	}
	if user, err := ResolveMembership(context.Background(), nil, VerifiedIdentity{}, "invalid"); user != nil || err != errMembership {
		t.Fatal("missing pool or proof did not fail closed")
	}
}

func TestVerifiedMembershipResolution(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL integration")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid integration database configuration")
	}
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("integration database unavailable")
	}
	defer pool.Close()
	var safe bool
	if err := pool.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolbypassrls AND
 NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner=current_user)
 FROM pg_roles WHERE rolname=current_user`).Scan(&safe); err != nil || !safe {
		t.Fatal("non-owner runtime role required")
	}
	if err := pool.QueryRow(ctx, "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='users'::regclass").Scan(&safe); err != nil || !safe {
		t.Fatal("user RLS must remain enabled and forced")
	}
	orgs := []string{"61000000-0000-0000-0000-000000000001", "61000000-0000-0000-0000-000000000002"}
	id, otherID := "62000000-0000-0000-0000-000000000001", "62000000-0000-0000-0000-000000000002"
	principal := VerifiedIdentity{issuer: "https://resolver-a.test", subject: "resolver-subject"}
	other := VerifiedIdentity{issuer: "https://resolver-b.test", subject: principal.subject}
	for _, org := range orgs {
		err = database.WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
			for _, query := range []struct {
				sql  string
				args []any
			}{
				{"INSERT INTO orgs(id,name) VALUES($1,'resolver fixture') ON CONFLICT DO NOTHING", []any{org}},
				{`INSERT INTO users(org_id,id,issuer,subject,display_name,role) VALUES($1,$2,$3,$4,'resolver user','reader')
 ON CONFLICT (org_id,id) DO UPDATE SET role='reader'`, []any{org, id, principal.issuer, principal.subject}},
				{"INSERT INTO stacks(org_id,id,name) VALUES($1,$2,'resolver fixture') ON CONFLICT DO NOTHING", []any{org, id}},
			} {
				if _, err := tx.Exec(ctx, query.sql, query.args...); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal("membership fixtures failed")
		}
	}
	err = database.WithOrg(ctx, pool, orgs[0], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users(org_id,id,issuer,subject,display_name,role)
 VALUES($1,$2,$3,$4,'different issuer','writer') ON CONFLICT (org_id,id) DO UPDATE SET role='writer'`, orgs[0], otherID, other.issuer, other.subject)
		return err
	})
	if err != nil {
		t.Fatal("alternate issuer fixture failed")
	}
	assertReset := func() {
		t.Helper()
		var count int
		var cleared bool
		err := pool.QueryRow(ctx, `SELECT coalesce(current_setting('forge.org_id',true),'')='',
 coalesce(current_setting('forge.auth_issuer',true),'')='' AND coalesce(current_setting('forge.auth_subject',true),'')=''`).Scan(&safe, &cleared)
		if err != nil || !safe || !cleared {
			t.Fatal("resolution context survived transaction")
		}
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil || count != 0 {
			t.Fatal("membership rows visible outside authorized transaction")
		}
	}
	for _, org := range orgs {
		user, err := ResolveMembership(ctx, pool, principal, org)
		if err != nil || user.GetId() != id || user.GetOrgId() != org || user.GetRole() != forgev1.Role_ROLE_READER {
			t.Fatal("verified member could not select its organization")
		}
		assertReset()
	}
	user, err := ResolveMembership(ctx, pool, other, orgs[0])
	if err != nil || user.GetId() != otherID || user.GetRole() != forgev1.Role_ROLE_WRITER {
		t.Fatal("issuer was not part of identity selection")
	}
	for _, tc := range []struct {
		proof VerifiedIdentity
		org   string
	}{
		{VerifiedIdentity{}, orgs[0]}, {VerifiedIdentity{issuer: principal.issuer}, orgs[0]},
		{VerifiedIdentity{subject: principal.subject}, orgs[0]}, {other, orgs[1]},
		{VerifiedIdentity{issuer: "https://wrong.test", subject: principal.subject}, orgs[0]},
		{VerifiedIdentity{issuer: principal.issuer, subject: "wrong-subject"}, orgs[0]},
		{principal, "61000000-0000-0000-0000-000000000003"}, {principal, ""}, {principal, "invalid"},
		{principal, "61000000000000000000000000000001"},
	} {
		member, err := ResolveMembership(ctx, pool, tc.proof, tc.org)
		if member != nil || err != errMembership {
			t.Fatal("invalid identity or organization returned membership")
		}
		testutil.NoSecrets(t, err.Error(), principal.issuer, principal.subject, other.issuer, "wrong-subject")
		assertReset()
	}
	for _, proof := range []VerifiedIdentity{{}, {issuer: principal.issuer}, {subject: principal.subject}} {
		tx, err := beginResolution(ctx, pool, proof)
		if err != nil {
			t.Fatal("incomplete-proof fixture failed")
		}
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil || count != 0 {
			t.Fatal("RLS accepted incomplete identity proof")
		}
		_ = tx.Rollback(ctx)
		assertReset()
	}
	// A stale pooled tenant setting cannot extend resolution visibility. The
	// lookup policy reveals matching principals, not any organization's resources.
	if _, err := pool.Exec(ctx, "SELECT set_config('forge.org_id',$1,false)", orgs[1]); err != nil {
		t.Fatal("ambient tenant fixture failed")
	}
	tx, err := beginResolution(ctx, pool, other)
	if err != nil {
		t.Fatal("resolution transaction failed")
	}
	for table, expected := range map[string]int{"users": 1, "orgs": 0, "stacks": 0, "teams": 0} {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != expected {
			t.Fatal("resolution context exposed unrelated rows")
		}
	}
	_, err = tx.Exec(ctx, "UPDATE users SET role='admin' WHERE org_id=$1 AND id=$2", orgs[0], otherID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "25006" {
		t.Fatal("resolution transaction permitted a write")
	}
	_ = tx.Rollback(ctx)
	if _, err := pool.Exec(ctx, "SELECT set_config('forge.org_id','',false)"); err != nil {
		t.Fatal("ambient tenant cleanup failed")
	}
	assertReset()
	// The SELECT policy must not grant writes even in a read-write transaction.
	for _, query := range []string{
		`INSERT INTO users(org_id,id,issuer,subject,display_name) VALUES($1,'62000000-0000-0000-0000-000000000003',$2,$3,'denied')`,
		"UPDATE users SET role='admin' WHERE org_id=$1 AND issuer=$2 AND subject=$3",
		"DELETE FROM users WHERE org_id=$1 AND issuer=$2 AND subject=$3",
	} {
		func() {
			tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadWrite})
			if err != nil {
				t.Fatal("write-policy fixture failed")
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := tx.Exec(ctx, `SELECT set_config('forge.org_id','',true),
 set_config('forge.auth_issuer',$1,true),set_config('forge.auth_subject',$2,true)`, principal.issuer, principal.subject); err != nil {
				t.Fatal("write-policy identity context failed")
			}
			var visible int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM users WHERE org_id=$1 AND issuer=$2 AND subject=$3", orgs[0], principal.issuer, principal.subject).Scan(&visible); err != nil || visible != 1 {
				t.Fatal("SELECT policy did not expose its matching membership")
			}
			tag, err := tx.Exec(ctx, query, orgs[0], principal.issuer, principal.subject)
			if query[0] == 'I' {
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
					t.Fatal("identity proof permitted an insert")
				}
			} else if err != nil || tag.RowsAffected() != 0 {
				t.Fatal("identity proof permitted a membership mutation")
			}
		}()
		assertReset()
	}
	// Cancellation during resolution must release context even when the request
	// context can no longer be used for cleanup.
	canceled, cancel := context.WithCancel(ctx)
	tx, err = beginResolution(canceled, pool, principal)
	if err != nil {
		t.Fatal("cancellation fixture failed")
	}
	cancel()
	_, _ = tx.Exec(canceled, "SELECT 1")
	_ = tx.Rollback(context.WithoutCancel(canceled))
	assertReset()
	if member, err := ResolveMembership(canceled, pool, principal, orgs[0]); member != nil || err != errMembership {
		t.Fatal("canceled resolution returned membership")
	}
	assertReset()
	for _, role := range []string{"admin", "writer", "reader"} {
		err = database.WithOrg(ctx, pool, orgs[0], func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "UPDATE users SET role=$1 WHERE org_id=$2 AND id=$3", role, orgs[0], id)
			return err
		})
		if err != nil {
			t.Fatal("role change failed")
		}
		member, err := ResolveMembership(ctx, pool, principal, orgs[0])
		if err != nil || member.GetRole() != membershipRole(role) {
			t.Fatal("resolution retained a stale role")
		}
	}
	err = database.WithOrg(ctx, pool, orgs[0], func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "DELETE FROM users WHERE org_id=$1 AND id=$2", orgs[0], id)
		return err
	})
	if err != nil {
		t.Fatal("membership deletion failed")
	}
	if member, err := ResolveMembership(ctx, pool, principal, orgs[0]); member != nil || err != errMembership {
		t.Fatal("deleted membership retained authority")
	}
	assertReset()
	pool.Close()
	if member, err := ResolveMembership(ctx, pool, principal, orgs[1]); member != nil || err != errMembership {
		t.Fatal("database failure exposed authority or diagnostics")
	}
}
