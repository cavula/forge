package auth

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"github.com/cavula/forge/internal/database"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestWithMembershipInputFailures(t *testing.T) {
	called := false
	op := func(pgx.Tx, *forgev1.User) error { called = true; return nil }
	for _, action := range []Action{ReadMetadata, WriteResource, ManageIdentity, "", "state.write"} {
		if WithMembership(context.Background(), nil, VerifiedIdentity{}, "invalid", action, op) != errMembership {
			t.Fatal("invalid authorization input accepted")
		}
	}
	if WithMembership(context.Background(), nil, VerifiedIdentity{}, "", ReadMetadata, nil) != errMembership || called {
		t.Fatal("invalid callback invoked")
	}
}

func TestWithMembershipTransactions(t *testing.T) {
	runtimeURL, ownerURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("DATABASE_URL")
	if runtimeURL == "" || ownerURL == "" {
		t.Skip("TEST_DATABASE_URL and DATABASE_URL required for PostgreSQL integration")
	}
	runtimeURL, _ = flowDatabase(t, runtimeURL, ownerURL)
	pool := flowPool(t, runtimeURL, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const org = "74000000-0000-0000-0000-000000000001"
	const foreign = "74000000-0000-0000-0000-000000000002"
	const userID = "75000000-0000-0000-0000-000000000001"
	proof := VerifiedIdentity{issuer: "https://operation.test", subject: "member"}
	var safe bool
	if err := pool.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolbypassrls AND
 NOT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner=current_user)
 AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='users'::regclass)
 FROM pg_roles WHERE rolname=current_user`).Scan(&safe); err != nil || !safe {
		t.Fatal("non-owner forced-RLS runtime required")
	}
	for _, id := range []string{org, foreign} {
		if err := database.WithOrg(ctx, pool, id, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "INSERT INTO orgs(id,name) VALUES($1,'authorization fixture')", id)
			return err
		}); err != nil {
			t.Fatal("organization fixture unavailable")
		}
	}
	resetMember := func(role string) {
		t.Helper()
		if err := database.WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO users(org_id,id,issuer,subject,display_name,role)
 VALUES($1,$2,$3,$4,'member',$5) ON CONFLICT(org_id,id) DO UPDATE SET role=EXCLUDED.role`,
				org, userID, proof.issuer, proof.subject, role)
			return err
		}); err != nil {
			t.Fatal("membership fixture unavailable")
		}
	}
	checkReset := func() {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count); err != nil || count != 0 {
			t.Fatal("membership authority survived transaction")
		}
	}
	for _, tc := range []struct {
		role    string
		action  Action
		allowed bool
	}{{"reader", ReadMetadata, true}, {"reader", WriteResource, false}, {"writer", WriteResource, true},
		{"writer", ManageIdentity, false}, {"admin", ManageIdentity, true}} {
		resetMember(tc.role)
		called := false
		err := WithMembership(ctx, pool, proof, org, tc.action, func(tx pgx.Tx, current *forgev1.User) error {
			called = true
			if current.Id != userID || current.OrgId != org || !Allows(current.Role, tc.action) {
				t.Error("operation received wrong current membership")
			}
			var other int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM orgs WHERE id=$1", foreign).Scan(&other); err != nil || other != 0 {
				t.Error("operation crossed tenant boundary")
			}
			return nil
		})
		if called != tc.allowed || (err == nil) != tc.allowed {
			t.Fatal("current-role policy mismatch")
		}
		checkReset()
	}
	for _, identity := range []VerifiedIdentity{{}, {issuer: proof.issuer, subject: "wrong"}, {issuer: "https://wrong.test", subject: proof.subject}} {
		if WithMembership(ctx, pool, identity, org, ReadMetadata, func(pgx.Tx, *forgev1.User) error {
			t.Error("unverified/nonmember callback invoked")
			return nil
		}) != errMembership {
			t.Fatal("nonmember accepted")
		}
	}
	if WithMembership(ctx, pool, proof, foreign, ReadMetadata, func(pgx.Tx, *forgev1.User) error {
		t.Error("foreign callback invoked")
		return nil
	}) != errMembership {
		t.Fatal("foreign membership accepted")
	}
	resetMember("writer")
	failure := errors.New("operation declined")
	if err := WithMembership(ctx, pool, proof, org, WriteResource, func(tx pgx.Tx, _ *forgev1.User) error {
		if _, err := tx.Exec(ctx, "UPDATE orgs SET name='rolled back' WHERE id=$1", org); err != nil {
			return err
		}
		return failure
	}); err != failure {
		t.Fatal("callback error lost")
	}
	if err := WithMembership(ctx, pool, proof, org, ReadMetadata, func(tx pgx.Tx, _ *forgev1.User) error {
		var name string
		if err := tx.QueryRow(ctx, "SELECT name FROM orgs WHERE id=$1", org).Scan(&name); err != nil || name != "authorization fixture" {
			t.Error("failed operation committed")
		}
		return nil
	}); err != nil {
		t.Fatal("rollback verification failed")
	}

	for _, query := range []string{"UPDATE users SET role='reader' WHERE org_id=$1 AND id=$2", "DELETE FROM users WHERE org_id=$1 AND id=$2"} {
		resetMember("writer")
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- WithMembership(ctx, pool, proof, org, WriteResource, func(pgx.Tx, *forgev1.User) error {
				close(entered)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("authorization did not enter operation")
		}
		err := database.WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='100ms'"); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, query, org, userID)
			return err
		})
		close(release)
		if guardErr := <-done; guardErr != nil {
			t.Fatal("guarded operation failed")
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
			t.Fatal("membership mutation bypassed FOR SHARE")
		}
		if err := database.WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, query, org, userID)
			return err
		}); err != nil {
			t.Fatal("membership remained locked after commit")
		}
		if WithMembership(ctx, pool, proof, org, WriteResource, func(pgx.Tx, *forgev1.User) error {
			t.Error("demoted/deleted callback invoked")
			return nil
		}) != errMembership {
			t.Fatal("revoked authority persisted")
		}
	}

	// Pause the second acquisition after resolution, then commit a demotion.
	// The in-operation row lock must read the new role rather than the snapshot.
	resetMember("writer")
	config, err := pgxpool.ParseConfig(runtimeURL)
	if err != nil {
		t.Fatal("guard pool configuration unavailable")
	}
	var acquisitions atomic.Int32
	resolved, proceed := make(chan struct{}), make(chan struct{})
	config.BeforeAcquire = func(ctx context.Context, _ *pgx.Conn) bool {
		if acquisitions.Add(1) == 2 {
			close(resolved)
			select {
			case <-proceed:
			case <-ctx.Done():
				return false
			}
		}
		return true
	}
	guardPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("guard pool unavailable")
	}
	defer guardPool.Close()
	done := make(chan error, 1)
	go func() {
		done <- WithMembership(ctx, guardPool, proof, org, WriteResource, func(pgx.Tx, *forgev1.User) error {
			t.Error("stale role authorized operation")
			return nil
		})
	}()
	select {
	case <-resolved:
	case <-ctx.Done():
		t.Fatal("resolution barrier unavailable")
	}
	resetMember("reader")
	close(proceed)
	if <-done != errMembership {
		t.Fatal("resolution role reused after demotion")
	}
	checkReset()
}
