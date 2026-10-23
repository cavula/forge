package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const loginFlowInsert = `INSERT INTO login_flows
 (id,state_hash,binding_hash,ciphertext,nonce,wrapped_dek,key_id)
 VALUES($1,$2,$3,$4,$5,$6,$7)`

func loginStoragePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL integration")
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var safe bool
	err = pool.QueryRow(context.Background(), `SELECT NOT rolsuper AND NOT rolbypassrls
 AND NOT EXISTS (SELECT FROM pg_tables WHERE schemaname='public' AND tableowner=current_user)
 AND (SELECT count(*)=2 AND bool_and(relrowsecurity AND relforcerowsecurity)
 FROM pg_class WHERE oid IN ('login_flows'::regclass,'auth_security_events'::regclass))
 FROM pg_roles WHERE rolname=current_user`).Scan(&safe)
	if err != nil || !safe {
		t.Fatalf("nonowner runtime and forced RLS required: safe=%v err=%v", safe, err)
	}
	return pool
}

func loginStorageID(t *testing.T) string {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func loginStorageArgs(t *testing.T) []any {
	t.Helper()
	state, binding := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(binding); err != nil {
		t.Fatal(err)
	}
	return []any{loginStorageID(t), state, binding, []byte("cipher"), []byte("123456789012"), []byte("wrapped"), "test-key"}
}

// These are SQL-policy fixtures, not the future production auth transaction helper.
func loginStorageTx(pool *pgxpool.Pool, state, binding string, fn func(pgx.Tx) error) error {
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT set_config('forge.login_state_hash',$1,true),
 set_config('forge.login_binding_hash',$2,true)`, state, binding)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func TestLoginFlowStorageRLS(t *testing.T) {
	ctx := context.Background()
	pool := loginStoragePool(t)
	owner := storageFixtureOwner(t)
	first, second := loginStorageArgs(t), loginStorageArgs(t)
	state, binding := hex.EncodeToString(first[1].([]byte)), hex.EncodeToString(first[2].([]byte))
	orgID := loginStorageID(t)
	if err := WithOrg(ctx, pool, orgID, func(tx pgx.Tx) error {
		for _, sql := range []string{
			"INSERT INTO orgs(id,name) VALUES($1,'flow isolation')",
			"INSERT INTO users(org_id,id,issuer,subject,display_name) VALUES($1,$1,'https://flow.test','subject','test')",
			"INSERT INTO stacks(org_id,id,name) VALUES($1,$1,'flow isolation')",
		} {
			if _, err := tx.Exec(ctx, sql, orgID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := WithOrg(ctx, owner, orgID, func(tx pgx.Tx) error {
			for _, table := range []string{"stacks", "users", "orgs"} {
				column := "org_id"
				if table == "orgs" {
					column = "id"
				}
				if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE "+column+"=$1", orgID); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	for _, args := range [][]any{first, second} {
		s, b := hex.EncodeToString(args[1].([]byte)), hex.EncodeToString(args[2].([]byte))
		err := loginStorageTx(pool, s, b, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, loginFlowInsert, args...); err != nil {
				return err
			}
			var valid bool
			err := tx.QueryRow(ctx, `SELECT created_at=now() AND expires_at=now()+interval '10 minutes'
 FROM login_flows WHERE state_hash=$1 AND binding_hash=$2`, args[1], args[2]).Scan(&valid)
			if err == nil && !valid {
				t.Fatal("flow timestamps must use database time and ten-minute expiry")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := loginStorageTx(pool, s, b, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, "DELETE FROM login_flows WHERE state_hash=$1 AND binding_hash=$2", args[1], args[2])
				return err
			}); err != nil {
				t.Error(err)
			}
		})
	}
	for _, tc := range []struct{ name, state, binding string }{
		{"absent", "", ""}, {"state only", state, ""}, {"binding only", "", binding},
		{"wrong state", strings.Repeat("0", 64), binding}, {"wrong binding", state, strings.Repeat("0", 64)},
		{"uppercase state", strings.ToUpper(state), binding}, {"uppercase binding", state, strings.ToUpper(binding)},
		{"short", state[:63], binding}, {"malformed", "not-a-digest", binding}, {"whitespace", state + " ", binding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := loginStorageTx(pool, tc.state, tc.binding, func(tx pgx.Tx) error {
				var count int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM login_flows").Scan(&count); err != nil {
					return err
				}
				tag, err := tx.Exec(ctx, "DELETE FROM login_flows")
				if err == nil && (count != 0 || tag.RowsAffected() != 0) {
					t.Fatal("incomplete or noncanonical proof exposed a flow")
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			requireSQLState(t, loginStorageTx(pool, tc.state, tc.binding, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, loginFlowInsert, first...)
				return err
			}), "42501")
		})
	}
	rollback := errors.New("retain fixture")
	err := loginStorageTx(pool, state, binding, func(tx pgx.Tx) error {
		var isolated bool
		if err := tx.QueryRow(ctx, `SELECT
 coalesce(current_setting('forge.org_id',true),'')='' AND
 coalesce(current_setting('forge.auth_issuer',true),'')='' AND
 coalesce(current_setting('forge.auth_subject',true),'')='' AND
 (SELECT count(*) FROM orgs)=0 AND (SELECT count(*) FROM users)=0 AND
 (SELECT count(*) FROM stacks)=0`).Scan(&isolated); err != nil {
			return err
		}
		if !isolated {
			t.Fatal("flow proof admitted tenant resources or inherited tenant/principal context")
		}
		var id string
		if err := tx.QueryRow(ctx, "SELECT id FROM login_flows").Scan(&id); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM login_flows").Scan(&count); err != nil {
			return err
		}
		if id != first[0] || count != 1 {
			t.Fatal("matching proof must expose exactly its flow")
		}
		tag, err := tx.Exec(ctx, "DELETE FROM login_flows WHERE state_hash=$1 AND binding_hash=$2", first[1], first[2])
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			t.Fatal("matching flow deletion denied")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM login_flows").Scan(&count); err != nil || count != 0 {
		t.Fatalf("transaction-local proof leaked: count=%d err=%v", count, err)
	}
	err = loginStorageTx(pool, "", "", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT set_config('forge.org_id',$1,true),
 set_config('forge.auth_issuer','https://issuer.test',true),set_config('forge.auth_subject','subject',true),
 set_config('forge.browser_session_hash',$2,true)`, first[0], state)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM login_flows").Scan(&count); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM login_flows")
		if err != nil {
			return err
		}
		if count != 0 || tag.RowsAffected() != 0 {
			t.Fatal("org or principal context granted flow access")
		}
		_, err = tx.Exec(ctx, loginFlowInsert, first...)
		return err
	})
	requireSQLState(t, err, "42501")
	for _, sql := range []string{"UPDATE login_flows SET key_id='changed'", "TRUNCATE login_flows"} {
		_, err := pool.Exec(ctx, sql)
		requireSQLState(t, err, "42501")
	}
}

func TestLoginFlowStorageMetadata(t *testing.T) {
	ctx := context.Background()
	pool := loginStoragePool(t)
	for _, tc := range []struct {
		name   string
		column int
		value  any
	}{
		{"short state", 1, make([]byte, 31)}, {"long binding", 2, make([]byte, 33)},
		{"empty ciphertext", 3, []byte{}}, {"bad nonce", 4, make([]byte, 11)},
		{"empty wrapped DEK", 5, []byte{}}, {"empty key ID", 6, ""}, {"null ciphertext", 3, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := loginStorageArgs(t)
			args[tc.column] = tc.value
			err := loginStorageTx(pool, hex.EncodeToString(args[1].([]byte)), hex.EncodeToString(args[2].([]byte)), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, loginFlowInsert, args...)
				return err
			})
			code := "23514"
			if tc.value == nil {
				code = "23502"
			}
			requireSQLState(t, err, code)
		})
	}
	for _, column := range []string{"created_at", "expires_at"} {
		_, err := pool.Exec(ctx, "INSERT INTO login_flows ("+column+") VALUES(now())")
		requireSQLState(t, err, "42501")
	}
}

func TestAuthSecurityEventStorage(t *testing.T) {
	ctx := context.Background()
	pool := loginStoragePool(t)
	for _, action := range []string{"login_flow.created", "login_flow.consumed"} {
		_, err := pool.Exec(ctx, "INSERT INTO auth_security_events(id,action,outcome) VALUES($1,$2,'success')", loginStorageID(t), action)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]any{{"session.created", "success"}, {"login_flow.created", "failure"}, {"login_flow.created", "provider details"}} {
		_, err := pool.Exec(ctx, "INSERT INTO auth_security_events(id,action,outcome) VALUES($1,$2,$3)", loginStorageID(t), args[0], args[1])
		requireSQLState(t, err, "23514")
	}
	for _, sql := range []string{
		"SELECT * FROM auth_security_events", "UPDATE auth_security_events SET outcome='success'",
		"DELETE FROM auth_security_events", "TRUNCATE auth_security_events",
		"INSERT INTO auth_security_events(occurred_at) VALUES(now())",
	} {
		_, err := pool.Exec(ctx, sql)
		requireSQLState(t, err, "42501")
	}
	var guarded bool
	err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_trigger
 WHERE tgrelid='auth_security_events'::regclass AND NOT tgisinternal
 AND tgfoid='reject_audit_mutation()'::regprocedure AND tgtype=58 AND tgenabled='O')`).Scan(&guarded)
	if err != nil || !guarded {
		t.Fatalf("append-only UPDATE/DELETE/TRUNCATE statement trigger required: guarded=%v err=%v", guarded, err)
	}
}
