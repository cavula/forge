package database

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const browserSessionInsert = `INSERT INTO browser_sessions
 (id,credential_hash,issuer,subject,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6)`

func browserStoragePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := loginStoragePool(t)
	var safe bool
	err := pool.QueryRow(context.Background(), `SELECT relrowsecurity AND relforcerowsecurity
 AND pg_get_userbyid(relowner)<>current_user FROM pg_class
 WHERE oid='browser_sessions'::regclass`).Scan(&safe)
	if err != nil || !safe {
		t.Fatalf("nonowner session FORCE RLS required: safe=%v err=%v", safe, err)
	}
	return pool
}

func browserStorageArgs(t *testing.T) []any {
	t.Helper()
	flow := loginStorageArgs(t)
	return []any{flow[0], flow[1], "https://session.test", "verified-subject", flow[2], time.Now().UTC().Add(time.Hour)}
}

// SQL-policy fixture only; future production helpers must independently clear contexts.
func browserStorageTx(pool *pgxpool.Pool, hash string, fn func(pgx.Tx) error) error {
	return loginStorageTx(pool, "", "", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `SELECT set_config('forge.org_id','',true),
 set_config('forge.auth_issuer','',true),set_config('forge.auth_subject','',true),
 set_config('forge.browser_session_hash',$1,true)`, hash)
		if err != nil {
			return err
		}
		return fn(tx)
	})
}

func browserStorageReset(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var reset bool
	err := pool.QueryRow(context.Background(), `SELECT
 coalesce(current_setting('forge.browser_session_hash',true),'')=''
 AND coalesce(current_setting('forge.login_state_hash',true),'')=''
 AND coalesce(current_setting('forge.login_binding_hash',true),'')=''
 AND coalesce(current_setting('forge.org_id',true),'')=''
 AND coalesce(current_setting('forge.auth_issuer',true),'')=''
 AND coalesce(current_setting('forge.auth_subject',true),'')=''
 AND (SELECT count(*) FROM browser_sessions)=0`).Scan(&reset)
	if err != nil || !reset {
		t.Fatalf("pooled context leaked: reset=%v err=%v", reset, err)
	}
}

func TestBrowserSessionStorageRLS(t *testing.T) {
	ctx := context.Background()
	pool := browserStoragePool(t)
	first, second, flow := browserStorageArgs(t), browserStorageArgs(t), loginStorageArgs(t)
	hash := hex.EncodeToString(first[1].([]byte))
	org := loginStorageID(t)
	if err := WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
		for _, sql := range []string{"INSERT INTO orgs(id,name) VALUES($1,'session fixture')",
			"INSERT INTO users(org_id,id,issuer,subject,display_name) VALUES($1,$1,'https://session.test','verified-subject','fixture')",
			"INSERT INTO stacks(org_id,id,name) VALUES($1,$1,'session fixture')"} {
			if _, err := tx.Exec(ctx, sql, org); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
			for _, sql := range []string{"DELETE FROM stacks WHERE org_id=$1", "DELETE FROM users WHERE org_id=$1", "DELETE FROM orgs WHERE id=$1"} {
				if _, err := tx.Exec(ctx, sql, org); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	s, b := hex.EncodeToString(flow[1].([]byte)), hex.EncodeToString(flow[2].([]byte))
	if err := loginStorageTx(pool, s, b, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, loginFlowInsert, flow...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := loginStorageTx(pool, s, b, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "DELETE FROM login_flows WHERE state_hash=$1 AND binding_hash=$2", flow[1], flow[2])
			return err
		}); err != nil {
			t.Error(err)
		}
	})
	for _, args := range [][]any{first, second} {
		h := hex.EncodeToString(args[1].([]byte))
		if err := browserStorageTx(pool, h, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, browserSessionInsert, args...); err != nil {
				return err
			}
			var valid bool
			err := tx.QueryRow(ctx, `SELECT created_at=now() AND expires_at=$2
 FROM browser_sessions WHERE credential_hash=$1`, args[1], args[5]).Scan(&valid)
			if err == nil && !valid {
				t.Fatal("database creation time or server expiry changed")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		browserStorageReset(t, pool)
		t.Cleanup(func() {
			if err := browserStorageTx(pool, h, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, "DELETE FROM browser_sessions WHERE credential_hash=$1", args[1])
				return err
			}); err != nil {
				t.Error(err)
			}
		})
	}
	for _, proof := range []string{"", strings.Repeat("0", 64), strings.ToUpper(hash), hash[:63], "not-hex", hash + " ", "\\x" + hash} {
		err := browserStorageTx(pool, proof, func(tx pgx.Tx) error {
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM browser_sessions").Scan(&count); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, "DELETE FROM browser_sessions")
			if err == nil && (count != 0 || tag.RowsAffected() != 0) {
				t.Fatal("absent/wrong/noncanonical credential context exposed a session")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		requireSQLState(t, browserStorageTx(pool, proof, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, browserSessionInsert, first...)
			return err
		}), "42501")
	}
	rollback := errors.New("rollback policy fixture")
	err := browserStorageTx(pool, hash, func(tx pgx.Tx) error {
		var isolated bool
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM browser_sessions)=1
 AND (SELECT count(*) FROM orgs)=0 AND (SELECT count(*) FROM users)=0
 AND (SELECT count(*) FROM stacks)=0 AND (SELECT count(*) FROM login_flows)=0`).Scan(&isolated); err != nil {
			return err
		}
		if !isolated {
			t.Fatal("session proof exposed another session, tenant resource or login flow")
		}
		tag, err := tx.Exec(ctx, "DELETE FROM browser_sessions WHERE credential_hash=$1 AND expires_at>now()", first[1])
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatal("matching session deletion denied")
		}
		if err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	browserStorageReset(t, pool)
	err = browserStorageTx(pool, "", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT set_config('forge.org_id',$1,true),
 set_config('forge.auth_issuer','https://session.test',true),set_config('forge.auth_subject','verified-subject',true),
 set_config('forge.login_state_hash',$2,true),set_config('forge.login_binding_hash',$3,true)`, org, s, b)
		if err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM browser_sessions").Scan(&count); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM browser_sessions")
		if err == nil && (count != 0 || tag.RowsAffected() != 0) {
			t.Fatal("tenant/principal/flow context granted session access")
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, browserSessionInsert, first...)
		return err
	})
	requireSQLState(t, err, "42501")
	browserStorageReset(t, pool)
	cancelCtx, cancel := context.WithCancel(ctx)
	tx, err := pool.Begin(cancelCtx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(cancelCtx, "SELECT set_config('forge.browser_session_hash',$1,true)", hash); err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = tx.Exec(cancelCtx, "SELECT 1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not observed: %v", err)
	}
	_ = tx.Rollback(ctx)
	browserStorageReset(t, pool)
	for _, sql := range []string{"UPDATE browser_sessions SET subject='changed'", "TRUNCATE browser_sessions",
		"INSERT INTO browser_sessions(created_at) VALUES(now())"} {
		_, err := pool.Exec(ctx, sql)
		requireSQLState(t, err, "42501")
	}
}

func TestBrowserSessionStorageConstraints(t *testing.T) {
	ctx := context.Background()
	pool := browserStoragePool(t)
	for _, tc := range []struct {
		name   string
		column int
		value  any
		code   string
	}{
		{"short credential", 1, make([]byte, 31), "23514"}, {"long credential", 1, make([]byte, 33), "23514"},
		{"short CSRF", 4, make([]byte, 31), "23514"}, {"long CSRF", 4, make([]byte, 33), "23514"},
		{"empty issuer", 2, "", "23514"}, {"empty subject", 3, "", "23514"},
		{"null issuer", 2, nil, "23502"}, {"null CSRF", 4, nil, "23502"}, {"missing expiry", 5, nil, "23502"},
		{"past expiry", 5, time.Now().Add(-time.Hour), "23514"}, {"too late", 5, time.Now().Add(9 * time.Hour), "23514"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := browserStorageArgs(t)
			args[tc.column] = tc.value
			requireSQLState(t, browserStorageTx(pool, hex.EncodeToString(args[1].([]byte)), func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, browserSessionInsert, args...)
				return err
			}), tc.code)
		})
	}
	args := browserStorageArgs(t)
	hash := hex.EncodeToString(args[1].([]byte))
	err := browserStorageTx(pool, hash, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, browserSessionInsert, args...); err != nil {
			return err
		}
		args[0] = loginStorageID(t)
		_, err := tx.Exec(ctx, browserSessionInsert, args...)
		return err
	})
	requireSQLState(t, err, "23505")
	for _, bound := range []string{"now()", "now()+interval '8 hours 1 microsecond'"} {
		requireSQLState(t, browserStorageTx(pool, hash, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, strings.Replace(browserSessionInsert, "$6)", bound+")", 1), args[:5]...)
			return err
		}), "23514")
	}
	rollback := errors.New("constraint fixture")
	err = browserStorageTx(pool, hash, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, strings.Replace(browserSessionInsert, "$6)", "now()+interval '8 hours')", 1), args[:5]...)
		if err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	var columns string
	err = pool.QueryRow(ctx, `SELECT string_agg(column_name,',' ORDER BY ordinal_position)
 FROM information_schema.columns WHERE table_schema='public' AND table_name='browser_sessions'`).Scan(&columns)
	if err != nil || columns != "id,credential_hash,issuer,subject,csrf_hash,created_at,expires_at" {
		t.Fatalf("unexpected persisted session metadata: columns=%s err=%v", columns, err)
	}
}

func TestBrowserSessionEventStorage(t *testing.T) {
	ctx := context.Background()
	pool := browserStoragePool(t)
	rollback := errors.New("event fixture")
	for _, action := range []string{"login_flow.created", "login_flow.consumed", "browser_session.created", "browser_session.revoked", "browser_session.replaced"} {
		err := browserStorageTx(pool, "", func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "INSERT INTO auth_security_events(id,action,outcome) VALUES($1,$2,'success')", loginStorageID(t), action); err != nil {
				return err
			}
			return rollback
		})
		if !errors.Is(err, rollback) {
			t.Fatal(err)
		}
	}
	for _, args := range [][]any{{"browser_session.failed", "success"}, {"browser_session.created", "failure"}} {
		_, err := pool.Exec(ctx, "INSERT INTO auth_security_events(id,action,outcome) VALUES($1,$2,$3)", loginStorageID(t), args[0], args[1])
		requireSQLState(t, err, "23514")
	}
	var narrow bool
	err := pool.QueryRow(ctx, `SELECT has_column_privilege(current_user,'auth_security_events','id','INSERT')
 AND has_column_privilege(current_user,'auth_security_events','action','INSERT')
 AND has_column_privilege(current_user,'auth_security_events','outcome','INSERT')
 AND NOT has_column_privilege(current_user,'auth_security_events','occurred_at','INSERT')
 AND NOT has_table_privilege(current_user,'auth_security_events','SELECT,UPDATE,DELETE,TRUNCATE')`).Scan(&narrow)
	if err != nil || !narrow {
		t.Fatalf("event privileges widened: narrow=%v err=%v", narrow, err)
	}
	ownerURL := os.Getenv("DATABASE_URL")
	if ownerURL == "" {
		t.Fatal("DATABASE_URL migration owner required for actual owner append-only proof")
	}
	owner, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close(ctx) }()
	var owns bool
	err = owner.QueryRow(ctx, `SELECT pg_get_userbyid(relowner)=current_user
 FROM pg_class WHERE oid='auth_security_events'::regclass`).Scan(&owns)
	if err != nil || !owns {
		t.Fatalf("append-only proof requires actual migration owner: owns=%v err=%v", owns, err)
	}
	for _, sql := range []string{"UPDATE auth_security_events SET outcome='success'", "DELETE FROM auth_security_events", "TRUNCATE auth_security_events"} {
		_, err := owner.Exec(ctx, sql)
		requireSQLState(t, err, "P0001")
	}
}
