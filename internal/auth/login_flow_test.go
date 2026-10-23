package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavula/forge/internal/database"
	"github.com/cavula/forge/internal/secrets"
	"github.com/cavula/forge/internal/testutil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func flowPool(t *testing.T, url string, max int32) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid database fixture")
	}
	config.MaxConns = max
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal("database fixture unavailable")
	}
	t.Cleanup(pool.Close)
	return pool
}

// Each test owns its database so concurrent packages cannot change audit counts.
func flowDatabase(t *testing.T, runtimeURL, ownerURL string) (string, string) {
	t.Helper()
	ctx := context.Background()
	admin := flowPool(t, ownerURL, 1)
	id, err := loginFlowUUID()
	if err != nil {
		t.Fatal(err)
	}
	name := "forge_flow_" + strings.ReplaceAll(id, "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("isolated fixture creation failed")
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("isolated fixture cleanup failed")
		}
	})
	urls := make([]string, 2)
	for i, raw := range []string{runtimeURL, ownerURL} {
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
			t.Fatal("invalid database fixture URL")
		}
		parsed.Path = "/" + name
		urls[i] = parsed.String()
	}
	config := admin.Config().ConnConfig.Copy()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	migrations, _ := fs.Sub(database.Migrations, "migrations")
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations)
	if err != nil {
		t.Fatal("isolated fixture migrator failed")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("isolated fixture migration failed")
	}
	return urls[0], urls[1]
}

func flowKey(t *testing.T, id string, material byte) *secrets.AuthFlowKey {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := dir + "/auth-key"
	if err := os.WriteFile(path, bytes.Repeat([]byte{material}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	local, err := secrets.LoadLocalKeyFile(id, path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := secrets.NewAuthFlowKey(local)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestLoginFlowRedactionAndInputs(t *testing.T) {
	value := LoginFlowValue{strings.Repeat("credential", 8)}
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("fixture", "credential", value)
	encoded, _ := json.Marshal(LoginFlowStart{value, value, value, value})
	text, _ := value.MarshalText()
	testutil.NoSecrets(t, fmt.Sprintf("%v %+v %#v %s %q", value, value, value, value, value)+value.GoString()+string(encoded)+string(text)+log.String(), value.Reveal())
	for _, invalid := range []string{"", strings.Repeat("A", 42), strings.Repeat("A", 42) + "B", strings.Repeat("A", 43) + "=", strings.Repeat("A", 42) + "\n"} {
		if _, ok := loginFlowDigest(invalid); ok {
			t.Fatal("noncanonical proof accepted")
		}
	}
	if store, err := NewLoginFlowStore(nil, flowKey(t, "input", 37)); store != nil || err != ErrLoginFlow {
		t.Fatal("nil pool accepted")
	}
	if store, err := NewLoginFlowStore(&pgxpool.Pool{}, nil); store != nil || err != ErrLoginFlow {
		t.Fatal("nil key accepted")
	}
	invalidKey, _ := NewLoginFlowStore(&pgxpool.Pool{}, &secrets.AuthFlowKey{})
	if result, err := invalidKey.Create(context.Background()); result != nil || err != ErrLoginFlow {
		t.Fatal("invalid key returned credentials")
	}
	var store *LoginFlowStore
	if result, err := store.Create(context.Background()); result != nil || err != ErrLoginFlow {
		t.Fatal("nil store accepted")
	}
}

func TestLoginFlowPostgres(t *testing.T) {
	url, ownerURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("DATABASE_URL")
	if url == "" || ownerURL == "" {
		t.Skip("disposable PostgreSQL runtime and owner fixture required")
	}
	url, ownerURL = flowDatabase(t, url, ownerURL)
	ctx := context.Background()
	pool, owner := flowPool(t, url, 1), flowPool(t, ownerURL, 1)
	key := flowKey(t, "login-flow-fixture", 37)
	store, _ := NewLoginFlowStore(pool, key)
	exec := func(p *pgxpool.Pool, sql string, args ...any) {
		t.Helper()
		if _, err := p.Exec(ctx, sql, args...); err != nil {
			t.Fatal("fixture SQL failed")
		}
	}
	var safe bool
	err := pool.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolbypassrls AND
 NOT EXISTS(SELECT FROM pg_tables WHERE schemaname='public' AND tableowner=current_user)
 AND (SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM pg_class
 WHERE oid IN ('login_flows'::regclass,'auth_security_events'::regclass))
 FROM pg_roles WHERE rolname=current_user`).Scan(&safe)
	if err != nil || !safe {
		t.Fatal("non-owner runtime with forced RLS required")
	}
	// Owner-only policies and conditional faults exist solely in this disposable
	// fixture. The runtime keeps its original restricted grants and policies.
	for _, table := range []string{"login_flows", "auth_security_events"} {
		exec(owner, "CREATE POLICY flow_fixture_owner ON "+table+" TO forge_owner USING(true) WITH CHECK(true)")
		t.Cleanup(func() { exec(owner, "DROP POLICY flow_fixture_owner ON "+table) })
	}
	exec(owner, `CREATE FUNCTION flow_fixture_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.action=current_setting('forge.test_event_fault',true) THEN RAISE EXCEPTION 'fixture fault'; END IF;
 IF current_setting('forge.test_event_fault',true)='cancel' THEN PERFORM pg_sleep(10); END IF;
 RETURN NEW; END $$`)
	exec(owner, "CREATE TRIGGER flow_fixture_fault BEFORE INSERT ON auth_security_events FOR EACH ROW EXECUTE FUNCTION flow_fixture_fault()")
	t.Cleanup(func() {
		exec(owner, "DROP TRIGGER flow_fixture_fault ON auth_security_events")
		exec(owner, "DROP FUNCTION flow_fixture_fault()")
	})
	count := func(table string) int {
		t.Helper()
		var n int
		if owner.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n) != nil {
			t.Fatal("fixture count failed")
		}
		return n
	}
	reset := func() {
		t.Helper()
		var clean bool
		if pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM unnest(ARRAY[
 'forge.org_id','forge.auth_issuer','forge.auth_subject','forge.browser_session_hash',
 'forge.login_state_hash','forge.login_binding_hash']) s WHERE coalesce(current_setting(s,true),'')<>'')
 AND (SELECT count(*) FROM login_flows)=0 AND (SELECT count(*) FROM users)=0`).Scan(&clean) != nil || !clean {
			t.Fatal("pooled authority survived transaction")
		}
	}
	create := func() *LoginFlowStart {
		t.Helper()
		result, err := store.Create(ctx)
		if err != nil || result == nil {
			t.Fatal("flow creation failed")
		}
		reset()
		return result
	}
	t.Run("creation stores encrypted credentials and one event", func(t *testing.T) {
		flows, events := count("login_flows"), count("auth_security_events")
		start := create()
		state, _ := loginFlowDigest(start.State.Reveal())
		binding, _ := loginFlowDigest(start.Binding.Reveal())
		tx, err := store.begin(ctx, state, binding)
		if err != nil {
			t.Fatal(err)
		}
		var row, id string
		var expiry bool
		var envelope secrets.Envelope
		err = tx.QueryRow(ctx, `SELECT row_to_json(login_flows)::text,
 expires_at=created_at+interval '10 minutes',id::text,ciphertext,nonce,wrapped_dek,key_id
 FROM login_flows WHERE state_hash=$1 AND binding_hash=$2`, state, binding).
			Scan(&row, &expiry, &id, &envelope.Ciphertext, &envelope.Nonce, &envelope.WrappedDEK, &envelope.KeyID)
		_ = tx.Commit(ctx)
		if err != nil || !expiry {
			t.Fatal("database expiry or stored row invalid")
		}
		plaintext, err := key.Open(secrets.AuthFlowContext{FlowID: id, Version: 1}, envelope)
		if err != nil {
			t.Fatal("stored payload did not authenticate")
		}
		var payload loginFlowPayload
		if json.Unmarshal(plaintext, &payload) != nil {
			t.Fatal("stored payload invalid")
		}
		challenge := sha256.Sum256([]byte(payload.Verifier))
		if payload.Nonce != start.Nonce.Reveal() || base64.RawURLEncoding.EncodeToString(challenge[:]) != start.PKCEChallenge.Reveal() {
			t.Fatal("outbound nonce or PKCE did not match encrypted payload")
		}
		seen := map[string]bool{}
		for _, value := range []string{start.State.Reveal(), start.Binding.Reveal(), start.Nonce.Reveal(), payload.Verifier} {
			if _, valid := loginFlowDigest(value); !valid || seen[value] {
				t.Fatal("credentials not canonical and independent")
			}
			seen[value] = true
			testutil.NoSecrets(t, row, value)
		}
		if count("login_flows") != flows+1 || count("auth_security_events") != events+1 {
			t.Fatal("creation event not atomic with flow insertion")
		}
		exec(owner, "DELETE FROM login_flows WHERE id=$1", id)
		reset()
	})
	t.Run("creation event failure rolls back; cancellation resets pool", func(t *testing.T) {
		flows, events := count("login_flows"), count("auth_security_events")
		exec(pool, "SELECT set_config('forge.test_event_fault','login_flow.created',false)")
		if result, err := store.Create(ctx); result != nil || err != ErrLoginFlow {
			t.Fatal("creation event failure exposed credentials")
		}
		exec(pool, "RESET forge.test_event_fault")
		reset()
		if count("login_flows") != flows || count("auth_security_events") != events {
			t.Fatal("creation failure partially committed")
		}
		exec(pool, "SELECT set_config('forge.test_event_fault','cancel',false)")
		canceled, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
		if result, err := store.Create(canceled); result != nil || err != ErrLoginFlow {
			t.Fatal("canceled transaction returned credentials")
		}
		exec(pool, "RESET forge.test_event_fault")
		reset()
		if count("login_flows") != flows || count("auth_security_events") != events {
			t.Fatal("canceled creation partially committed")
		}
	})
	t.Run("flow authority clears inherited tenant and principal contexts", func(t *testing.T) {
		id, _ := loginFlowUUID()
		err := database.WithOrg(ctx, pool, id, func(tx pgx.Tx) error {
			for _, sql := range []string{"INSERT INTO orgs(id,name) VALUES($1,'flow fixture')", "INSERT INTO users(org_id,id,issuer,subject,display_name) VALUES($1,$1,'https://flow.test','subject','fixture')", "INSERT INTO stacks(org_id,id,name) VALUES($1,$1,'flow fixture')"} {
				if _, err := tx.Exec(ctx, sql, id); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal("tenant fixture failed")
		}
		start := create()
		state, _ := loginFlowDigest(start.State.Reveal())
		binding, _ := loginFlowDigest(start.Binding.Reveal())
		exec(pool, `SELECT set_config('forge.org_id',$1,false),set_config('forge.auth_issuer','https://flow.test',false),set_config('forge.auth_subject','subject',false),set_config('forge.browser_session_hash','stale',false),set_config('forge.login_state_hash','stale',false),set_config('forge.login_binding_hash','stale',false)`, id)
		for _, rollback := range []bool{false, true} {
			tx, err := store.begin(ctx, state, binding)
			if err != nil {
				t.Fatal(err)
			}
			var isolated bool
			err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM orgs)=0 AND (SELECT count(*) FROM users)=0 AND (SELECT count(*) FROM stacks)=0 AND current_setting('forge.org_id')='' AND current_setting('forge.auth_issuer')='' AND current_setting('forge.auth_subject')='' AND current_setting('forge.browser_session_hash')=''`).Scan(&isolated)
			if err != nil || !isolated {
				t.Fatal("flow context exposed tenant authority")
			}
			if rollback {
				_ = tx.Rollback(ctx)
			} else {
				_ = tx.Commit(ctx)
			}
		}
		exec(pool, "RESET ALL")
		reset()
		exec(owner, "DELETE FROM login_flows WHERE state_hash=$1", state)
		if database.WithOrg(ctx, pool, id, func(tx pgx.Tx) error {
			for _, table := range []string{"stacks", "users", "orgs"} {
				column := "org_id"
				if table == "orgs" {
					column = "id"
				}
				if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE "+column+"=$1", id); err != nil {
					return err
				}
			}
			return nil
		}) != nil {
			t.Fatal("tenant fixture cleanup failed")
		}
	})
	t.Run("database acquisition failure returns no partial credentials", func(t *testing.T) {
		closed := flowPool(t, url, 1)
		closed.Close()
		unavailable, _ := NewLoginFlowStore(closed, key)
		if result, err := unavailable.Create(ctx); result != nil || err != ErrLoginFlow {
			t.Fatal("closed pool returned outbound credentials")
		}

	})
}
