package auth

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/cavula/forge/internal/database"
	"github.com/cavula/forge/internal/testutil"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBrowserSessionRejectsMissingProofAndPool(t *testing.T) {
	if store, err := NewBrowserSessionStore(nil); store != nil || err != ErrBrowserSession {
		t.Fatal("nil pool accepted")
	}
	for _, store := range []*BrowserSessionStore{nil, {}, {pool: &pgxpool.Pool{}}} {
		for _, proof := range []VerifiedIdentity{{}, {issuer: "https://session.test"}, {subject: "subject"}, {issuer: "https://session.test", subject: "subject"}} {
			if result, err := store.Create(context.Background(), proof); result != nil || err != ErrBrowserSession {
				t.Fatal("fabricated proof returned credentials")
			}
		}
	}
}

func TestBrowserSessionCreatePostgres(t *testing.T) {
	runtimeURL, ownerURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("DATABASE_URL")
	if runtimeURL == "" || ownerURL == "" {
		t.Skip("disposable PostgreSQL runtime and owner fixture required")
	}
	runtimeURL, ownerURL = flowDatabase(t, runtimeURL, ownerURL)
	ctx := context.Background()
	pool, owner := flowPool(t, runtimeURL, 1), flowPool(t, ownerURL, 1)
	store, _ := NewBrowserSessionStore(pool)
	exec := func(p *pgxpool.Pool, sql string, args ...any) {
		t.Helper()
		if _, err := p.Exec(ctx, sql, args...); err != nil {
			t.Fatal("session fixture SQL failed")
		}
	}
	var safe bool
	err := pool.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolbypassrls AND
 NOT EXISTS(SELECT FROM pg_tables WHERE schemaname='public' AND tableowner=current_user)
 AND (SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM pg_class
 WHERE oid IN ('browser_sessions'::regclass,'auth_security_events'::regclass))
 FROM pg_roles WHERE rolname=current_user`).Scan(&safe)
	if err != nil || !safe {
		t.Fatal("non-owner runtime with forced RLS required")
	}
	for _, table := range []string{"browser_sessions", "auth_security_events"} {
		exec(owner, "CREATE POLICY session_fixture_owner ON "+table+" FOR SELECT TO forge_owner USING(true)")
	}
	exec(owner, `CREATE FUNCTION session_fixture_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.action='browser_session.created' THEN
  IF current_setting('forge.test_session_fault',true)='reject' THEN RAISE EXCEPTION 'fixture fault'; END IF;
  IF current_setting('forge.test_session_fault',true)='cancel' THEN PERFORM pg_sleep(10); END IF;
 END IF; RETURN NEW; END $$`)
	exec(owner, "CREATE TRIGGER session_fixture_fault BEFORE INSERT ON auth_security_events FOR EACH ROW EXECUTE FUNCTION session_fixture_fault()")
	count := func(table string) int {
		t.Helper()
		var result int
		if owner.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&result) != nil {
			t.Fatal("fixture count failed")
		}
		return result
	}
	reset := func() {
		t.Helper()
		var clean bool
		if pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM unnest(ARRAY[
 'forge.org_id','forge.auth_issuer','forge.auth_subject','forge.browser_session_hash',
 'forge.login_state_hash','forge.login_binding_hash']) s WHERE coalesce(current_setting(s,true),'')<>'')
 AND (SELECT count(*) FROM browser_sessions)=0 AND (SELECT count(*) FROM users)=0
 AND (SELECT count(*) FROM login_flows)=0`).Scan(&clean) != nil || !clean {
			t.Fatal("session context survived transaction")
		}
	}
	server, signingKey := oidcFixture(t, nil)
	providerCtx := oidc.ClientContext(ctx, server.Client())
	verifier, err := NewOIDCVerifier(providerCtx, server.URL, "session-client")
	if err != nil {
		t.Fatal("TLS identity fixture unavailable")
	}
	proof := func(expiry time.Time) (VerifiedIdentity, string) {
		t.Helper()
		raw := signedIDToken(t, signingKey, map[string]any{"iss": server.URL, "sub": "session-subject", "aud": "session-client", "exp": expiry.Unix(), "nonce": "session-nonce"})
		identity, err := verifier.Verify(providerCtx, raw, "session-nonce")
		if err != nil {
			t.Fatal("signed identity fixture failed verification")
		}
		return identity, raw
	}
	identity, rawToken := proof(time.Now().Add(time.Hour))
	create := func(identity VerifiedIdentity) *BrowserSessionCreated {
		t.Helper()
		result, err := store.Create(ctx, identity)
		if err != nil || result == nil {
			t.Fatal("verified session creation failed")
		}
		reset()
		return result
	}
	t.Run("opaque independent credentials, confidentiality and database expiry caps", func(t *testing.T) {
		seen := map[string]bool{}
		for _, lifetime := range []time.Duration{time.Hour, 24 * time.Hour} {
			principal, _ := proof(time.Now().Add(lifetime))
			sessions, events := count("browser_sessions"), count("auth_security_events")
			result := create(principal)
			credentialHash, credentialOK := loginFlowDigest(result.Credential.Reveal())
			csrfHash, csrfOK := loginFlowDigest(result.CSRF.Reveal())
			if !credentialOK || !csrfOK {
				t.Fatal("session credentials not canonical 32-byte values")
			}
			for _, value := range []string{result.Credential.Reveal(), result.CSRF.Reveal()} {
				if seen[value] {
					t.Fatal("credential material reused")
				}
				seen[value] = true
			}
			var row, issuer, subject string
			var created, expires time.Time
			var storedCSRF []byte
			err := owner.QueryRow(ctx, `SELECT row_to_json(browser_sessions)::text,issuer,subject,csrf_hash,created_at,expires_at
 FROM browser_sessions WHERE credential_hash=$1`, credentialHash).Scan(&row, &issuer, &subject, &storedCSRF, &created, &expires)
			if err != nil || issuer != principal.issuer || subject != principal.subject || !bytes.Equal(storedCSRF, csrfHash) {
				t.Fatal("session stored incorrect identity or verifiers")
			}
			expected := principal.verifiedExpiry
			if cap := created.Add(8 * time.Hour); cap.Before(expected) {
				expected = cap
			}
			if !expires.Equal(expected) || !result.ExpiresAt.Equal(expires) || !expires.After(created) {
				t.Fatal("session expiry did not use database time and verified cap")
			}
			var output bytes.Buffer
			_, _ = fmt.Fprintf(&output, "%v %+v %#v", result, *result, result.Credential)
			encoded, _ := json.Marshal(result)
			output.Write(encoded)
			encoded, _ = result.CSRF.MarshalText()
			output.Write(encoded)
			slog.New(slog.NewJSONHandler(&output, nil)).Info("created", "session", result, "csrf", result.CSRF)
			testutil.NoSecrets(t, row+output.String(), result.Credential.Reveal(), result.CSRF.Reveal(), rawToken)
			if count("browser_sessions") != sessions+1 || count("auth_security_events") != events+1 {
				t.Fatal("session/event creation not atomic")
			}
		}
	})
	t.Run("expired proofs cannot create or renew a session", func(t *testing.T) {
		expiring, _ := proof(time.Now().Add(2 * time.Second))
		time.Sleep(time.Until(expiring.verifiedExpiry) + time.Millisecond)
		sessions, events := count("browser_sessions"), count("auth_security_events")
		if result, err := store.Create(ctx, expiring); result != nil || err != ErrBrowserSession {
			t.Fatal("expired verified proof created session")
		}
		if count("browser_sessions") != sessions || count("auth_security_events") != events {
			t.Fatal("expired proof mutated storage")
		}
		reset()
	})
	t.Run("event failure and cancellation rollback without credentials", func(t *testing.T) {
		for _, mode := range []string{"reject", "cancel"} {
			sessions, events := count("browser_sessions"), count("auth_security_events")
			exec(pool, "SELECT set_config('forge.test_session_fault',$1,false)", mode)
			requestCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			result, err := store.Create(requestCtx, identity)
			cancel()
			if result != nil || err != ErrBrowserSession {
				t.Fatal("failed session transaction returned credentials")
			}
			testutil.NoSecrets(t, err.Error(), identity.issuer, identity.subject, rawToken)
			exec(pool, "RESET forge.test_session_fault")
			reset()
			if count("browser_sessions") != sessions || count("auth_security_events") != events {
				t.Fatal("failed creation partially committed")
			}
			create(identity)
		}
	})
	t.Run("session-only context clears inherited tenant, identity and flow access", func(t *testing.T) {
		orgID, _ := loginFlowUUID()
		if database.WithOrg(ctx, pool, orgID, func(tx pgx.Tx) error {
			for _, sql := range []string{"INSERT INTO orgs(id,name) VALUES($1,'session fixture')", "INSERT INTO users(org_id,id,issuer,subject,display_name) VALUES($1,$1,'https://session.test','subject','fixture')", "INSERT INTO stacks(org_id,id,name) VALUES($1,$1,'session fixture')"} {
				if _, err := tx.Exec(ctx, sql, orgID); err != nil {
					return err
				}
			}
			return nil
		}) != nil {
			t.Fatal("tenant fixture failed")
		}
		flowStore, _ := NewLoginFlowStore(pool, flowKey(t, "session-flow-fixture", 39))
		flow, err := flowStore.Create(ctx)
		if err != nil {
			t.Fatal("flow fixture failed")
		}
		state, _ := loginFlowDigest(flow.State.Reveal())
		binding, _ := loginFlowDigest(flow.Binding.Reveal())
		flowTx, err := flowStore.begin(ctx, state, binding)
		if err != nil {
			t.Fatal("flow-only fixture failed")
		}
		var sessionCount int
		if err := flowTx.QueryRow(ctx, "SELECT count(*) FROM browser_sessions").Scan(&sessionCount); err != nil || sessionCount != 0 {
			t.Fatal("flow-only context exposed browser sessions")
		}
		_ = flowTx.Rollback(ctx)
		exec(pool, `SELECT set_config('forge.org_id',$1,false),set_config('forge.auth_issuer','https://session.test',false),
 set_config('forge.auth_subject','subject',false),set_config('forge.login_state_hash',$2,false),
 set_config('forge.login_binding_hash',$3,false),set_config('forge.browser_session_hash','stale',false)`, orgID, hex.EncodeToString(state), hex.EncodeToString(binding))
		created, err := store.Create(ctx, identity)
		if err != nil {
			t.Fatal("inherited context blocked valid session creation")
		}
		digest, _ := loginFlowDigest(created.Credential.Reveal())
		for _, rollback := range []bool{false, true} {
			tx, err := store.begin(ctx, digest)
			if err != nil {
				t.Fatal(err)
			}
			var isolated bool
			err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM orgs)=0 AND (SELECT count(*) FROM users)=0
 AND (SELECT count(*) FROM stacks)=0 AND (SELECT count(*) FROM login_flows)=0
 AND (SELECT count(*) FROM browser_sessions WHERE credential_hash=$1)=1
 AND NOT EXISTS(SELECT FROM unnest(ARRAY['forge.org_id','forge.auth_issuer','forge.auth_subject',
 'forge.login_state_hash','forge.login_binding_hash']) s WHERE current_setting(s,true)<>'')`, digest).Scan(&isolated)
			if err != nil || !isolated {
				t.Fatal("session context admitted unrelated authority")
			}
			if rollback {
				_ = tx.Rollback(ctx)
			} else {
				_ = tx.Commit(ctx)
			}
		}
		exec(pool, "RESET ALL")
		reset()
		if _, err := flowStore.Consume(ctx, flow.State.Reveal(), flow.Binding.Reveal()); err != nil {
			t.Fatal("session helper damaged unrelated flow")
		}
	})
	t.Run("closed pool returns generic failure", func(t *testing.T) {
		closed := flowPool(t, runtimeURL, 1)
		closed.Close()
		unavailable, _ := NewBrowserSessionStore(closed)
		if result, err := unavailable.Create(ctx, identity); result != nil || err != ErrBrowserSession {
			t.Fatal("unavailable database returned credentials")
		}
	})
}
