package auth

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavula/forge/internal/database"
	"github.com/cavula/forge/internal/testutil"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
		for _, invalid := range []string{"", strings.Repeat("A", 42) + "B", strings.Repeat("A", 43) + "="} {
			if result, err := store.Lookup(context.Background(), invalid); result != nil || err != ErrBrowserSession {
				t.Fatal("invalid lookup proof accepted")
			}
			if store.Revoke(context.Background(), invalid) != ErrBrowserSession {
				t.Fatal("invalid revocation proof accepted")
			}
		}
	}
}

func TestBrowserSessionLifecyclePostgres(t *testing.T) {
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
	exec(owner, `CREATE FUNCTION session_revoke_fixture_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.action='browser_session.revoked' THEN
  IF current_setting('forge.test_revoke_fault',true)=TG_ARGV[0] THEN RAISE EXCEPTION 'fixture fault'; END IF;
  IF TG_ARGV[0]='reject' AND current_setting('forge.test_revoke_fault',true)='cancel' THEN PERFORM pg_sleep(10); END IF;
 END IF; RETURN NEW; END $$`)
	exec(owner, "CREATE TRIGGER session_revoke_fixture_insert BEFORE INSERT ON auth_security_events FOR EACH ROW EXECUTE FUNCTION session_revoke_fixture_fault('reject')")
	exec(owner, "CREATE CONSTRAINT TRIGGER session_revoke_fixture_commit AFTER INSERT ON auth_security_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION session_revoke_fixture_fault('commit')")
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
		expiredSession := create(expiring)
		time.Sleep(time.Until(expiring.verifiedExpiry) + time.Millisecond)
		sessions, events := count("browser_sessions"), count("auth_security_events")
		if result, err := store.Create(ctx, expiring); result != nil || err != ErrBrowserSession {
			t.Fatal("expired verified proof created session")
		}
		if result, err := store.Lookup(ctx, expiredSession.Credential.Reveal()); result != nil || err != ErrBrowserSession {
			t.Fatal("expired session lookup succeeded")
		}
		if store.Revoke(ctx, expiredSession.Credential.Reveal()) != ErrBrowserSession {
			t.Fatal("expired session revocation succeeded")
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
		if result, err := store.Lookup(ctx, created.Credential.Reveal()); result == nil || err != nil {
			t.Fatal("inherited context blocked valid lookup")
		}
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
		if store.Revoke(ctx, created.Credential.Reveal()) != nil {
			t.Fatal("inherited context blocked revocation")
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
		if result, err := unavailable.Lookup(ctx, strings.Repeat("A", 43)); result != nil || err != ErrBrowserSession {
			t.Fatal("closed pool returned lookup proof")
		}
		if unavailable.Revoke(ctx, strings.Repeat("A", 43)) != ErrBrowserSession {
			t.Fatal("closed pool accepted revocation")
		}
	})
	t.Run("lookup returns redacted membership proof without renewal authority", func(t *testing.T) {
		created := create(identity)
		found, err := store.Lookup(ctx, created.Credential.Reveal())
		if err != nil || found == nil {
			t.Fatal("active session lookup failed")
		}
		principal := found.Principal()
		csrf, _ := loginFlowDigest(created.CSRF.Reveal())
		if principal.issuer != identity.issuer || principal.subject != identity.subject || !principal.verifiedExpiry.IsZero() || principal.usableForSession(time.Now()) || !bytes.Equal(found.csrfHash[:], csrf) || !found.expiresAt.Equal(created.ExpiresAt) {
			t.Fatal("lookup manufactured authority or lost metadata")
		}
		digest, _ := loginFlowDigest(created.Credential.Reveal())
		readTx, err := store.beginTx(ctx, digest, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatal("read-only lookup transaction failed")
		}
		var readOnly bool
		if readTx.QueryRow(ctx, "SELECT current_setting('transaction_read_only')='on'").Scan(&readOnly) != nil || !readOnly {
			t.Fatal("lookup transaction was writable")
		}
		_, err = readTx.Exec(ctx, "DELETE FROM browser_sessions WHERE credential_hash=$1", digest)
		_ = readTx.Rollback(ctx)
		if pgError, ok := err.(*pgconn.PgError); !ok || pgError.Code != "25006" {
			t.Fatal("read-only lookup context permitted mutation")
		}
		reset()
		sessions, events := count("browser_sessions"), count("auth_security_events")
		if result, err := store.Create(ctx, principal); result != nil || err != ErrBrowserSession {
			t.Fatal("session lookup proof renewed a session")
		}
		orgID, _ := loginFlowUUID()
		if database.WithOrg(ctx, pool, orgID, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "INSERT INTO orgs(id,name) VALUES($1,'membership fixture')", orgID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO users(org_id,id,issuer,subject,display_name) VALUES($1,$1,$2,$3,'member')", orgID, identity.issuer, identity.subject)
			return err
		}) != nil {
			t.Fatal("membership fixture failed")
		}
		if user, err := ResolveMembership(ctx, pool, principal, orgID); err != nil || user == nil || user.GetOrgId() != orgID {
			t.Fatal("lookup principal could not resolve existing membership")
		}
		var output bytes.Buffer
		_, _ = fmt.Fprintf(&output, "%v %+v %#v", found, *found, found)
		output.WriteString(found.GoString())
		encoded, _ := json.Marshal(found)
		output.Write(encoded)
		encoded, _ = found.MarshalText()
		output.Write(encoded)
		slog.New(slog.NewJSONHandler(&output, nil)).Info("lookup", "session", found)
		testutil.NoSecrets(t, output.String(), identity.issuer, identity.subject, rawToken, created.Credential.Reveal(), created.CSRF.Reveal(), hex.EncodeToString(csrf), fmt.Sprint(found.csrfHash), fmt.Sprintf("%#v", found.csrfHash), found.expiresAt.String())
		if count("browser_sessions") != sessions || count("auth_security_events") != events {
			t.Fatal("lookup or rejected renewal mutated storage")
		}
		reset()
	})
	t.Run("wrong proofs preserve sessions; successful revocation rejects replay", func(t *testing.T) {
		created, other := create(identity), create(identity)
		sessions, events := count("browser_sessions"), count("auth_security_events")
		for _, invalid := range []string{"", created.Credential.Reveal() + "=", strings.Repeat("A", 43)} {
			if result, err := store.Lookup(ctx, invalid); result != nil || err != ErrBrowserSession {
				t.Fatal("wrong credential returned principal")
			}
			if store.Revoke(ctx, invalid) != ErrBrowserSession {
				t.Fatal("wrong credential revoked session")
			}
			reset()
		}
		if store.Revoke(ctx, created.Credential.Reveal()) != nil || store.Revoke(ctx, created.Credential.Reveal()) != ErrBrowserSession {
			t.Fatal("revocation or replay outcome incorrect")
		}
		if result, err := store.Lookup(ctx, created.Credential.Reveal()); result != nil || err != ErrBrowserSession {
			t.Fatal("revoked session remained usable")
		}
		if result, err := store.Lookup(ctx, other.Credential.Reveal()); result == nil || err != nil {
			t.Fatal("unrelated session affected")
		}
		if count("browser_sessions") != sessions-1 || count("auth_security_events") != events+1 {
			t.Fatal("revocation event/mutation count incorrect")
		}
		reset()
	})
	t.Run("simultaneous revocations commit once", func(t *testing.T) {
		created := create(identity)
		concurrent, _ := NewBrowserSessionStore(flowPool(t, runtimeURL, 4))
		sessions, events := count("browser_sessions"), count("auth_security_events")
		var winners atomic.Int32
		var group sync.WaitGroup
		barrier := make(chan struct{})
		for range 12 {
			group.Go(func() {
				<-barrier
				err := concurrent.Revoke(ctx, created.Credential.Reveal())
				if err == nil {
					winners.Add(1)
				} else if err != ErrBrowserSession {
					t.Error("nongeneric concurrent failure")
				}
			})
		}
		close(barrier)
		group.Wait()
		if winners.Load() != 1 || count("browser_sessions") != sessions-1 || count("auth_security_events") != events+1 {
			t.Fatal("concurrent revocation did not commit exactly once")
		}
		reset()
	})
	t.Run("revocation event insertion, commit and cancellation failures roll back", func(t *testing.T) {
		for _, mode := range []string{"reject", "commit", "cancel"} {
			created := create(identity)
			sessions, events := count("browser_sessions"), count("auth_security_events")
			exec(pool, "SELECT set_config('forge.test_revoke_fault',$1,false)", mode)
			requestCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			err := store.Revoke(requestCtx, created.Credential.Reveal())
			cancel()
			if err != ErrBrowserSession {
				t.Fatal("failed revocation claimed success")
			}
			testutil.NoSecrets(t, err.Error(), created.Credential.Reveal(), created.CSRF.Reveal(), identity.issuer, identity.subject)
			exec(pool, "RESET forge.test_revoke_fault")
			reset()
			if count("browser_sessions") != sessions || count("auth_security_events") != events {
				t.Fatal("failed revocation partially committed")
			}
			if result, err := store.Lookup(ctx, created.Credential.Reveal()); result == nil || err != nil {
				t.Fatal("failed revocation burned valid session")
			}
			if store.Revoke(ctx, created.Credential.Reveal()) != nil {
				t.Fatal("retry after rollback failed")
			}
			reset()
		}
	})
	t.Run("lookup cancellation releases context and preserves session", func(t *testing.T) {
		created := create(identity)
		lock, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal("lookup lock fixture failed")
		}
		defer func() { _ = lock.Rollback(ctx) }()
		if _, err := lock.Exec(ctx, "LOCK TABLE browser_sessions IN ACCESS EXCLUSIVE MODE"); err != nil {
			t.Fatal("lookup lock fixture failed")
		}
		requestCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		result, err := store.Lookup(requestCtx, created.Credential.Reveal())
		cancel()
		_ = lock.Rollback(ctx)
		if result != nil || err != ErrBrowserSession {
			t.Fatal("canceled lookup returned partial proof")
		}
		reset()
		if result, err := store.Lookup(ctx, created.Credential.Reveal()); result == nil || err != nil {
			t.Fatal("canceled lookup damaged session")
		}
		reset()
	})
}
