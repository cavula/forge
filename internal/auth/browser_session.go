package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrBrowserSession = errors.New("browser session unavailable")

type BrowserSessionCreated struct {
	Credential, CSRF LoginFlowValue
	ExpiresAt        time.Time
}

// BrowserSessionLookup retains private verification metadata, never tenant or
// renewal authority. Principal returns a membership-only identity proof.
type BrowserSessionLookup struct {
	principal      VerifiedIdentity
	csrfHash       [32]byte
	credentialHash [32]byte
	expiresAt      time.Time
}

func (session BrowserSessionLookup) Principal() VerifiedIdentity {
	return VerifiedIdentity{issuer: session.principal.issuer, subject: session.principal.subject}
}
func (BrowserSessionLookup) String() string           { return "[redacted browser session]" }
func (session BrowserSessionLookup) GoString() string { return session.String() }
func (session BrowserSessionLookup) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, session.String())
}
func (session BrowserSessionLookup) MarshalJSON() ([]byte, error) {
	return []byte(`"` + session.String() + `"`), nil
}
func (session BrowserSessionLookup) MarshalText() ([]byte, error) {
	return []byte(session.String()), nil
}
func (session BrowserSessionLookup) LogValue() slog.Value { return slog.StringValue(session.String()) }

// BrowserSessionStore requires an explicitly supplied non-owner runtime pool.
// It neither loads credentials nor discovers an owner database connection.
type BrowserSessionStore struct{ pool *pgxpool.Pool }

func NewBrowserSessionStore(pool *pgxpool.Pool) (*BrowserSessionStore, error) {
	if pool == nil {
		return nil, ErrBrowserSession
	}
	return &BrowserSessionStore{pool: pool}, nil
}

// Create accepts expiry provenance only from OIDC verification. No caller-chosen
// credential or lifetime is accepted. Initial creation does not replace a session.
func (store *BrowserSessionStore) Create(ctx context.Context, identity VerifiedIdentity) (*BrowserSessionCreated, error) {
	if store == nil || store.pool == nil || !identity.usableForSession(time.Now()) {
		return nil, ErrBrowserSession
	}
	var material [2][32]byte
	for i := range material {
		if _, err := rand.Read(material[i][:]); err != nil {
			return nil, ErrBrowserSession
		}
	}
	credentialHash, csrfHash := sha256.Sum256(material[0][:]), sha256.Sum256(material[1][:])
	id, err := loginFlowUUID()
	if err != nil {
		return nil, ErrBrowserSession
	}
	eventID, err := loginFlowUUID()
	if err != nil {
		return nil, ErrBrowserSession
	}
	tx, err := store.begin(ctx, credentialHash[:])
	if err != nil {
		return nil, ErrBrowserSession
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var expiry time.Time
	err = tx.QueryRow(ctx, `INSERT INTO browser_sessions
 (id,credential_hash,issuer,subject,csrf_hash,expires_at)
 SELECT $1,$2,$3,$4,$5,least(now()+interval '8 hours',$6::timestamptz)
 WHERE $6::timestamptz>now() RETURNING expires_at`, id, credentialHash[:],
		identity.issuer, identity.subject, csrfHash[:], identity.verifiedExpiry).Scan(&expiry)
	if err != nil {
		return nil, ErrBrowserSession
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth_security_events(id,action,outcome)
 VALUES($1,'browser_session.created','success')`, eventID)
	if err != nil || tx.Commit(ctx) != nil {
		return nil, ErrBrowserSession
	}
	return &BrowserSessionCreated{LoginFlowValue{base64.RawURLEncoding.EncodeToString(material[0][:])},
		LoginFlowValue{base64.RawURLEncoding.EncodeToString(material[1][:])}, expiry}, nil
}

// Lookup authenticates one active credential and returns no token-expiry proof.
func (store *BrowserSessionStore) Lookup(ctx context.Context, credential string) (*BrowserSessionLookup, error) {
	digest, valid := loginFlowDigest(credential)
	if store == nil || store.pool == nil || !valid {
		return nil, ErrBrowserSession
	}
	tx, err := store.beginTx(ctx, digest, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, ErrBrowserSession
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var session BrowserSessionLookup
	var csrf []byte
	err = tx.QueryRow(ctx, `SELECT issuer,subject,csrf_hash,expires_at FROM browser_sessions
 WHERE credential_hash=$1 AND expires_at>now()`, digest).
		Scan(&session.principal.issuer, &session.principal.subject, &csrf, &session.expiresAt)
	if err != nil || session.principal.issuer == "" || session.principal.subject == "" || len(csrf) != 32 || tx.Commit(ctx) != nil {
		return nil, ErrBrowserSession
	}
	copy(session.csrfHash[:], csrf)
	copy(session.credentialHash[:], digest)
	return &session, nil
}

// Revoke commits the active session's deletion and success event together.
func (store *BrowserSessionStore) Revoke(ctx context.Context, credential string) error {
	digest, valid := loginFlowDigest(credential)
	if store == nil || store.pool == nil || !valid {
		return ErrBrowserSession
	}
	eventID, err := loginFlowUUID()
	if err != nil {
		return ErrBrowserSession
	}
	tx, err := store.begin(ctx, digest)
	if err != nil {
		return ErrBrowserSession
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	tag, err := tx.Exec(ctx, `DELETE FROM browser_sessions WHERE credential_hash=$1 AND expires_at>now()`, digest)
	if err != nil || tag.RowsAffected() != 1 {
		return ErrBrowserSession
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth_security_events(id,action,outcome)
 VALUES($1,'browser_session.revoked','success')`, eventID)
	if err != nil || tx.Commit(ctx) != nil {
		return ErrBrowserSession
	}
	return nil
}

// Replace requires an existing old credential and a new OIDC expiry proof. An
// expired old row may be removed, but never grants identity or renewal authority.
func (store *BrowserSessionStore) Replace(ctx context.Context, oldCredential string, identity VerifiedIdentity) (*BrowserSessionCreated, error) {
	oldDigest, valid := loginFlowDigest(oldCredential)
	if store == nil || store.pool == nil || !valid || !identity.usableForSession(time.Now()) {
		return nil, ErrBrowserSession
	}
	var material [2][32]byte
	for i := range material {
		if _, err := rand.Read(material[i][:]); err != nil {
			return nil, ErrBrowserSession
		}
	}
	credentialHash, csrfHash := sha256.Sum256(material[0][:]), sha256.Sum256(material[1][:])
	ids := make([]string, 3)
	for i := range ids {
		var err error
		ids[i], err = loginFlowUUID()
		if err != nil {
			return nil, ErrBrowserSession
		}
	}
	tx, err := store.begin(ctx, oldDigest)
	if err != nil {
		return nil, ErrBrowserSession
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	tag, err := tx.Exec(ctx, "DELETE FROM browser_sessions WHERE credential_hash=$1", oldDigest)
	if err != nil || tag.RowsAffected() != 1 {
		return nil, ErrBrowserSession
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('forge.browser_session_hash','',true)"); err != nil {
		return nil, ErrBrowserSession
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('forge.browser_session_hash',$1,true)", hex.EncodeToString(credentialHash[:])); err != nil {
		return nil, ErrBrowserSession
	}
	var expiry time.Time
	err = tx.QueryRow(ctx, `INSERT INTO browser_sessions
 (id,credential_hash,issuer,subject,csrf_hash,expires_at)
 SELECT $1,$2,$3,$4,$5,least(now()+interval '8 hours',$6::timestamptz)
 WHERE $6::timestamptz>now() RETURNING expires_at`, ids[0], credentialHash[:],
		identity.issuer, identity.subject, csrfHash[:], identity.verifiedExpiry).Scan(&expiry)
	if err != nil {
		return nil, ErrBrowserSession
	}
	for i, action := range []string{"browser_session.replaced", "browser_session.created"} {
		if _, err := tx.Exec(ctx, "INSERT INTO auth_security_events(id,action,outcome) VALUES($1,$2,'success')", ids[i+1], action); err != nil {
			return nil, ErrBrowserSession
		}
	}
	if tx.Commit(ctx) != nil {
		return nil, ErrBrowserSession
	}
	return &BrowserSessionCreated{LoginFlowValue{base64.RawURLEncoding.EncodeToString(material[0][:])},
		LoginFlowValue{base64.RawURLEncoding.EncodeToString(material[1][:])}, expiry}, nil
}

func (store *BrowserSessionStore) begin(ctx context.Context, digest []byte) (pgx.Tx, error) {
	return store.beginTx(ctx, digest, pgx.TxOptions{})
}

func (store *BrowserSessionStore) beginTx(ctx context.Context, digest []byte, options pgx.TxOptions) (pgx.Tx, error) {
	tx, err := store.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, ErrBrowserSession
	}
	_, err = tx.Exec(ctx, `SELECT set_config('forge.org_id','',true),
 set_config('forge.auth_issuer','',true),set_config('forge.auth_subject','',true),
 set_config('forge.login_state_hash','',true),set_config('forge.login_binding_hash','',true),
 set_config('forge.browser_session_hash',$1,true)`, hex.EncodeToString(digest))
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, ErrBrowserSession
	}
	return tx, nil
}
