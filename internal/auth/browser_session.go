package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrBrowserSession = errors.New("browser session unavailable")

type BrowserSessionCreated struct {
	Credential, CSRF LoginFlowValue
	ExpiresAt        time.Time
}

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

func (store *BrowserSessionStore) begin(ctx context.Context, digest []byte) (pgx.Tx, error) {
	tx, err := store.pool.Begin(ctx)
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
