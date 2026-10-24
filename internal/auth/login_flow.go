package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/cavula/forge/internal/secrets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrLoginFlow = errors.New("login flow unavailable")

// LoginFlowValue is opaque except at an explicit outbound protocol boundary.
type LoginFlowValue struct{ value string }

func (v LoginFlowValue) Reveal() string               { return v.value }
func (LoginFlowValue) String() string                 { return "[redacted login flow]" }
func (v LoginFlowValue) GoString() string             { return v.String() }
func (v LoginFlowValue) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, v.String()) }
func (v LoginFlowValue) MarshalJSON() ([]byte, error) { return json.Marshal(v.String()) }
func (v LoginFlowValue) MarshalText() ([]byte, error) { return []byte(v.String()), nil }
func (v LoginFlowValue) LogValue() slog.Value         { return slog.StringValue(v.String()) }

type LoginFlowStart struct {
	State, Binding, Nonce, PKCEChallenge LoginFlowValue
	ExpiresAt                            time.Time
}
type LoginFlowConsumed struct{ Nonce, PKCEVerifier LoginFlowValue }

// LoginFlowStore requires an explicit runtime pool and dedicated, protected-file
// AuthFlowKey. It provides no key discovery, fallback or browser route wiring.
type LoginFlowStore struct {
	pool *pgxpool.Pool
	key  *secrets.AuthFlowKey
}

func NewLoginFlowStore(pool *pgxpool.Pool, key *secrets.AuthFlowKey) (*LoginFlowStore, error) {
	if pool == nil || key == nil {
		return nil, ErrLoginFlow
	}
	return &LoginFlowStore{pool: pool, key: key}, nil
}

type loginFlowPayload struct {
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

func (s *LoginFlowStore) Create(ctx context.Context) (*LoginFlowStart, error) {
	if s == nil || s.pool == nil || s.key == nil {
		return nil, ErrLoginFlow
	}
	values := make([]string, 4)
	for i := range values {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, ErrLoginFlow
		}
		values[i] = base64.RawURLEncoding.EncodeToString(raw[:])
	}
	id, err := loginFlowUUID()
	if err != nil {
		return nil, ErrLoginFlow
	}
	payload, _ := json.Marshal(loginFlowPayload{values[2], values[3]})
	defer clear(payload)
	envelope, err := s.key.Seal(secrets.AuthFlowContext{FlowID: id, Version: 1}, payload)
	if err != nil {
		return nil, ErrLoginFlow
	}
	state, _ := loginFlowDigest(values[0])
	binding, _ := loginFlowDigest(values[1])
	tx, err := s.begin(ctx, state, binding)
	if err != nil {
		return nil, ErrLoginFlow
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var expiresAt time.Time
	err = tx.QueryRow(ctx, `INSERT INTO login_flows
 (id,state_hash,binding_hash,ciphertext,nonce,wrapped_dek,key_id)
 VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING expires_at`, id, state, binding,
		envelope.Ciphertext, envelope.Nonce, envelope.WrappedDEK, envelope.KeyID).Scan(&expiresAt)
	if err != nil || loginFlowEvent(ctx, tx, "login_flow.created") != nil || tx.Commit(ctx) != nil {
		return nil, ErrLoginFlow
	}
	challenge := sha256.Sum256([]byte(values[3]))
	return &LoginFlowStart{State: LoginFlowValue{values[0]}, Binding: LoginFlowValue{values[1]},
		Nonce: LoginFlowValue{values[2]}, PKCEChallenge: LoginFlowValue{base64.RawURLEncoding.EncodeToString(challenge[:])},
		ExpiresAt: expiresAt}, nil
}

// Consume commits deletion and its event before opening the payload. An invalid
// envelope or payload permanently consumes the flow and returns no credentials.
func (s *LoginFlowStore) Consume(ctx context.Context, stateValue, bindingValue string) (*LoginFlowConsumed, error) {
	state, validState := loginFlowDigest(stateValue)
	binding, validBinding := loginFlowDigest(bindingValue)
	if s == nil || s.pool == nil || s.key == nil || !validState || !validBinding {
		return nil, ErrLoginFlow
	}
	tx, err := s.begin(ctx, state, binding)
	if err != nil {
		return nil, ErrLoginFlow
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var id string
	var envelope secrets.Envelope
	err = tx.QueryRow(ctx, `DELETE FROM login_flows
 WHERE state_hash=$1 AND binding_hash=$2 AND expires_at>now()
 RETURNING id::text,ciphertext,nonce,wrapped_dek,key_id`, state, binding).
		Scan(&id, &envelope.Ciphertext, &envelope.Nonce, &envelope.WrappedDEK, &envelope.KeyID)
	if err != nil || loginFlowEvent(ctx, tx, "login_flow.consumed") != nil || tx.Commit(ctx) != nil {
		return nil, ErrLoginFlow
	}
	plaintext, err := s.key.Open(secrets.AuthFlowContext{FlowID: id, Version: 1}, envelope)
	if err != nil {
		return nil, ErrLoginFlow
	}
	defer clear(plaintext)
	var payload loginFlowPayload
	if json.Unmarshal(plaintext, &payload) != nil {
		return nil, ErrLoginFlow
	}
	canonical, _ := json.Marshal(payload)
	defer clear(canonical)
	_, nonceOK := loginFlowDigest(payload.Nonce)
	_, verifierOK := loginFlowDigest(payload.Verifier)
	if !bytes.Equal(plaintext, canonical) || !nonceOK || !verifierOK {
		return nil, ErrLoginFlow
	}
	return &LoginFlowConsumed{LoginFlowValue{payload.Nonce}, LoginFlowValue{payload.Verifier}}, nil
}

func (s *LoginFlowStore) begin(ctx context.Context, state, binding []byte) (pgx.Tx, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, ErrLoginFlow
	}
	_, err = tx.Exec(ctx, `SELECT set_config('forge.org_id','',true),
 set_config('forge.auth_issuer','',true),set_config('forge.auth_subject','',true),
 set_config('forge.browser_session_hash','',true),
 set_config('forge.login_state_hash',$1,true),set_config('forge.login_binding_hash',$2,true)`,
		hex.EncodeToString(state), hex.EncodeToString(binding))
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, ErrLoginFlow
	}
	return tx, nil
}

func loginFlowDigest(value string) ([]byte, bool) {
	if len(value) != 43 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, false
	}
	digest := sha256.Sum256(raw)
	return digest[:], true
}

func loginFlowUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrLoginFlow
	}
	raw[6], raw[8] = raw[6]&0x0f|0x40, raw[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[:4], raw[4:6], raw[6:8], raw[8:10], raw[10:]), nil
}

func loginFlowEvent(ctx context.Context, tx pgx.Tx, action string) error {
	id, err := loginFlowUUID()
	if err != nil {
		return ErrLoginFlow
	}
	_, err = tx.Exec(ctx, "INSERT INTO auth_security_events(id,action,outcome) VALUES($1,$2,'success')", id, action)
	return err
}
