package secrets

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
)

const authFlowPurpose = "forge/auth/login-flow/v1"

// MaxAuthFlowPayload bounds the encrypted nonce/PKCE payload, including encoding.
const MaxAuthFlowPayload = 1024

// AuthFlowContext identifies a trusted server-generated flow, never a tenant.
// FlowID must be a lowercase canonical UUID; only schema version 1 is supported.
type AuthFlowContext struct {
	FlowID  string
	Version uint32
}

func (AuthFlowContext) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[redacted auth flow]") }
func (AuthFlowContext) LogValue() slog.Value       { return slog.StringValue("[redacted auth flow]") }
func (AuthFlowContext) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted auth flow]"`), nil
}

// AuthFlowKey protects pre-tenant login material in a separate encryption domain.
// Operators must supply a dedicated master key and ID through LoadLocalKeyFile;
// sharing tenant state/secret keys is outside this caller configuration contract.
type AuthFlowKey struct{ local LocalKey }

func (AuthFlowKey) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[redacted auth flow key]") }
func (AuthFlowKey) LogValue() slog.Value       { return slog.StringValue("[redacted auth flow key]") }
func (AuthFlowKey) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted auth flow key]"`), nil
}

// NewAuthFlowKey copies an explicitly loaded local key. No raw-key, environment,
// default-key or automatic reload path is provided by the auth-flow API.
func NewAuthFlowKey(local *LocalKey) (*AuthFlowKey, error) {
	if local == nil || local.id == "" || local.random == nil {
		return nil, ErrInvalidKey
	}
	return &AuthFlowKey{local: *local}, nil
}

func (k *AuthFlowKey) Seal(ctx AuthFlowContext, plaintext []byte) (Envelope, error) {
	aad, err := ctx.associatedData()
	if err != nil {
		return Envelope{}, err
	}
	if k == nil || k.local.id == "" || k.local.random == nil {
		return Envelope{}, ErrInvalidKey
	}
	if len(plaintext) > MaxAuthFlowPayload {
		return Envelope{}, ErrEncryption
	}
	dek := make([]byte, 32)
	defer clear(dek)
	nonce, wrapNonce := make([]byte, 12), make([]byte, 12)
	for _, dst := range [][]byte{dek, nonce, wrapNonce} {
		if _, err := io.ReadFull(k.local.random, dst); err != nil {
			return Envelope{}, ErrEncryption
		}
	}
	wrapped := newGCM(k.local.key[:]).Seal(wrapNonce, wrapNonce, dek, k.wrapAAD(aad))
	return Envelope{Ciphertext: newGCM(dek).Seal(nil, nonce, plaintext, aad),
		WrappedDEK: wrapped, Nonce: nonce, KeyID: k.local.id}, nil
}

func (k *AuthFlowKey) Open(ctx AuthFlowContext, envelope Envelope) ([]byte, error) {
	aad, err := ctx.associatedData()
	if err != nil {
		return nil, err
	}
	if k == nil || k.local.id == "" {
		return nil, ErrInvalidKey
	}
	if envelope.KeyID != k.local.id || len(envelope.Nonce) != 12 ||
		len(envelope.WrappedDEK) != 60 || len(envelope.Ciphertext) < 16 ||
		len(envelope.Ciphertext) > MaxAuthFlowPayload+16 {
		return nil, ErrDecryption
	}
	wrapped := envelope.WrappedDEK
	dek, err := newGCM(k.local.key[:]).Open(nil, wrapped[:12], wrapped[12:], k.wrapAAD(aad))
	if err != nil {
		return nil, ErrDecryption
	}
	defer clear(dek)
	plaintext, err := newGCM(dek).Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

func (ctx AuthFlowContext) associatedData() ([]byte, error) {
	if len(ctx.FlowID) != 36 || ctx.Version != 1 {
		return nil, ErrInvalidContext
	}
	for i, c := range []byte(ctx.FlowID) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return nil, ErrInvalidContext
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, ErrInvalidContext
		}
	}
	aad := []byte("forge/auth/login-flow/data/v1")
	for _, value := range []string{ctx.FlowID, authFlowPurpose} {
		aad = binary.BigEndian.AppendUint64(aad, uint64(len(value)))
		aad = append(aad, value...)
	}
	return binary.BigEndian.AppendUint32(aad, ctx.Version), nil
}

func (k *AuthFlowKey) wrapAAD(aad []byte) []byte {
	wrapped := append([]byte("forge/auth/login-flow/wrap/v1"), aad...)
	wrapped = binary.BigEndian.AppendUint64(wrapped, uint64(len(k.local.id)))
	return append(wrapped, k.local.id...)
}
