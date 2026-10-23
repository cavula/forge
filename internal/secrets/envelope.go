// Package secrets protects state and secret values using authenticated encryption.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

var (
	ErrInvalidKey     = errors.New("invalid envelope key configuration")
	ErrInvalidContext = errors.New("invalid envelope context")
	ErrEncryption     = errors.New("envelope encryption failed")
	ErrDecryption     = errors.New("envelope decryption failed")
)

// Context binds a value to its tenant, resource, purpose and schema version.
// Callers must derive tenant and resource identity from authorized storage access.
type Context struct {
	OrgID, ResourceID, Purpose string
	Version                    uint32
}

// Envelope contains only encrypted data and the metadata required to decrypt it.
// WrappedDEK is the wrapping nonce followed by the authenticated encrypted DEK.
type Envelope struct {
	Ciphertext, WrappedDEK, Nonce []byte
	KeyID                         string
}

// Format redacts even verbose diagnostics, including wrapped key material.
func (Envelope) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[redacted envelope]") }
func (Envelope) LogValue() slog.Value       { return slog.StringValue("[redacted envelope]") }
func (Envelope) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted envelope]"`), nil
}

// LocalKey holds an explicitly supplied master key; it never generates a default.
// Load master keys from protected files outside the database and container image.
type LocalKey struct {
	id     string
	key    [32]byte
	random io.Reader
}

func (LocalKey) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[redacted local key]") }
func (LocalKey) LogValue() slog.Value       { return slog.StringValue("[redacted local key]") }
func (LocalKey) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted local key]"`), nil
}

func NewLocalKey(keyID string, key []byte) (*LocalKey, error) {
	if keyID == "" || len(key) != 32 {
		return nil, ErrInvalidKey
	}
	k := &LocalKey{id: keyID, random: rand.Reader}
	copy(k.key[:], key)
	return k, nil
}

func (k *LocalKey) Seal(ctx Context, plaintext []byte) (Envelope, error) {
	aad, err := ctx.associatedData()
	if err != nil {
		return Envelope{}, err
	}
	if k == nil || k.id == "" {
		return Envelope{}, ErrInvalidKey
	}
	dek := make([]byte, 32)
	defer clear(dek)
	nonce, wrapNonce := make([]byte, 12), make([]byte, 12)
	for _, dst := range [][]byte{dek, nonce, wrapNonce} {
		if _, err := io.ReadFull(k.random, dst); err != nil {
			return Envelope{}, ErrEncryption
		}
	}
	dataCipher := newGCM(dek)
	wrapped := newGCM(k.key[:]).Seal(wrapNonce, wrapNonce, dek, k.wrapAAD(aad))
	return Envelope{Ciphertext: dataCipher.Seal(nil, nonce, plaintext, aad),
		WrappedDEK: wrapped, Nonce: nonce, KeyID: k.id}, nil
}

func (k *LocalKey) Open(ctx Context, envelope Envelope) ([]byte, error) {
	aad, err := ctx.associatedData()
	if err != nil {
		return nil, err
	}
	if k == nil || k.id == "" {
		return nil, ErrInvalidKey
	}
	if envelope.KeyID != k.id || len(envelope.Nonce) != 12 ||
		len(envelope.WrappedDEK) != 12+32+16 || len(envelope.Ciphertext) < 16 {
		return nil, ErrDecryption
	}
	wrapped := envelope.WrappedDEK
	dek, err := newGCM(k.key[:]).Open(nil, wrapped[:12], wrapped[12:], k.wrapAAD(aad))
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

func newGCM(key []byte) cipher.AEAD {
	// All callers supply exactly 32 bytes; AES-GCM construction cannot fail.
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead
}

func (ctx Context) associatedData() ([]byte, error) {
	if ctx.OrgID == "" || ctx.ResourceID == "" || ctx.Purpose == "" || ctx.Version == 0 {
		return nil, ErrInvalidContext
	}
	aad := []byte("forge/envelope/data/v1")
	for _, value := range []string{ctx.OrgID, ctx.ResourceID, ctx.Purpose} {
		aad = binary.BigEndian.AppendUint64(aad, uint64(len(value)))
		aad = append(aad, value...)
	}
	return binary.BigEndian.AppendUint32(aad, ctx.Version), nil
}

func (k *LocalKey) wrapAAD(aad []byte) []byte {
	wrapped := append([]byte("forge/envelope/wrap/v1"), aad...)
	return append(wrapped, k.id...)
}
