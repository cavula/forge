package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const tokenPrefix = "forge_v1."

var errToken = errors.New("invalid API token")

// Token contains a credential shown once to its owner. String formatting always
// redacts it; callers must explicitly use Reveal only for the issuance response.
type Token struct{ raw string }

func (Token) String() string               { return "[REDACTED]" }
func (Token) GoString() string             { return "[REDACTED]" }
func (Token) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[REDACTED]") }
func (t Token) Reveal() string             { return t.raw }
func (Token) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }
func (Token) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }

// TokenVerifier is the one-way value suitable for storage, never a bearer token.
// The public selector locates a record; it does not authenticate its owner.
type TokenVerifier struct {
	Selector string
	Digest   [sha256.Size]byte
}

func (TokenVerifier) String() string               { return "[REDACTED]" }
func (TokenVerifier) GoString() string             { return "[REDACTED]" }
func (TokenVerifier) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[REDACTED]") }
func (TokenVerifier) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }
func (TokenVerifier) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }

// NewToken creates a random selector and 256-bit secret using crypto/rand.
// Expiration, scopes, revocation and current membership must also be enforced
// before a future authentication layer accepts any successfully matched token.
func NewToken() (Token, TokenVerifier, error) { return newToken(rand.Reader) }

func newToken(random io.Reader) (Token, TokenVerifier, error) {
	var entropy [48]byte
	if _, err := io.ReadFull(random, entropy[:]); err != nil {
		return Token{}, TokenVerifier{}, errors.New("API token generation failed")
	}
	selector := base64.RawURLEncoding.EncodeToString(entropy[:16])
	raw := tokenPrefix + selector + "." + base64.RawURLEncoding.EncodeToString(entropy[16:])
	return Token{raw: raw}, TokenVerifier{Selector: selector, Digest: sha256.Sum256([]byte(raw))}, nil
}

// ParseToken rejects unsupported versions, lengths and noncanonical encodings.
// Errors deliberately omit the input credential.
func ParseToken(raw string) (Token, string, error) {
	if len(raw) != len(tokenPrefix)+22+1+43 || !strings.HasPrefix(raw, tokenPrefix) {
		return Token{}, "", errToken
	}
	parts := strings.Split(strings.TrimPrefix(raw, tokenPrefix), ".")
	if len(parts) != 2 || !canonicalPart(parts[0], 16) || !canonicalPart(parts[1], 32) {
		return Token{}, "", errToken
	}
	return Token{raw: raw}, parts[0], nil
}

func canonicalPart(encoded string, size int) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil && len(decoded) == size && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

// Matches checks only the credential, never the associated authorization gates.
func (v TokenVerifier) Matches(token Token) bool {
	parsed, selector, err := ParseToken(token.raw)
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parsed.raw))
	return subtle.ConstantTimeCompare(v.Digest[:], digest[:]) == 1 && selector == v.Selector
}
