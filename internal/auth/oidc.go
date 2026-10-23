package auth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var errOIDC = errors.New("invalid identity token")

// VerifiedIdentity contains only verified identity, never organization authority.
// verifiedExpiry is populated only by successful ID-token verification; identities
// reconstructed for membership lookup cannot establish a new browser session.
type VerifiedIdentity struct {
	issuer, subject string
	verifiedExpiry  time.Time
}

func (VerifiedIdentity) String() string               { return "[REDACTED]" }
func (VerifiedIdentity) GoString() string             { return "[REDACTED]" }
func (VerifiedIdentity) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[REDACTED]") }
func (VerifiedIdentity) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }
func (VerifiedIdentity) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (VerifiedIdentity) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }

func (identity VerifiedIdentity) usableForSession(now time.Time) bool {
	return identity.issuer != "" && identity.subject != "" && !identity.verifiedExpiry.IsZero() && identity.verifiedExpiry.After(now)
}

// OIDCVerifier checks provider-backed identity; it does not create a membership.
type OIDCVerifier struct {
	issuer   string
	clientID string
	verifier *oidc.IDTokenVerifier
}

// NewOIDCVerifier requires operator-configured HTTPS discovery and a client ID.
// A context HTTP client may provide custom trust roots; requests remain bounded.
func NewOIDCVerifier(ctx context.Context, issuer, clientID string) (*OIDCVerifier, error) {
	if !httpsURL(issuer) || clientID == "" || strings.TrimSpace(clientID) != clientID {
		return nil, errors.New("invalid OIDC configuration")
	}
	client := http.Client{Timeout: 10 * time.Second}
	if configured, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && configured != nil {
		client = *configured
		if client.Timeout <= 0 || client.Timeout > 10*time.Second {
			client.Timeout = 10 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx = oidc.ClientContext(ctx, &client)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, errors.New("OIDC discovery failed")
	}
	var metadata struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if provider.Claims(&metadata) != nil || metadata.Issuer != issuer || !httpsURL(metadata.JWKS) {
		return nil, errors.New("invalid OIDC provider metadata")
	}
	return &OIDCVerifier{issuer: issuer, clientID: clientID, verifier: provider.VerifierContext(ctx, &oidc.Config{ClientID: clientID})}, nil
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// Verify requires the nonce from the consumed browser flow record. State/PKCE
// validation and one-use flow consumption are the browser handler's duty.
// All failures omit credentials, claims and upstream diagnostics.
func (v *OIDCVerifier) Verify(ctx context.Context, raw, expectedNonce string) (VerifiedIdentity, error) {
	if v == nil || v.verifier == nil || expectedNonce == "" || len(raw) > 65536 {
		return VerifiedIdentity{}, errOIDC
	}
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil || token.Issuer != v.issuer || token.Subject == "" || subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(expectedNonce)) != 1 {
		return VerifiedIdentity{}, errOIDC
	}
	var claims map[string]json.RawMessage
	if token.Claims(&claims) != nil {
		return VerifiedIdentity{}, errOIDC
	}
	// The SDK decodes registered claims into a struct. Reject case-folded names
	// so JSON struct matching cannot substitute or shadow the actual OIDC claim.
	for name, required := range map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "nonce": true, "iat": false, "nbf": false} {
		if _, present := claims[name]; required && !present {
			return VerifiedIdentity{}, errOIDC
		}
		for actual := range claims {
			if actual != name && strings.EqualFold(actual, name) {
				return VerifiedIdentity{}, errOIDC
			}
		}
	}
	partyClaim, present := claims["azp"] // OIDC claim names are case-sensitive.
	if len(token.Audience) > 1 && !present {
		return VerifiedIdentity{}, errOIDC
	}
	if present {
		var party string
		if json.Unmarshal(partyClaim, &party) != nil || party != v.clientID {
			return VerifiedIdentity{}, errOIDC
		}
	}
	var expiry canonicalOIDCExpiry
	if token.Claims(&expiry) != nil || !expiry.value.Equal(token.Expiry) || !expiry.value.After(time.Now()) {
		return VerifiedIdentity{}, errOIDC
	}
	return VerifiedIdentity{issuer: token.Issuer, subject: token.Subject, verifiedExpiry: expiry.value}, nil
}

// Reject the SDK's permissive quoted/fractional/exponent NumericDate coercion and
// duplicate expiry keys. Retain only one exact, positive integer seconds value.
type canonicalOIDCExpiry struct{ value time.Time }

func (expiry *canonicalOIDCExpiry) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if opening, err := decoder.Token(); err != nil || opening != json.Delim('{') {
		return errOIDC
	}
	for decoder.More() {
		name, err := decoder.Token()
		var value json.RawMessage
		if err != nil || decoder.Decode(&value) != nil {
			return errOIDC
		}
		if name != "exp" {
			continue
		}
		seconds, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil || seconds <= 0 || strconv.FormatInt(seconds, 10) != string(value) || !expiry.value.IsZero() {
			return errOIDC
		}
		expiry.value = time.Unix(seconds, 0)
	}
	if _, err := decoder.Token(); err != nil || expiry.value.IsZero() {
		return errOIDC
	}
	return nil
}
