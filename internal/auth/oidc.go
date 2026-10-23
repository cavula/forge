package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var errOIDC = errors.New("invalid identity token")

// VerifiedIdentity contains only verified identity, never organization authority.
type VerifiedIdentity struct{ issuer, subject string }

func (VerifiedIdentity) String() string               { return "[REDACTED]" }
func (VerifiedIdentity) GoString() string             { return "[REDACTED]" }
func (VerifiedIdentity) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[REDACTED]") }
func (VerifiedIdentity) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }
func (VerifiedIdentity) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }

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
	return VerifiedIdentity{issuer: token.Issuer, subject: token.Subject}, nil
}
