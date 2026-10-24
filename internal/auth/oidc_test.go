package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cavula/forge/internal/testutil"
	"github.com/coreos/go-oidc/v3/oidc"
)

func oidcFixture(t *testing.T, discovery func(string) any) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("fixture key generation failed")
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			metadata := any(map[string]any{"issuer": server.URL, "jwks_uri": server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			if discovery != nil {
				metadata = discovery(server.URL)
			}
			_ = json.NewEncoder(w).Encode(metadata)
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
				"kty": "RSA", "kid": "fixture-key", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, key
}

func signedIDToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal("fixture claims could not be encoded")
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture-key"}`))
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal("fixture signing failed")
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCProviderVerification(t *testing.T) {
	server, key := oidcFixture(t, nil)
	ctx := oidc.ClientContext(context.Background(), server.Client())
	verifier, err := NewOIDCVerifier(ctx, server.URL, "forge-client")
	if err != nil {
		t.Fatal("TLS provider discovery failed")
	}
	claims := func() map[string]any {
		return map[string]any{"iss": server.URL, "sub": "verified-subject", "aud": "forge-client", "exp": time.Now().Add(time.Hour).Unix(), "nonce": "browser-flow-nonce"}
	}
	raw := signedIDToken(t, key, claims())
	principal, err := verifier.Verify(ctx, raw, "browser-flow-nonce")
	if err != nil || principal != (VerifiedIdentity{issuer: server.URL, subject: "verified-subject"}) {
		t.Fatal("valid signed identity did not resolve")
	}
	var captured bytes.Buffer
	for _, value := range []any{principal, &principal} {
		_, _ = fmt.Fprintf(&captured, "%v %+v %#v", value, value, value)
	}
	_, _ = fmt.Fprint(&captured, principal.String(), principal.GoString())
	encoded, _ := json.Marshal(principal)
	captured.Write(encoded)
	encoded, _ = principal.MarshalText()
	captured.Write(encoded)
	slog.New(slog.NewTextHandler(&captured, nil)).Info("identity", "principal", principal)
	testutil.NoSecrets(t, captured.String(), raw, server.URL, "verified-subject", "browser-flow-nonce")
	for _, audience := range []any{"forge-client", []string{"forge-client"}, []string{"forge-client", "other-client"}} {
		valid := claims()
		valid["aud"], valid["azp"] = audience, "forge-client"
		valid["AZP"] = "unrelated-claim"
		if got, err := verifier.Verify(ctx, signedIDToken(t, key, valid), "browser-flow-nonce"); err != nil || got != principal {
			t.Fatal("matching authorized party rejected")
		}
	}
	for name, change := range map[string]func(map[string]any){
		"wrong issuer":     func(c map[string]any) { c["iss"] = "https://other-issuer.example" },
		"wrong audience":   func(c map[string]any) { c["aud"] = "other-client" },
		"missing audience": func(c map[string]any) { delete(c, "aud") },
		"expired":          func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"missing expiry":   func(c map[string]any) { delete(c, "exp") },
		"empty subject":    func(c map[string]any) { c["sub"] = "" },
		"missing subject":  func(c map[string]any) { delete(c, "sub") },
		"wrong nonce":      func(c map[string]any) { c["nonce"] = "different-browser" },
		"missing nonce":    func(c map[string]any) { delete(c, "nonce") },
		"wrong azp":        func(c map[string]any) { c["azp"] = "other-client" },
		"empty azp":        func(c map[string]any) { c["azp"] = "" },
		"null azp":         func(c map[string]any) { c["azp"] = nil },
		"invalid azp type": func(c map[string]any) { c["azp"] = []string{"forge-client"} },
		"multiple audiences without azp": func(c map[string]any) {
			c["aud"] = []string{"forge-client", "other-client"}
		},
		"multiple audiences wrong azp": func(c map[string]any) {
			c["aud"], c["azp"] = []string{"forge-client", "other-client"}, "other-client"
		},
		"uppercase claim without azp": func(c map[string]any) {
			c["aud"], c["AZP"] = []string{"forge-client", "other-client"}, "forge-client"
		},
		"uppercase claim cannot override azp": func(c map[string]any) {
			c["azp"], c["AZP"] = "other-client", "forge-client"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := claims()
			change(changed)
			assertOIDCRejected(t, verifier, ctx, signedIDToken(t, key, changed), "browser-flow-nonce")
		})
	}
	for _, name := range []string{"iss", "sub", "aud", "exp", "nonce"} {
		t.Run("casefolded "+name, func(t *testing.T) {
			changed := claims()
			changed[strings.ToUpper(name)] = changed[name]
			delete(changed, name)
			assertOIDCRejected(t, verifier, ctx, signedIDToken(t, key, changed), "browser-flow-nonce")
			changed = claims()
			changed[strings.ToUpper(name)] = changed[name]
			assertOIDCRejected(t, verifier, ctx, signedIDToken(t, key, changed), "browser-flow-nonce")
		})
	}
	parts := strings.Split(raw, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signature[0] ^= 1
	unsignedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	for name, bad := range map[string]string{
		"empty": "", "malformed": "sensitive-bad-token", "oversized": strings.Repeat("x", 65537),
		"forged":   parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature),
		"unsigned": unsignedHeader + "." + parts[1] + ".",
	} {
		t.Run(name, func(t *testing.T) { assertOIDCRejected(t, verifier, ctx, bad, "browser-flow-nonce") })
	}
	assertOIDCRejected(t, verifier, ctx, raw, "")
	assertOIDCRejected(t, nil, ctx, raw, "browser-flow-nonce")
	assertOIDCRejected(t, &OIDCVerifier{}, ctx, raw, "browser-flow-nonce")
}

func assertOIDCRejected(t *testing.T, verifier *OIDCVerifier, ctx context.Context, raw, nonce string) {
	t.Helper()
	principal, err := verifier.Verify(ctx, raw, nonce)
	if err != errOIDC || principal != (VerifiedIdentity{}) {
		t.Fatal("invalid identity returned authority or a nongeneric error")
	}
	testutil.NoSecrets(t, fmt.Sprint(err), raw, nonce, "verified-subject", "different-browser")
}

func TestOIDCConfigurationRejectsInsecureDiscovery(t *testing.T) {
	for _, issuer := range []string{"", "http://issuer.example", "http://127.0.0.1", "//issuer.example", "https:///missing-host", "https://user:password@issuer.example", "https://issuer.example?secret=credential", "https://issuer.example#fragment", "%"} {
		verifier, err := NewOIDCVerifier(context.Background(), issuer, "client")
		if err == nil || verifier != nil {
			t.Fatal("invalid issuer configuration accepted")
		}
		testutil.NoSecrets(t, err.Error(), issuer, "password", "credential")
	}
	for _, client := range []string{"", " ", " client", "client "} {
		if verifier, err := NewOIDCVerifier(context.Background(), "https://issuer.example", client); err == nil || verifier != nil {
			t.Fatal("invalid client configuration accepted")
		}
	}
	for name, discovery := range map[string]func(string) any{
		"mismatched issuer": func(base string) any {
			return map[string]string{"issuer": "https://other.example", "jwks_uri": base + "/keys"}
		},
		"insecure keys": func(base string) any {
			return map[string]string{"issuer": base, "jwks_uri": "http://insecure.example/keys"}
		},
		"malformed claims": func(string) any { return "sensitive-provider-body" },
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := oidcFixture(t, discovery)
			verifier, err := NewOIDCVerifier(oidc.ClientContext(context.Background(), server.Client()), server.URL, "client")
			if err == nil || verifier != nil {
				t.Fatal("invalid discovery metadata accepted")
			}
			testutil.NoSecrets(t, err.Error(), "sensitive-provider-body", "insecure.example", "other.example")
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if verifier, err := NewOIDCVerifier(ctx, "https://issuer.example", "client"); err == nil || verifier != nil {
		t.Fatal("canceled discovery succeeded")
	}
}

type oidcTransport func(*http.Request) (*http.Response, error)

func (f oidcTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOIDCBoundsRequestsAndRejectsRedirects(t *testing.T) {
	for _, configuredTimeout := range []time.Duration{0, time.Hour, time.Second} {
		t.Run(configuredTimeout.String(), func(t *testing.T) {
			client := &http.Client{Timeout: configuredTimeout, Transport: oidcTransport(func(r *http.Request) (*http.Response, error) {
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > 10*time.Second {
					t.Error("provider request did not have a bounded deadline")
				}
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://insecure.example"}}, Body: io.NopCloser(strings.NewReader("sensitive-provider-body")), Request: r}, nil
			})}
			verifier, err := NewOIDCVerifier(oidc.ClientContext(context.Background(), client), "https://issuer.example", "client")
			if err == nil || verifier != nil {
				t.Fatal("redirecting discovery accepted")
			}
			if client.Timeout != configuredTimeout || client.CheckRedirect != nil {
				t.Fatal("operator's HTTP client was mutated")
			}
			testutil.NoSecrets(t, err.Error(), "insecure.example", "sensitive-provider-body")
		})
	}
}
