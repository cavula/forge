package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cavula/forge/internal/testutil"
	"github.com/coreos/go-oidc/v3/oidc"
)

func boundaryValue(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}
func boundaryRequest(credential, csrf string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://untrusted-host.test/", nil)
	request.Header.Set("Origin", "https://forge.test:8443")
	request.Header.Set("Cookie", browserSessionCookie+"="+credential+"; "+browserCSRFCookie+"="+csrf)
	request.Header.Set("X-Forge-CSRF", csrf)
	return request
}

func TestBrowserBoundaryConfigurationAndOrigin(t *testing.T) {
	origin := "https://forge.test:8443"
	for _, invalid := range []string{"", "http://forge.test", "https:///missing", "https://user:password@forge.test", "https://forge.test/", "https://forge.test?query", "https://forge.test#fragment", "%"} {
		if result, err := NewBrowserBoundary(invalid, invalid+"/auth/callback"); result != nil || err != ErrBrowserBoundary {
			t.Fatal("invalid browser configuration accepted")
		}
	}
	if result, err := NewBrowserBoundary(origin, origin+"/auth/callback?return=attacker"); result != nil || err != ErrBrowserBoundary {
		t.Fatal("nonexact callback accepted")
	}
	boundary, err := NewBrowserBoundary(origin, origin+"/auth/callback")
	if err != nil || boundary.callback != origin+"/auth/callback" {
		t.Fatal("configured callback lost")
	}
	request := boundaryRequest(boundaryValue(1), boundaryValue(2))
	request.Header.Set("Forwarded", "host=attacker.test;proto=http")
	if boundary.CheckOrigin(request) != nil {
		t.Fatal("request host changed configured origin")
	}
	for _, invalid := range []string{"", "null", "http://forge.test:8443", "https://forge.test", "https://forge.test:8443/", origin + ", " + origin} {
		request.Header.Set("Origin", invalid)
		if boundary.CheckOrigin(request) != ErrBrowserBoundary {
			t.Fatal("nonexact origin accepted")
		}
	}
	request.Header["Origin"] = []string{origin, origin}
	if boundary.CheckOrigin(request) != ErrBrowserBoundary {
		t.Fatal("duplicate origin accepted")
	}
	request.Header["Origin"] = []string{origin}
	request.Header["origin"] = []string{origin}
	if boundary.CheckOrigin(request) != ErrBrowserBoundary {
		t.Fatal("case-aliased origin duplicate accepted")
	}
	var absent *BrowserBoundary
	if absent.CheckOrigin(request) != ErrBrowserBoundary || boundary.CheckOrigin(nil) != ErrBrowserBoundary {
		t.Fatal("missing boundary accepted")
	}
}

func TestBrowserCookieParsingAndAttributes(t *testing.T) {
	credential, csrf := boundaryValue(1), boundaryValue(2)
	valid := browserSessionCookie + "=" + credential
	for _, headers := range [][]string{{}, {valid + "; " + valid}, {valid, valid}, {valid + "; " + browserCSRFCookie + "=" + csrf + "; " + browserCSRFCookie + "=" + csrf}, {strings.Repeat("x", maxBrowserCookieBytes) + valid}, append(make([]string, maxBrowserCookieBytes), valid)} {
		request := httptest.NewRequest(http.MethodGet, "https://forge.test", nil)
		request.Header["Cookie"] = headers
		if value, err := BrowserSessionCredential(request); value.Reveal() != "" || err != ErrBrowserBoundary {
			t.Fatal("missing, duplicate or oversized cookie accepted")
		}
	}
	for _, invalid := range []string{"", credential + "=", `"` + credential + `"`, credential + " ", strings.Repeat("A", 42) + "B", credential[:42]} {
		request := httptest.NewRequest(http.MethodGet, "https://forge.test", nil)
		request.Header.Set("Cookie", browserSessionCookie+"="+invalid)
		value, err := BrowserSessionCredential(request)
		if value.Reveal() != "" || err != ErrBrowserBoundary {
			t.Fatal("noncanonical cookie accepted")
		}
		testutil.NoSecrets(t, fmt.Sprint(err), credential, csrf)
	}
	request := httptest.NewRequest(http.MethodGet, "https://forge.test", nil)
	request.Header["cookie"] = []string{valid, "other=ignored; " + browserFlowCookie + "=" + csrf}
	session, err := BrowserSessionCredential(request)
	binding, bindingErr := BrowserFlowBinding(request)
	if err != nil || bindingErr != nil || session.Reveal() != credential || binding.Reveal() != csrf {
		t.Fatal("canonical cookies rejected")
	}
	request.Header["Cookie"] = []string{valid}
	if _, err := BrowserSessionCredential(request); err != ErrBrowserBoundary {
		t.Fatal("case-aliased cookie duplicate accepted")
	}
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	flow, err := BrowserFlowCookie(binding, expiry)
	pair, pairErr := BrowserSessionCookies(&BrowserSessionCreated{session, binding, expiry})
	if err != nil || pairErr != nil || len(pair) != 2 {
		t.Fatal("cookie construction failed")
	}
	testutil.NoSecrets(t, fmt.Sprintf("%v %+v %#v", pair, flow, pair), credential, csrf)
	for _, header := range append(pair, flow) {
		cookie := (&http.Response{Header: http.Header{"Set-Cookie": []string{header.Reveal()}}}).Cookies()[0]
		if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || !cookie.Expires.Equal(expiry) || cookie.MaxAge != 0 {
			t.Fatal("host cookie attributes unsafe")
		}
		csrfCookie := cookie.Name == browserCSRFCookie
		if cookie.HttpOnly == csrfCookie || (csrfCookie && cookie.SameSite != http.SameSiteStrictMode) || (!csrfCookie && cookie.SameSite != http.SameSiteLaxMode) {
			t.Fatal("cookie confidentiality or same-site policy unsafe")
		}
	}
	for _, header := range ClearBrowserCookies() {
		cookie := (&http.Response{Header: http.Header{"Set-Cookie": []string{header.Reveal()}}}).Cookies()[0]
		if cookie.Value != "" || cookie.MaxAge != -1 || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || !cookie.Expires.Before(time.Now()) {
			t.Fatal("cookie deletion scope unsafe")
		}
	}
	if value, err := BrowserSessionCredential(nil); value.Reveal() != "" || err != ErrBrowserBoundary {
		t.Fatal("nil request accepted")
	}
	if _, err := BrowserFlowCookie(LoginFlowValue{}, expiry); err != ErrBrowserBoundary {
		t.Fatal("empty flow proof accepted")
	}
	if _, err := BrowserFlowCookie(binding, time.Now().Add(-time.Second)); err != ErrBrowserBoundary {
		t.Fatal("expired flow cookie accepted")
	}
	for _, created := range []*BrowserSessionCreated{nil, {session, binding, time.Time{}}, {LoginFlowValue{}, binding, expiry}, {session, LoginFlowValue{}, expiry}} {
		if _, err := BrowserSessionCookies(created); err != ErrBrowserBoundary {
			t.Fatal("invalid session cookie input accepted")
		}
	}
}

func TestBrowserMutationProofBinding(t *testing.T) {
	boundary, _ := NewBrowserBoundary("https://forge.test:8443", "https://forge.test:8443/auth/callback")
	credential, csrf := boundaryValue(1), boundaryValue(2)
	credentialHash, _ := loginFlowDigest(credential)
	csrfHash, _ := loginFlowDigest(csrf)
	session := BrowserSessionLookup{principal: VerifiedIdentity{issuer: "https://issuer.test", subject: "subject"}, expiresAt: time.Now().Add(time.Hour)}
	copy(session.credentialHash[:], credentialHash)
	copy(session.csrfHash[:], csrfHash)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		request := boundaryRequest(credential, csrf)
		request.Method = method
		if boundary.ValidateMutation(request, &session) != nil {
			t.Fatal("valid mutation proof rejected")
		}
	}
	for name, change := range map[string]func(*http.Request){
		"wrong origin":       func(r *http.Request) { r.Header.Set("Origin", "https://other.test") },
		"missing csrf":       func(r *http.Request) { r.Header.Del("X-Forge-CSRF") },
		"wrong csrf":         func(r *http.Request) { r.Header.Set("X-Forge-CSRF", boundaryValue(3)) },
		"quoted csrf":        func(r *http.Request) { r.Header.Set("X-Forge-CSRF", `"`+csrf+`"`) },
		"duplicate csrf":     func(r *http.Request) { r.Header.Add("X-Forge-CSRF", csrf) },
		"aliased csrf":       func(r *http.Request) { r.Header["x-forge-csrf"] = []string{csrf} },
		"missing credential": func(r *http.Request) { r.Header.Set("Cookie", browserCSRFCookie+"="+csrf) },
		"other credential same csrf": func(r *http.Request) {
			r.Header.Set("Cookie", browserSessionCookie+"="+boundaryValue(3)+"; "+browserCSRFCookie+"="+csrf)
		},
		"forged double submit": func(r *http.Request) {
			r.Header.Set("Cookie", browserSessionCookie+"="+credential+"; "+browserCSRFCookie+"="+boundaryValue(3))
			r.Header.Set("X-Forge-CSRF", boundaryValue(3))
		},
		"mixed auth": func(r *http.Request) { r.Header["authorization"] = []string{""} },
		"GET":        func(r *http.Request) { r.Method = http.MethodGet }, "HEAD": func(r *http.Request) { r.Method = http.MethodHead }, "OPTIONS": func(r *http.Request) { r.Method = http.MethodOptions }, "unknown": func(r *http.Request) { r.Method = "CUSTOM" },
	} {
		t.Run(name, func(t *testing.T) {
			request := boundaryRequest(credential, csrf)
			change(request)
			err := boundary.ValidateMutation(request, &session)
			if err != ErrBrowserBoundary {
				t.Fatal("invalid mutation proof accepted")
			}
			testutil.NoSecrets(t, fmt.Sprint(err), credential, csrf)
		})
	}
	request := boundaryRequest(credential, csrf)
	expired := session
	expired.expiresAt = time.Now().Add(-time.Second)
	for _, proof := range []*BrowserSessionLookup{nil, {}, &expired} {
		if boundary.ValidateMutation(request, proof) != ErrBrowserBoundary {
			t.Fatal("missing or expired lookup accepted")
		}
	}
	var absent *BrowserBoundary
	if absent.ValidateMutation(request, &session) != ErrBrowserBoundary || boundary.ValidateMutation(nil, &session) != ErrBrowserBoundary {
		t.Fatal("nil mutation boundary accepted")
	}
}

func TestBrowserBoundaryLookupPostgres(t *testing.T) {
	runtimeURL, ownerURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("DATABASE_URL")
	if runtimeURL == "" || ownerURL == "" {
		t.Skip("disposable PostgreSQL fixture required")
	}
	runtimeURL, _ = flowDatabase(t, runtimeURL, ownerURL)
	ctx := context.Background()
	pool := flowPool(t, runtimeURL, 1)
	server, key := oidcFixture(t, nil)
	providerCtx := oidc.ClientContext(ctx, server.Client())
	verifier, err := NewOIDCVerifier(providerCtx, server.URL, "boundary-client")
	if err != nil {
		t.Fatal("TLS verifier fixture failed")
	}
	raw := signedIDToken(t, key, map[string]any{"iss": server.URL, "sub": "boundary-subject", "aud": "boundary-client", "exp": time.Now().Add(time.Hour).Unix(), "nonce": "boundary-nonce"})
	identity, err := verifier.Verify(providerCtx, raw, "boundary-nonce")
	if err != nil {
		t.Fatal("verified identity fixture failed")
	}
	store, _ := NewBrowserSessionStore(pool)
	created, err := store.Create(ctx, identity)
	if err != nil {
		t.Fatal("session fixture failed")
	}
	found, err := store.Lookup(ctx, created.Credential.Reveal())
	if err != nil {
		t.Fatal("session lookup failed")
	}
	digest, _ := loginFlowDigest(created.Credential.Reveal())
	if !bytes.Equal(found.credentialHash[:], digest) {
		t.Fatal("lookup did not retain private credential binding")
	}
	boundary, _ := NewBrowserBoundary("https://forge.test:8443", "https://forge.test:8443/auth/callback")
	request := boundaryRequest(created.Credential.Reveal(), created.CSRF.Reveal())
	if boundary.ValidateMutation(request, found) != nil {
		t.Fatal("real lookup mutation proof failed")
	}
	request.Header.Set("Cookie", browserSessionCookie+"="+boundaryValue(3)+"; "+browserCSRFCookie+"="+created.CSRF.Reveal())
	if boundary.ValidateMutation(request, found) != ErrBrowserBoundary {
		t.Fatal("real lookup accepted another credential")
	}
	testutil.NoSecrets(t, fmt.Sprintf("%v %+v %#v", found, *found, found), created.Credential.Reveal(), created.CSRF.Reveal(), hex.EncodeToString(digest), raw)
}
