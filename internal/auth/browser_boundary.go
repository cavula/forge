package auth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	browserSessionCookie  = "__Host-forge-session"
	browserFlowCookie     = "__Host-forge-login"
	browserCSRFCookie     = "__Host-forge-csrf"
	maxBrowserCookieBytes = 8 * 1024
)

var ErrBrowserBoundary = errors.New("browser authentication unavailable")

type BrowserBoundary struct{ origin, callback string }

// NewBrowserBoundary supports only explicitly configured production HTTPS.
func NewBrowserBoundary(origin, callback string) (*BrowserBoundary, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || origin != "https://"+parsed.Host || callback != origin+"/auth/callback" {
		return nil, ErrBrowserBoundary
	}
	return &BrowserBoundary{origin, callback}, nil
}

func (boundary *BrowserBoundary) CheckOrigin(request *http.Request) error {
	origin, single := boundaryHeader(request, "Origin")
	if boundary == nil || boundary.origin == "" || !single || origin != boundary.origin {
		return ErrBrowserBoundary
	}
	return nil
}

func boundaryHeader(request *http.Request, name string) (string, bool) {
	if request == nil {
		return "", false
	}
	value, count := "", 0
	for key, values := range request.Header {
		if strings.EqualFold(key, name) {
			for _, entry := range values {
				value, count = entry, count+1
			}
		}
	}
	return value, count == 1
}

// browserCookies deliberately avoids net/http's permissive quoted-value parser.
func browserCookies(request *http.Request) (map[string]string, error) {
	if request == nil {
		return nil, ErrBrowserBoundary
	}
	cookies, size := make(map[string]string), 0
	for key, headers := range request.Header {
		if !strings.EqualFold(key, "Cookie") {
			continue
		}
		for _, header := range headers {
			if len(header) >= maxBrowserCookieBytes-size {
				return nil, ErrBrowserBoundary
			}
			size += len(header) + 1
			for _, field := range strings.Split(header, ";") {
				rawName, value, paired := strings.Cut(strings.TrimLeft(field, " \t"), "=")
				name := strings.TrimSpace(rawName)
				if name != browserSessionCookie && name != browserFlowCookie && name != browserCSRFCookie {
					continue
				}
				if _, duplicate := cookies[name]; duplicate || !paired || name != rawName {
					return nil, ErrBrowserBoundary
				}
				if _, canonical := loginFlowDigest(value); !canonical {
					return nil, ErrBrowserBoundary
				}
				cookies[name] = value
			}
		}
	}
	return cookies, nil
}

func browserCredential(request *http.Request, name string) (LoginFlowValue, error) {
	cookies, err := browserCookies(request)
	if err != nil || cookies[name] == "" {
		return LoginFlowValue{}, ErrBrowserBoundary
	}
	return LoginFlowValue{cookies[name]}, nil
}

func BrowserSessionCredential(request *http.Request) (LoginFlowValue, error) {
	return browserCredential(request, browserSessionCookie)
}
func BrowserFlowBinding(request *http.Request) (LoginFlowValue, error) {
	return browserCredential(request, browserFlowCookie)
}

// ValidateMutation binds the request's credential and CSRF proofs to one Lookup.
// It does not resolve membership, execute mutations or expose a route.
func (boundary *BrowserBoundary) ValidateMutation(request *http.Request, session *BrowserSessionLookup) error {
	if boundary.CheckOrigin(request) != nil || session == nil || !session.expiresAt.After(time.Now()) || session.principal.issuer == "" || session.principal.subject == "" {
		return ErrBrowserBoundary
	}
	switch request.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return ErrBrowserBoundary
	}
	for key := range request.Header {
		if strings.EqualFold(key, "Authorization") {
			return ErrBrowserBoundary
		}
	}
	cookies, err := browserCookies(request)
	if err != nil {
		return ErrBrowserBoundary
	}
	credential, credentialOK := loginFlowDigest(cookies[browserSessionCookie])
	csrf, csrfOK := loginFlowDigest(cookies[browserCSRFCookie])
	header, single := boundaryHeader(request, "X-Forge-CSRF")
	_, headerOK := loginFlowDigest(header)
	if !credentialOK || !csrfOK || !single || !headerOK {
		return ErrBrowserBoundary
	}
	matches := subtle.ConstantTimeCompare([]byte(cookies[browserCSRFCookie]), []byte(header))
	matches &= subtle.ConstantTimeCompare(csrf, session.csrfHash[:])
	matches &= subtle.ConstantTimeCompare(credential, session.credentialHash[:])
	if matches != 1 {
		return ErrBrowserBoundary
	}
	return nil
}

func browserCookie(name, value string, expiry time.Time) *http.Cookie {
	cookie := &http.Cookie{Name: name, Value: value, Path: "/", Expires: expiry.UTC(), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if name == browserCSRFCookie {
		cookie.HttpOnly, cookie.SameSite = false, http.SameSiteStrictMode
	}
	return cookie
}

// BrowserFlowCookie requires the actual persisted flow expiry from trusted code.
func BrowserFlowCookie(binding LoginFlowValue, expiry time.Time) (LoginFlowValue, error) {
	if _, valid := loginFlowDigest(binding.Reveal()); !valid || !expiry.After(time.Now()) {
		return LoginFlowValue{}, ErrBrowserBoundary
	}
	return LoginFlowValue{browserCookie(browserFlowCookie, binding.Reveal(), expiry).String()}, nil
}

// BrowserSessionCookies must be used only after successful committed persistence.
func BrowserSessionCookies(created *BrowserSessionCreated) ([]LoginFlowValue, error) {
	if created == nil || !created.ExpiresAt.After(time.Now()) {
		return nil, ErrBrowserBoundary
	}
	if _, valid := loginFlowDigest(created.Credential.Reveal()); !valid {
		return nil, ErrBrowserBoundary
	}
	if _, valid := loginFlowDigest(created.CSRF.Reveal()); !valid {
		return nil, ErrBrowserBoundary
	}
	return []LoginFlowValue{{browserCookie(browserSessionCookie, created.Credential.Reveal(), created.ExpiresAt).String()}, {browserCookie(browserCSRFCookie, created.CSRF.Reveal(), created.ExpiresAt).String()}}, nil
}

// ClearBrowserCookies only builds descriptors; logout must first commit revocation.
func ClearBrowserCookies() []LoginFlowValue {
	var cookies []LoginFlowValue
	for _, name := range []string{browserSessionCookie, browserFlowCookie, browserCSRFCookie} {
		cookie := browserCookie(name, "", time.Unix(1, 0))
		cookie.MaxAge = -1
		cookies = append(cookies, LoginFlowValue{cookie.String()})
	}
	return cookies
}
