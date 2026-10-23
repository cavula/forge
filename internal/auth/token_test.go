package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/cavula/forge/internal/testutil"
)

func TestTokenRoundTrip(t *testing.T) {
	token, verifier, err := NewToken()
	if err != nil {
		t.Fatal("token issuance failed")
	}
	parsed, selector, err := ParseToken(token.Reveal())
	if err != nil || parsed.Reveal() != token.Reveal() || selector != verifier.Selector {
		t.Fatal("issued credential did not round trip")
	}
	if verifier.Digest != sha256.Sum256([]byte(token.Reveal())) || !verifier.Matches(parsed) {
		t.Fatal("verifier does not bind the complete credential")
	}
	parts := strings.Split(token.Reveal(), ".")
	for i, size := range []int{16, 32} {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[i+1])
		if err != nil || len(decoded) != size {
			t.Fatal("issued component has invalid encoding or entropy length")
		}
	}
	other, otherVerifier, err := NewToken()
	if err != nil {
		t.Fatal("second token issuance failed")
	}
	otherParts := strings.Split(other.Reveal(), ".")
	for _, raw := range []string{
		"forge_v1." + otherParts[1] + "." + parts[2],
		"forge_v1." + parts[1] + "." + otherParts[2],
		other.Reveal(),
	} {
		candidate, _, err := ParseToken(raw)
		if err != nil || verifier.Matches(candidate) {
			t.Fatal("changed credential component was not rejected")
		}
	}
	if otherVerifier.Matches(token) || (TokenVerifier{}).Matches(token) || verifier.Matches(Token{}) || (TokenVerifier{}).Matches(Token{}) {
		t.Fatal("wrong or zero credential/verifier matched")
	}
	wrongSelector := verifier
	wrongSelector.Selector = otherVerifier.Selector
	if wrongSelector.Matches(token) {
		t.Fatal("verifier accepted a mismatched lookup selector")
	}
}

func TestTokenRandomUniqueness(t *testing.T) {
	seenTokens, seenSelectors := map[string]bool{}, map[string]bool{}
	for range 32 {
		token, verifier, err := NewToken()
		if err != nil || seenTokens[token.Reveal()] || seenSelectors[verifier.Selector] {
			t.Fatal("token issuance failed or repeated entropy")
		}
		seenTokens[token.Reveal()], seenSelectors[verifier.Selector] = true, true
	}
}

func TestTokenRejectMalformed(t *testing.T) {
	selector, secret := strings.Repeat("A", 22), strings.Repeat("A", 43)
	valid := "forge_v1." + selector + "." + secret
	if _, _, err := ParseToken(valid); err != nil {
		t.Fatal("canonical boundary fixture rejected")
	}
	cases := map[string]string{
		"empty": "", "short": valid[:len(valid)-1], "long": valid + "A",
		"version":       strings.Replace(valid, "v1", "v2", 1),
		"prefix case":   strings.Replace(valid, "forge", "Forge", 1),
		"leading space": " " + valid, "trailing space": valid + " ",
		"newline":                 "forge_v1." + selector[:21] + "\n." + secret,
		"internal space":          "forge_v1." + selector[:21] + " ." + secret,
		"padding selector":        "forge_v1." + selector[:21] + "=." + secret,
		"padding secret":          valid[:len(valid)-1] + "=",
		"noncanonical selector":   "forge_v1." + selector[:21] + "B." + secret,
		"noncanonical secret":     valid[:len(valid)-1] + "B",
		"standard alphabet plus":  "forge_v1.+" + selector[1:] + "." + secret,
		"standard alphabet slash": valid[:len(valid)-1] + "/",
		"extra separator":         "forge_v1." + selector[:21] + ".." + secret,
		"missing selector":        "forge_v1.." + secret,
		"missing secret":          "forge_v1." + selector + ".",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			token, selected, err := ParseToken(raw)
			if err == nil || token.Reveal() != "" || selected != "" {
				t.Fatal("invalid credential accepted or partially returned")
			}
			if err.Error() != "invalid API token" {
				t.Fatal("parse error was not generic")
			}
			testutil.NoSecrets(t, err.Error(), raw, selector, secret)
		})
	}
}

type failingEntropy struct{}

func (failingEntropy) Read(p []byte) (int, error) {
	copy(p, "sensitive-entropy-source")
	return 7, errors.New("sensitive-entropy-source")
}

func TestTokenEntropyFailure(t *testing.T) {
	for _, reader := range []io.Reader{bytes.NewReader(make([]byte, 47)), failingEntropy{}} {
		token, verifier, err := newToken(reader)
		if err == nil || token.Reveal() != "" || verifier != (TokenVerifier{}) {
			t.Fatal("entropy failure returned partial credentials")
		}
		if err.Error() != "API token generation failed" {
			t.Fatal("generation error was not generic")
		}
		testutil.NoSecrets(t, err.Error(), "sensitive-entropy-source")
	}
}

func TestTokenDiagnosticRedaction(t *testing.T) {
	token, verifier, err := NewToken()
	if err != nil {
		t.Fatal("token issuance failed")
	}
	parts := strings.Split(token.Reveal(), ".")
	var captured bytes.Buffer
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X"} {
		for _, value := range []any{token, &token, verifier, &verifier} {
			_, _ = fmt.Fprintf(&captured, format, value)
		}
	}
	_, _ = fmt.Fprint(&captured, token.String(), token.GoString(), verifier.String(), verifier.GoString())
	for _, value := range []interface{ MarshalText() ([]byte, error) }{token, verifier} {
		text, err := value.MarshalText()
		if err != nil {
			t.Fatal("redacted text serialization failed")
		}
		captured.Write(text)
	}
	encoded, err := json.Marshal(map[string]any{"token": token, "pointer": &token, "verifier": verifier, "verifier_pointer": &verifier})
	if err != nil {
		t.Fatal("redacted JSON serialization failed")
	}
	captured.Write(encoded)
	slog.New(slog.NewJSONHandler(&captured, nil)).Info("credential diagnostics", "token", token, "verifier", verifier)
	testutil.NoSecrets(t, captured.String(), token.Reveal(), parts[1], parts[2], fmt.Sprint(verifier.Digest), fmt.Sprintf("%x", verifier.Digest), base64.StdEncoding.EncodeToString(verifier.Digest[:]))
	if !strings.Contains(captured.String(), "[REDACTED]") {
		t.Fatal("diagnostics did not produce a redaction marker")
	}
}
