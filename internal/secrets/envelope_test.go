package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/cavula/forge/internal/testutil"
)

var testContext = Context{OrgID: "org-a", ResourceID: "state-v1", Purpose: "state", Version: 1}

func fixtureKey(t *testing.T) *LocalKey {
	t.Helper()
	k, err := NewLocalKey("master-v1", bytes.Repeat([]byte("K"), 32))
	if err != nil {
		t.Fatal("construct local key:", err)
	}
	return k
}

func TestEnvelopeRoundTrip(t *testing.T) {
	k := fixtureKey(t)
	for _, plaintext := range [][]byte{nil, {}, []byte("sensitive state"), {0, 255, 1}} {
		encrypted, err := k.Seal(testContext, plaintext)
		if err != nil {
			t.Fatal("encrypt:", err)
		}
		if len(encrypted.Ciphertext) != len(plaintext)+16 || len(encrypted.WrappedDEK) != 60 || len(encrypted.Nonce) != 12 || encrypted.KeyID != "master-v1" {
			t.Fatal("incorrect envelope metadata")
		}
		got, err := k.Open(testContext, encrypted)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatal("round trip failed")
		}
	}
}

func TestEnvelopeRandomnessAndConcurrency(t *testing.T) {
	k := fixtureKey(t)
	const count = 24
	envelopes := make(chan Envelope, count)
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			e, err := k.Seal(testContext, []byte("same plaintext"))
			if err != nil {
				t.Error("encrypt:", err)
				return
			}
			envelopes <- e
		})
	}
	wg.Wait()
	close(envelopes)
	seen := [3]map[string]bool{{}, {}, {}}
	for e := range envelopes {
		for i, value := range [][]byte{e.Ciphertext, e.Nonce, e.WrappedDEK} {
			if seen[i][string(value)] {
				t.Fatal("encryption reused random material")
			}
			seen[i][string(value)] = true
		}
	}
}

func TestEnvelopeRejectsSubstitutionAndTampering(t *testing.T) {
	k := fixtureKey(t)
	encrypted, err := k.Seal(testContext, []byte("secret value"))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Envelope){
		"ciphertext":        func(e *Envelope) { e.Ciphertext[0] ^= 1 },
		"nonce":             func(e *Envelope) { e.Nonce[0] ^= 1 },
		"wrapping nonce":    func(e *Envelope) { e.WrappedDEK[0] ^= 1 },
		"wrapped key":       func(e *Envelope) { e.WrappedDEK[12] ^= 1 },
		"key id":            func(e *Envelope) { e.KeyID = "unknown-key" },
		"short ciphertext":  func(e *Envelope) { e.Ciphertext = e.Ciphertext[:15] },
		"short nonce":       func(e *Envelope) { e.Nonce = e.Nonce[:11] },
		"long nonce":        func(e *Envelope) { e.Nonce = append(e.Nonce, 0) },
		"short wrapped key": func(e *Envelope) { e.WrappedDEK = e.WrappedDEK[:59] },
		"long wrapped key":  func(e *Envelope) { e.WrappedDEK = append(e.WrappedDEK, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			e := Envelope{Ciphertext: bytes.Clone(encrypted.Ciphertext), Nonce: bytes.Clone(encrypted.Nonce), WrappedDEK: bytes.Clone(encrypted.WrappedDEK), KeyID: encrypted.KeyID}
			mutate(&e)
			if got, err := k.Open(testContext, e); got != nil || !errors.Is(err, ErrDecryption) {
				t.Fatal("tampering did not fail closed")
			}
		})
	}
	for _, ctx := range []Context{
		{"org-b", "state-v1", "state", 1}, {"org-a", "state-v2", "state", 1},
		{"org-a", "state-v1", "secret", 1}, {"org-a", "state-v1", "state", 2},
	} {
		if got, err := k.Open(ctx, encrypted); got != nil || !errors.Is(err, ErrDecryption) {
			t.Fatal("context substitution did not fail closed")
		}
	}
	other, _ := NewLocalKey("master-v1", bytes.Repeat([]byte("X"), 32))
	if got, err := other.Open(testContext, encrypted); got != nil || !errors.Is(err, ErrDecryption) {
		t.Fatal("wrong master key accepted")
	}
}

func TestEnvelopeInvalidInputsAndEntropyFailure(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if key, err := NewLocalKey("key", make([]byte, n)); key != nil || !errors.Is(err, ErrInvalidKey) {
			t.Fatal("invalid master key accepted")
		}
	}
	if key, err := NewLocalKey("", make([]byte, 32)); key != nil || !errors.Is(err, ErrInvalidKey) {
		t.Fatal("empty key identifier accepted")
	}
	k := fixtureKey(t)
	for _, ctx := range []Context{{}, {"", "id", "state", 1}, {"org", "", "state", 1}, {"org", "id", "", 1}, {"org", "id", "state", 0}} {
		if _, err := k.Seal(ctx, nil); !errors.Is(err, ErrInvalidContext) {
			t.Fatal("invalid encryption context accepted")
		}
		if got, err := k.Open(ctx, Envelope{}); got != nil || !errors.Is(err, ErrInvalidContext) {
			t.Fatal("invalid decryption context accepted")
		}
	}
	for _, invalid := range []*LocalKey{nil, {}} {
		if _, err := invalid.Seal(testContext, nil); !errors.Is(err, ErrInvalidKey) {
			t.Fatal("unconfigured key encrypted data")
		}
		if got, err := invalid.Open(testContext, Envelope{}); got != nil || !errors.Is(err, ErrInvalidKey) {
			t.Fatal("unconfigured key accepted envelope")
		}
	}
	for _, available := range []int{0, 31, 32, 43, 44, 55} {
		k.random = io.LimitReader(bytes.NewReader(make([]byte, 56)), int64(available))
		got, err := k.Seal(testContext, []byte("secret"))
		if !errors.Is(err, ErrEncryption) || len(got.Ciphertext)+len(got.WrappedDEK)+len(got.Nonce) != 0 || got.KeyID != "" {
			t.Fatal("entropy failure returned partial envelope")
		}
	}
}

func TestEnvelopeContextEncodingAndKeyCopy(t *testing.T) {
	a, _ := (Context{"a", "bc", "d", 1}).associatedData()
	b, _ := (Context{"ab", "c", "d", 1}).associatedData()
	if bytes.Equal(a, b) {
		t.Fatal("context encoding has ambiguous field boundaries")
	}
	master := bytes.Repeat([]byte("M"), 32)
	k, _ := NewLocalKey("master", master)
	clear(master)
	peer, _ := NewLocalKey("master", bytes.Repeat([]byte("M"), 32))
	e, _ := k.Seal(testContext, []byte("plaintext"))
	if _, err := peer.Open(testContext, e); err != nil {
		t.Fatal("constructor did not copy master key")
	}
}

func TestEnvelopeDiagnosticRedaction(t *testing.T) {
	k := fixtureKey(t)
	plaintext := "secret payload never log"
	e, _ := k.Seal(testContext, []byte(plaintext))
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("test", "key", k, "envelope", e)
	for _, value := range []any{k, *k, e, &e} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
			logs.WriteString(fmt.Sprintf(format, value))
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		logs.Write(encoded)
	}
	testutil.NoSecrets(t, logs.String(), plaintext, string(k.key[:]), "master-v1", string(e.Ciphertext), string(e.WrappedDEK), base64.StdEncoding.EncodeToString(e.Ciphertext), base64.StdEncoding.EncodeToString(e.WrappedDEK))
}
