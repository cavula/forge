package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/cavula/forge/internal/testutil"
)

var authFlowContext = AuthFlowContext{"f738e08b-c4be-4f9c-b66f-d305e4d47146", 1}

func authFlowFixture(t *testing.T) *AuthFlowKey {
	t.Helper()
	k, err := NewAuthFlowKey(fixtureKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAuthFlowRoundTripAndConcurrency(t *testing.T) {
	k := authFlowFixture(t)
	for _, value := range [][]byte{nil, {}, {0, 255, 1}, bytes.Repeat([]byte("X"), MaxAuthFlowPayload)} {
		e, err := k.Seal(authFlowContext, value)
		if err != nil || len(e.Ciphertext) != len(value)+16 || len(e.Nonce) != 12 || len(e.WrappedDEK) != 60 || e.KeyID != k.local.id {
			t.Fatal("encryption or metadata failed")
		}
		if got, err := k.Open(authFlowContext, e); err != nil || !bytes.Equal(got, value) {
			t.Fatal("round trip failed")
		}
	}
	const count = 24
	results := make(chan Envelope, count)
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			e, err := k.Seal(authFlowContext, []byte("same payload"))
			if err != nil {
				t.Error(err)
				return
			}
			if got, err := k.Open(authFlowContext, e); err != nil || string(got) != "same payload" {
				t.Error("concurrent round trip failed")
			}
			results <- e
		})
	}
	wg.Wait()
	close(results)
	seen := [4]map[string]bool{{}, {}, {}, {}}
	aad, _ := authFlowContext.associatedData()
	for e := range results {
		dek, err := newGCM(k.local.key[:]).Open(nil, e.WrappedDEK[:12], e.WrappedDEK[12:], k.wrapAAD(aad))
		if err != nil {
			t.Fatal("cannot inspect fixture DEK")
		}
		for i, value := range [][]byte{e.Ciphertext, e.Nonce, e.WrappedDEK[:12], dek} {
			if seen[i][string(value)] {
				t.Fatal("random material reused")
			}
			seen[i][string(value)] = true
		}
		clear(dek)
	}
}

func TestAuthFlowRejectsTampering(t *testing.T) {
	k := authFlowFixture(t)
	encrypted, _ := k.Seal(authFlowContext, []byte("private nonce and verifier"))
	for name, mutate := range map[string]func(*Envelope){
		"data":        func(e *Envelope) { e.Ciphertext[0] ^= 1 },
		"nonce":       func(e *Envelope) { e.Nonce[0] ^= 1 },
		"wrap nonce":  func(e *Envelope) { e.WrappedDEK[0] ^= 1 },
		"wrapped key": func(e *Envelope) { e.WrappedDEK[12] ^= 1 },
		"key ID":      func(e *Envelope) { e.KeyID = "unknown" },
		"short data":  func(e *Envelope) { e.Ciphertext = e.Ciphertext[:15] },
		"long data":   func(e *Envelope) { e.Ciphertext = make([]byte, MaxAuthFlowPayload+17) },
		"short nonce": func(e *Envelope) { e.Nonce = e.Nonce[:11] },
		"long nonce":  func(e *Envelope) { e.Nonce = append(e.Nonce, 0) },
		"short wrap":  func(e *Envelope) { e.WrappedDEK = e.WrappedDEK[:59] },
		"long wrap":   func(e *Envelope) { e.WrappedDEK = append(e.WrappedDEK, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			e := Envelope{bytes.Clone(encrypted.Ciphertext), bytes.Clone(encrypted.WrappedDEK), bytes.Clone(encrypted.Nonce), encrypted.KeyID}
			mutate(&e)
			if got, err := k.Open(authFlowContext, e); got != nil || err != ErrDecryption {
				t.Fatal("tampering returned plaintext")
			}
		})
	}
	wrongFlow := AuthFlowContext{"ae2a8540-a0bb-48d0-a460-f72de1dfc705", 1}
	if got, err := k.Open(wrongFlow, encrypted); got != nil || err != ErrDecryption {
		t.Fatal("flow substitution accepted")
	}
	for _, config := range []struct{ id, material string }{{"master-v1", "Z"}, {"other-key", "K"}} {
		local, _ := NewLocalKey(config.id, bytes.Repeat([]byte(config.material), 32))
		other, _ := NewAuthFlowKey(local)
		e := encrypted
		e.KeyID = config.id // A renamed ID with identical material must also fail.
		if got, err := other.Open(authFlowContext, e); got != nil || err != ErrDecryption {
			t.Fatal("wrong key or key ID binding accepted")
		}
	}
}

func TestAuthFlowDomainSeparation(t *testing.T) {
	k := authFlowFixture(t)
	// Share keys only in this fixture so AAD alone must reject both directions.
	tenant := Context{"149b286b-58fc-4433-af7d-33c8d65078d7", authFlowContext.FlowID, "state", 1}
	e, _ := k.local.Seal(tenant, []byte("tenant state"))
	if got, err := k.Open(authFlowContext, e); got != nil || err != ErrDecryption {
		t.Fatal("tenant envelope accepted in auth domain")
	}
	e, _ = k.Seal(authFlowContext, []byte("login material"))
	if got, err := k.local.Open(tenant, e); got != nil || err != ErrDecryption {
		t.Fatal("auth envelope accepted in tenant domain")
	}
	aad, _ := authFlowContext.associatedData()
	for _, domain := range []string{"data", "wrap", "purpose"} {
		dataAAD, wrapAAD := bytes.Clone(aad), k.wrapAAD(aad)
		switch domain {
		case "data":
			dataAAD[0] ^= 1
		case "wrap":
			wrapAAD[0] ^= 1
		case "purpose":
			dataAAD = bytes.Replace(dataAAD, []byte(authFlowPurpose), []byte("forge/auth/other-flow/v1"), 1)
		}
		dek, nonce, wrapNonce := bytes.Repeat([]byte("D"), 32), make([]byte, 12), make([]byte, 12)
		e := Envelope{newGCM(dek).Seal(nil, nonce, nil, dataAAD), newGCM(k.local.key[:]).Seal(wrapNonce, wrapNonce, dek, wrapAAD), nonce, k.local.id}
		if got, err := k.Open(authFlowContext, e); got != nil || err != ErrDecryption {
			t.Fatal("wrong domain/purpose accepted:", domain)
		}
	}
}

func TestAuthFlowInvalidConfigurationAndEntropy(t *testing.T) {
	k := authFlowFixture(t)
	for _, ctx := range []AuthFlowContext{{}, {authFlowContext.FlowID, 0}, {authFlowContext.FlowID, 2}, {"bad", 1}, {strings.ToUpper(authFlowContext.FlowID), 1}, {strings.Replace(authFlowContext.FlowID, "-", "x", 1), 1}, {"g" + authFlowContext.FlowID[1:], 1}} {
		if e, err := k.Seal(ctx, nil); err != ErrInvalidContext || e.KeyID != "" {
			t.Fatal("invalid context encrypted")
		}
		if got, err := k.Open(ctx, Envelope{}); err != ErrInvalidContext || got != nil {
			t.Fatal("invalid context decrypted")
		}
	}
	for _, local := range []*LocalKey{nil, {}, {id: "missing randomness"}} {
		if got, err := NewAuthFlowKey(local); got != nil || err != ErrInvalidKey {
			t.Fatal("invalid dependency accepted")
		}
	}
	for _, invalid := range []*AuthFlowKey{nil, {}} {
		if _, err := invalid.Seal(authFlowContext, nil); err != ErrInvalidKey {
			t.Fatal("missing key encrypted")
		}
		if got, err := invalid.Open(authFlowContext, Envelope{}); got != nil || err != ErrInvalidKey {
			t.Fatal("lost key returned plaintext")
		}
	}
	if e, err := k.Seal(authFlowContext, make([]byte, MaxAuthFlowPayload+1)); err != ErrEncryption || e.KeyID != "" {
		t.Fatal("oversized payload accepted")
	}
	for _, available := range []int{0, 31, 32, 43, 44, 55} {
		k.local.random = io.LimitReader(bytes.NewReader(make([]byte, 56)), int64(available))
		e, err := k.Seal(authFlowContext, []byte("secret payload"))
		if err != ErrEncryption || len(e.Ciphertext)+len(e.WrappedDEK)+len(e.Nonce) != 0 || e.KeyID != "" {
			t.Fatal("random failure returned partial material")
		}
	}
	entropy := &authEntropyFailure{}
	k.local.random = entropy
	if _, err := k.Seal(authFlowContext, []byte("private entropy payload")); err != ErrEncryption {
		t.Fatal("entropy diagnostic leaked or succeeded")
	}
	if len(entropy.dek) != 32 || !bytes.Equal(entropy.dek, make([]byte, 32)) {
		t.Fatal("temporary DEK survived encryption failure")
	}
	local := fixtureKey(t)
	copyKey, _ := NewAuthFlowKey(local)
	clear(local.key[:])
	e, _ := copyKey.Seal(authFlowContext, nil)
	if _, err := authFlowFixture(t).Open(authFlowContext, e); err != nil {
		t.Fatal("auth constructor failed to copy key")
	}
}

type authEntropyFailure struct{ dek []byte }

func (r *authEntropyFailure) Read(p []byte) (int, error) {
	if r.dek != nil {
		return 0, fmt.Errorf("%s private entropy payload", authFlowContext.FlowID)
	}
	r.dek = p
	copy(p, bytes.Repeat([]byte("D"), len(p)))
	return len(p), nil
}

func TestAuthFlowDiagnostics(t *testing.T) {
	k := authFlowFixture(t)
	plaintext := "private nonce/PKCE payload"
	e, _ := k.Seal(authFlowContext, []byte(plaintext))
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("crypto", "key", k, "context", authFlowContext, "envelope", e)
	for _, value := range []any{k, *k, authFlowContext, &authFlowContext, e, &e, ErrEncryption, ErrDecryption, ErrInvalidContext, ErrInvalidKey} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
			logs.WriteString(fmt.Sprintf(format, value))
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		logs.Write(encoded)
	}
	testutil.NoSecrets(t, logs.String(), plaintext, authFlowContext.FlowID, k.local.id, string(k.local.key[:]), string(e.Ciphertext), string(e.WrappedDEK), base64.StdEncoding.EncodeToString(e.WrappedDEK))
}
