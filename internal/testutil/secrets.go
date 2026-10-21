// Package testutil holds security assertions shared by platform tests.
package testutil

import "strings"

type testingT interface {
	Helper()
	Fatalf(string, ...any)
}

// NoSecrets deliberately omits the sensitive value from failure diagnostics.
func NoSecrets(t testingT, output string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(output, secret) {
			t.Fatalf("sensitive value appeared in captured output")
		}
	}
}
