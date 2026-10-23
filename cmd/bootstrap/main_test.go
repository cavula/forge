package main

import (
	"context"
	"os"
	"testing"

	"github.com/cavula/forge/internal/orgs"
	"github.com/cavula/forge/internal/testutil"
)

func TestBootstrapCommandFailsGenerically(t *testing.T) {
	args := os.Args
	t.Cleanup(func() { os.Args = args })
	for _, tc := range []struct {
		name, owner string
		args        []string
	}{
		{"no owner fallback", "", []string{"bootstrap"}},
		{"invalid owner URL", "://private-operator-credential", []string{"bootstrap"}},
		{"unexpected identity argument", "unused", []string{"bootstrap", "private-subject"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			t.Setenv("FORGE_BOOTSTRAP_OWNER_URL", tc.owner)
			t.Setenv("DATABASE_URL", "private-runtime-credential")
			id, err := bootstrap(context.Background())
			if id != "" || err != orgs.ErrBootstrap {
				t.Fatal("command exposed an unexpected result")
			}
			testutil.NoSecrets(t, err.Error(), "private-operator-credential", "private-runtime-credential", "private-subject")
		})
	}
}
