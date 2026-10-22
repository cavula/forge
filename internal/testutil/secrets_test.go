package testutil

import "testing"

type recorder struct{ failed bool }

func (*recorder) Helper()                 {}
func (r *recorder) Fatalf(string, ...any) { r.failed = true }
func TestNoSecrets(t *testing.T) {
	for _, tc := range []struct {
		output, secret string
		want           bool
	}{{"safe", "token", false}, {"token", "token", true}, {"safe", "", false}} {
		r := &recorder{}
		NoSecrets(r, tc.output, tc.secret)
		if r.failed != tc.want {
			t.Fatal("secret assertion did not detect leak correctly")
		}
	}
}
