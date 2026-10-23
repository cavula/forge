package stacks

import (
	"strings"
	"testing"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
	"google.golang.org/protobuf/proto"
)

func environmentEntry(name, value string) *forgev1.StackEnvironmentVariable {
	return &forgev1.StackEnvironmentVariable{Name: name, Value: value}
}

func requireInvalidEnvironment(t *testing.T, entries []*forgev1.StackEnvironmentVariable) {
	t.Helper()
	got, err := normalizeEnvironment(entries)
	if err != errEnvironment || err.Error() != "invalid environment_variables" || got != nil {
		t.Fatal("invalid environment did not return only its fixed generic category")
	}
}

func TestNormalizeEnvironmentCopiesAndSorts(t *testing.T) {
	input := []*forgev1.StackEnvironmentVariable{
		environmentEntry("z", "last"), environmentEntry("a", "lower"), environmentEntry("A", "upper"),
	}
	input[0].ProtoReflect().SetUnknown([]byte{0x18, 0x01})
	snapshots := make([]*forgev1.StackEnvironmentVariable, len(input))
	for i, entry := range input {
		snapshots[i] = proto.Clone(entry).(*forgev1.StackEnvironmentVariable)
	}
	got, err := normalizeEnvironment(input)
	if err != nil || len(got) != 3 {
		t.Fatal("valid environment rejected")
	}
	for i, want := range []string{"A", "a", "z"} {
		if got[i].Name != want || len(got[i].ProtoReflect().GetUnknown()) != 0 {
			t.Fatal("normalization did not return sorted current-schema entries")
		}
		for _, entry := range input {
			if entry == got[i] {
				t.Fatal("normalization retained an input message")
			}
		}
	}
	got[2].Name, got[2].Value = "changed", "changed"
	got[0] = environmentEntry("replacement", "replacement")
	for i, entry := range input {
		if !proto.Equal(entry, snapshots[i]) {
			t.Fatal("normalization or output mutation changed the input")
		}
	}
	for _, entries := range [][]*forgev1.StackEnvironmentVariable{nil, {}} {
		got, err := normalizeEnvironment(entries)
		if err != nil || len(got) != 0 {
			t.Fatal("empty environment rejected")
		}
	}
}

func TestNormalizeEnvironmentNamesAndValues(t *testing.T) {
	validNames := []string{"_", "a", "Name_012", strings.Repeat("A", 64), "TF_VAR_", "TF_VAR_project", "TOKENIZED", "APP_TOKEN_LABEL"}
	validValues := []string{"", "ordinary text", "München 東京", "inside\u00a0space", "inside\u2028space", strings.Repeat("a", 4096), strings.Repeat("é", 2048)}
	for _, name := range validNames {
		for _, value := range validValues {
			got, err := normalizeEnvironment([]*forgev1.StackEnvironmentVariable{environmentEntry(name, value)})
			if err != nil || len(got) != 1 || got[0].Name != name || got[0].Value != value {
				t.Fatal("valid name or value was rejected or rewritten")
			}
		}
	}
	invalidNames := []string{"", "1NAME", "a-b", "a.b", "a=b", "a/b", "a:b", "a b", "\tAPP", "APP\n", " APP", "APP ", "é", "APP\x00", "APP\xff", strings.Repeat("a", 65)}
	for _, name := range invalidNames {
		requireInvalidEnvironment(t, []*forgev1.StackEnvironmentVariable{environmentEntry(name, "value-sentinel")})
	}
	invalidValues := []string{" value-sentinel", "value-sentinel ", "\u00a0value-sentinel", "value-sentinel\u2003", " ", "\t", "a\x00b", "a\tb", "a\nb", "a\rb", "a\x1fb", "a\x7fb", "a\u0085b", "a\u009fb", "a\xffb", strings.Repeat("a", 4097), strings.Repeat("é", 2049)}
	for _, value := range invalidValues {
		requireInvalidEnvironment(t, []*forgev1.StackEnvironmentVariable{environmentEntry("NAME_SENTINEL", value)})
	}
	requireInvalidEnvironment(t, []*forgev1.StackEnvironmentVariable{nil})
	requireInvalidEnvironment(t, []*forgev1.StackEnvironmentVariable{environmentEntry("APP", "first"), environmentEntry("APP", "second")})
}

func TestNormalizeEnvironmentProtectedNames(t *testing.T) {
	prefixes := []string{"FORGE_", "LD_", "DYLD_", "GIT_", "SSH_", "TF_CLI_", "TF_LOG", "TF_PLUGIN_", "TF_REATTACH_", "AWS_", "GOOGLE_", "GCLOUD_", "CLOUDSDK_", "AZURE_", "ARM_"}
	protected := []string{"PATH", "HOME", "USER", "LOGNAME", "SHELL", "IFS", "ENV", "BASH_ENV", "TMPDIR", "TMP", "TEMP", "PWD", "OLDPWD", "CDPATH", "TF_DATA_DIR", "TF_WORKSPACE", "TF_IN_AUTOMATION", "TF_INPUT", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS", "RUBYOPT", "PERL5LIB"}
	for _, prefix := range prefixes {
		protected = append(protected, prefix, prefix+"CUSTOM")
	}
	for _, suffix := range []string{"TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "CREDENTIALS", "ACCESS_KEY"} {
		protected = append(protected, suffix, "_"+suffix, "APP_"+suffix, "TF_VAR_"+suffix)
	}
	protected = append(protected, "AWS_REGION_EXTRA", "GOOGLE_CLOUD_PROJECT_EXTRA", "ARM_TENANT_ID_EXTRA")
	for _, name := range protected {
		for _, variant := range []string{name, strings.ToLower(name), strings.ToLower(name[:1]) + name[1:]} {
			requireInvalidEnvironment(t, []*forgev1.StackEnvironmentVariable{environmentEntry(variant, "value-sentinel")})
		}
	}
	allowed := []string{"AWS_REGION", "AWS_DEFAULT_REGION", "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_REGION", "GOOGLE_CLOUD_ZONE", "ARM_SUBSCRIPTION_ID", "ARM_TENANT_ID", "ARM_ENVIRONMENT"}
	for _, name := range allowed {
		for _, variant := range []string{name, strings.ToLower(name), strings.ToLower(name[:1]) + name[1:]} {
			got, err := normalizeEnvironment([]*forgev1.StackEnvironmentVariable{environmentEntry(variant, "region-or-project")})
			if err != nil || got[0].Name != variant {
				t.Fatal("cloud exception rejected or rewritten")
			}
		}
	}
}

func TestNormalizeEnvironmentCollectionLimits(t *testing.T) {
	entries := make([]*forgev1.StackEnvironmentVariable, 65)
	for i := range entries {
		entries[i] = environmentEntry("APP_"+string(rune('A'+i/26))+string(rune('A'+i%26)), "")
	}
	if got, err := normalizeEnvironment(entries[:64]); err != nil || len(got) != 64 {
		t.Fatal("64-entry boundary rejected")
	}
	requireInvalidEnvironment(t, entries)
	entries = []*forgev1.StackEnvironmentVariable{
		environmentEntry("A", strings.Repeat("é", 2048)), environmentEntry("B", strings.Repeat("b", 4096)),
		environmentEntry("C", strings.Repeat("c", 4096)), environmentEntry("D", strings.Repeat("é", 2046)),
	}
	if _, err := normalizeEnvironment(entries); err != nil {
		t.Fatal("16 KiB names-plus-values boundary rejected")
	}
	entries[3].Value += "x"
	requireInvalidEnvironment(t, entries)
}

func TestNormalizeEnvironmentFailureLeavesInputUntouched(t *testing.T) {
	input := []*forgev1.StackEnvironmentVariable{environmentEntry("z", "secret-sentinel"), environmentEntry("a", "secret-sentinel\x00")}
	before := []*forgev1.StackEnvironmentVariable{proto.Clone(input[0]).(*forgev1.StackEnvironmentVariable), proto.Clone(input[1]).(*forgev1.StackEnvironmentVariable)}
	requireInvalidEnvironment(t, input)
	for i := range input {
		if !proto.Equal(input[i], before[i]) {
			t.Fatal("failed normalization changed input")
		}
	}
}
