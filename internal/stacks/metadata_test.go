package stacks

import (
	"strings"
	"testing"
)

func TestValidateStackName(t *testing.T) {
	valid := []string{
		"x", "production", "Production", "production east", "東京", "dev/blue",
		strings.Repeat("x", 100), strings.Repeat("é", 50), strings.Repeat("🧱", 25),
	}
	invalid := []string{
		"", " name", "name ", "\u00a0name", "name\u2003", "name\n", "name\x00secret-sentinel",
		"secret-sentinel\xff", "name\u0085middle", "name\x7fmiddle",
		strings.Repeat("x", 101), strings.Repeat("é", 51), strings.Repeat("🧱", 26),
	}
	checkMetadataCases(t, validateStackName, "invalid name", valid, invalid)
}

func TestValidateBranch(t *testing.T) {
	valid := []string{
		"main", "feature/new-stack", "日本語/機能", "HEADs", "head", "HEAD/feature", "refs",
		"feature.locked", "feature.LOCK", "feature./next", "feature/-option", "feature@next", "@/next",
		"name]", "feature/#tag", strings.Repeat("x", 255), strings.Repeat("é", 127) + "x",
	}
	invalid := []string{
		"", "-main", "refs/heads/main", "refs/main", "HEAD", "@", "feature@{1}", "feature..next",
		"/main", "main/", "main//next", ".main", "feature/.hidden", "main.lock", "feature.lock/next",
		"main.", "feature/next.", "feature~1", "feature^2", "feature:next", "feature?next", "feature*next",
		"feature[next", "feature\\next", "main next", "main\tsecret-sentinel", "main\nnext",
		"main\u00a0next", "main\u2003next", "main\u2028next", "main\u3000next",
		"main\x00secret-sentinel", "main\x7fnext", "main\u0085next", "main\xffsecret-sentinel",
		strings.Repeat("x", 256), strings.Repeat("é", 128),
	}
	checkMetadataCases(t, validateBranch, "invalid branch", valid, invalid)
}

func TestValidateEngineVersion(t *testing.T) {
	valid := []string{
		"0.0.0", "1.10.3", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0", "1.0.0-0A", "1.0.0-01a",
		"1.0.0--", "1.0.0-x-y-z.--", "1.0.0-rc.1+build.001", "1.0.0+001", "1.0.0+BUILD.a-b.01",
		"1.0.0-" + strings.Repeat("a", 58), "1.0.0+" + strings.Repeat("0", 58),
		strings.Repeat("9", 60) + ".0.0",
	}
	invalid := []string{
		"", "1", "1.0", "1.0.0.0", "v1.0.0", "V1.0.0", "01.0.0", "1.01.0", "1.0.01",
		".0.0", "1..0", "1.0.", "-1.0.0", "+1.0.0", "1.+0.0", "1.0.-1", "1.0.0-",
		"1.0.0-01", "1.0.0-alpha.01", "1.0.0-.alpha", "1.0.0-alpha.", "1.0.0-alpha..1",
		"1.0.0+", "1.0.0+.build", "1.0.0+build.", "1.0.0+build..1", "1.0.0+build+other",
		"1.0.0-alpha_beta", "1.0.0+build_metadata", "1.0.0-α", "1.0.0+é", "１.0.0",
		" 1.0.0", "1.0.0 ", "1.0.0\u00a0", "1.0.0-rc\x00secret-sentinel", "1.0.0+build\xff",
		"latest", "stable", "*", ">=1.0.0", "~1.0.0", "1.0.x", "https://host/1.0.0", "./1.0.0",
		"1.0.0 --help", "1.0.0+secret-sentinel/credential", "1.0.0-" + strings.Repeat("a", 59),
		"1.0.0+" + strings.Repeat("0", 59), strings.Repeat("9", 61) + ".0.0",
	}
	checkMetadataCases(t, validateEngineVersion, "invalid engine_version", valid, invalid)
}

func TestMetadataRejectsAllControlCharacters(t *testing.T) {
	for r := rune(0); r <= 0x9f; r++ {
		if r > 0x1f && r < 0x7f {
			continue
		}
		control := string(r)
		for _, tc := range []struct {
			validate func(string) error
			value    string
			want     string
		}{
			{validateStackName, "before" + control + "secret-sentinel", "invalid name"},
			{validateBranch, "before" + control + "secret-sentinel", "invalid branch"},
			{validateEngineVersion, "1.0.0+before" + control + "secret-sentinel", "invalid engine_version"},
		} {
			if err := tc.validate(tc.value); err == nil || err.Error() != tc.want {
				t.Errorf("control U+%04X did not return the fixed field error", r)
			}
		}
	}
}

func checkMetadataCases(t *testing.T, validate func(string) error, category string, valid, invalid []string) {
	t.Helper()
	for i, value := range valid {
		if err := validate(value); err != nil {
			t.Errorf("valid case %d rejected: %v", i, err)
		}
	}
	for i, value := range invalid {
		if err := validate(value); err == nil || err.Error() != category {
			t.Errorf("invalid case %d did not return the fixed field error", i)
		}
	}
}
