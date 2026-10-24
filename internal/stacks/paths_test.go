package stacks

import (
	"strings"
	"testing"
)

func TestValidateRepositoryURL(t *testing.T) {
	valid := []string{
		"https://git.example/team/repo.git", "HTTPS://git.example/team/repo",
		"https://localhost/repo", "https://xn--bcher-kva.example/a_b.c~-D", "https://xn--fa-hia.de/repo",
		"https://192.0.2.1:1/repo", "https://git.example:65535/repo", "https://git.example:00443/repo",
		"https://[2001:db8::1]:443/repo", "https://[::1]/repo", "https://[::ffff:192.0.2.1]/repo",
		"https://git.example/" + strings.Repeat("x", 2048-len("https://git.example/")),
		"https://" + strings.Repeat("a", 63) + ".example/repo",
		"https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + "/repo",
	}
	for _, value := range valid {
		if err := validateRepositoryURL(value); err != nil {
			t.Errorf("valid URL rejected: %v", err)
		}
	}
	invalid := []string{
		"", "http://git.example/repo", "ssh://git.example/repo", "https:git.example/repo", "//git.example/repo",
		"https:///repo", "https://git.example", "https://git.example/", "https://git.example/repo/",
		"https://user:secret-sentinel@git.example/repo", "https://@git.example/repo",
		"https://git.example/repo?", "https://git.example/repo?token=secret-sentinel",
		"https://git.example/repo#", "https://git.example/repo#secret-sentinel", "https://git.example/repo\\other",
		"https://git.example/%2e%2e/repo", "https://git.example/%252e/repo", "https://git.example/repo%",
		"https://git.example//repo", "https://git.example/./repo", "https://git.example/../repo", "https://git.example/repo/..",
		"https://git.example/repo;other", "https://git.example/repo:other", "https://git.example/repo+other",
		" https://git.example/repo", "https://git.example/repo ", "https://git.example/repo\x00", "https://git.example/re\npo",
		"https://git.example/repo\x7f", "https://git.example/répo", "https://bücher.example/repo", "https://git.example/repo\xff",
		"https://Git.example/repo", "https://git.example./repo", "https://git..example/repo",
		"https://-git.example/repo", "https://git-.example/repo", "https://git_example/repo",
		"https://xn--a.example/repo", "https://xn--0.example/repo", "https://xn--abc.example/repo",
		"https://xn--.example/repo", "https://xn--abc-.example/repo", "https://ab--cd.example/repo",
		"https://" + strings.Repeat("a", 64) + ".example/repo", "https://" + strings.Repeat("aaaa.", 51) + "a/repo",
		"https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62) + "/repo",
		"https://010.0.0.1/repo", "https://127.1/repo", "https://256.0.0.1/repo",
		"https://[2001:0db8::1]/repo", "https://[2001:DB8::1]/repo", "https://[2001:db8:0:0:0:0:0:1]/repo",
		"https://[fe80::1%25eth0]/repo", "https://2001:db8::1/repo", "https://[git.example]/repo", "https://[bad/repo",
		"https://git.example:/repo", "https://git.example:0/repo", "https://git.example:65536/repo",
		"https://git.example:-1/repo", "https://git.example:+443/repo", "https://git.example:abc/repo",
		"https://git.example:999999999999999999999999999999/repo",
		"https://git.example/" + strings.Repeat("x", 2049-len("https://git.example/")),
	}
	for i, value := range invalid {
		err := validateRepositoryURL(value)
		if err == nil || err.Error() != "invalid repository_url" {
			t.Errorf("invalid URL case %d did not return a generic category error", i)
		}
	}
}

func TestValidateWorkingDirectory(t *testing.T) {
	valid := []string{".", "env/dev", "München/東京", "my project/dev", "a/~local", "a..b", strings.Repeat("x", 512), strings.Repeat("é", 256)}
	for _, value := range valid {
		if err := validateWorkingDirectory(value); err != nil {
			t.Errorf("valid directory rejected: %v", err)
		}
	}
	invalid := []string{
		"", "/env", "~", "~/env", "~user/env", "..", "./env", "env/.", "env/..", "env/../prod",
		"env//dev", "env/", "env\\dev", "C:env", "env:dev", "env/%2e%2e", "env/%", "env/%zz",
		" env", "env ", "\u00a0env", "env\u2003", "env/\nsecret-sentinel", "env/\tsecret-sentinel",
		"env/\x00secret-sentinel", "env/\x7fsecret-sentinel", "env/\u0085secret-sentinel", "env/\xffsecret-sentinel",
		strings.Repeat("x", 513), strings.Repeat("é", 257),
	}
	for i, value := range invalid {
		err := validateWorkingDirectory(value)
		if err == nil || err.Error() != "invalid working_directory" {
			t.Errorf("invalid directory case %d did not return a generic category error", i)
		}
	}
}
