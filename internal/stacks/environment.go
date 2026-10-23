package stacks

import (
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	forgev1 "github.com/cavula/forge/gen/go/forge/v1"
)

var errEnvironment = errors.New("invalid environment_variables")

// normalizeEnvironment validates non-secret configuration and copies it in name order.
// It does not establish that arbitrary values are free of secret material.
func normalizeEnvironment(entries []*forgev1.StackEnvironmentVariable) ([]*forgev1.StackEnvironmentVariable, error) {
	if len(entries) > 64 {
		return nil, errEnvironment
	}
	result := make([]*forgev1.StackEnvironmentVariable, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	total := 0
	for _, entry := range entries {
		if entry == nil {
			return nil, errEnvironment
		}
		name, value := entry.GetName(), entry.GetValue()
		if !validEnvironmentName(name) || protectedEnvironmentName(name) || seen[name] ||
			len(value) > 4096 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
			return nil, errEnvironment
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return nil, errEnvironment
			}
		}
		total += len(name) + len(value)
		if total > 16*1024 {
			return nil, errEnvironment
		}
		seen[name] = true
		result = append(result, &forgev1.StackEnvironmentVariable{Name: name, Value: value})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func validEnvironmentName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for i, b := range []byte(name) {
		if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && b != '_' && (i == 0 || b < '0' || b > '9') {
			return false
		}
	}
	return true
}

func protectedEnvironmentName(name string) bool {
	name = strings.ToUpper(name)
	for _, prefix := range []string{"FORGE_", "LD_", "DYLD_", "GIT_", "SSH_", "TF_CLI_", "TF_LOG", "TF_PLUGIN_", "TF_REATTACH_"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	switch name {
	case "PATH", "HOME", "USER", "LOGNAME", "SHELL", "IFS", "ENV", "BASH_ENV", "TMPDIR", "TMP", "TEMP", "PWD", "OLDPWD", "CDPATH",
		"TF_DATA_DIR", "TF_WORKSPACE", "TF_IN_AUTOMATION", "TF_INPUT", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS", "RUBYOPT", "PERL5LIB":
		return true
	}
	for _, suffix := range []string{"TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "CREDENTIALS", "ACCESS_KEY"} {
		if name == suffix || strings.HasSuffix(name, "_"+suffix) {
			return true
		}
	}
	for _, prefix := range []string{"AWS_", "GOOGLE_", "GCLOUD_", "CLOUDSDK_", "AZURE_", "ARM_"} {
		if strings.HasPrefix(name, prefix) {
			switch name {
			case "AWS_REGION", "AWS_DEFAULT_REGION", "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_REGION", "GOOGLE_CLOUD_ZONE",
				"ARM_SUBSCRIPTION_ID", "ARM_TENANT_ID", "ARM_ENVIRONMENT":
				return false
			}
			return true
		}
	}
	return false
}
