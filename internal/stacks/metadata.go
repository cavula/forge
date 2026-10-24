package stacks

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	errStackName     = errors.New("invalid name")
	errBranch        = errors.New("invalid branch")
	errEngineVersion = errors.New("invalid engine_version")
)

func validateStackName(value string) error {
	if !validMetadataText(value, 100) {
		return errStackName
	}
	return nil
}

func validateBranch(value string) error {
	if !validMetadataText(value, 255) || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "refs/") ||
		value == "HEAD" || value == "@" || strings.Contains(value, "@{") || strings.Contains(value, "..") ||
		strings.HasSuffix(value, ".") || strings.ContainsAny(value, "~^:?*[\\") {
		return errBranch
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return errBranch
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return errBranch
		}
	}
	return nil
}

func validMetadataText(value string, maxBytes int) bool {
	if len(value) == 0 || len(value) > maxBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateEngineVersion(value string) error {
	if len(value) == 0 || len(value) > 64 {
		return errEngineVersion
	}
	core, build, hasBuild := strings.Cut(value, "+")
	if hasBuild && !validVersionIdentifiers(build, false) {
		return errEngineVersion
	}
	core, prerelease, hasPrerelease := strings.Cut(core, "-")
	if hasPrerelease && !validVersionIdentifiers(prerelease, true) {
		return errEngineVersion
	}
	numbers := strings.Split(core, ".")
	if len(numbers) != 3 {
		return errEngineVersion
	}
	for _, number := range numbers {
		if !canonicalVersionNumber(number) {
			return errEngineVersion
		}
	}
	return nil
}

func canonicalVersionNumber(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func validVersionIdentifiers(value string, prerelease bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for i := range len(identifier) {
			b := identifier[i]
			if b >= '0' && b <= '9' {
				continue
			}
			numeric = false
			if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '-') {
				return false
			}
		}
		if prerelease && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}
