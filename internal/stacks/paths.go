package stacks

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var (
	errRepositoryURL    = errors.New("invalid repository_url")
	errWorkingDirectory = errors.New("invalid working_directory")
	repositoryIDNA      = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.BidiRule(), idna.VerifyDNSLength(true))
)

func validateRepositoryURL(value string) error {
	if len(value) == 0 || len(value) > 2048 || strings.ContainsAny(value, "\\%?#") {
		return errRepositoryURL
	}
	for _, b := range []byte(value) {
		if b < 0x21 || b > 0x7e {
			return errRepositoryURL
		}
	}
	u, err := url.Parse(value)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.User != nil || u.Host == "" {
		return errRepositoryURL
	}
	host := u.Hostname()
	address, ipErr := netip.ParseAddr(host)
	if ipErr == nil {
		if address.Zone() != "" || address.String() != host {
			return errRepositoryURL
		}
	} else if !validRepositoryDNS(host) {
		return errRepositoryURL
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errRepositoryURL
		}
		authority += ":" + port
	}
	if u.Host != authority || !strings.HasPrefix(u.Path, "/") {
		return errRepositoryURL
	}
	for _, segment := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errRepositoryURL
		}
		for _, b := range []byte(segment) {
			if !repositoryAlphaNumeric(b) && !strings.ContainsRune("._~-", rune(b)) {
				return errRepositoryURL
			}
		}
	}
	return nil
}

func validRepositoryDNS(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.Trim(host, "0123456789.") == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-') {
				return false
			}
		}
	}
	ascii, err := repositoryIDNA.ToASCII(host)
	return err == nil && ascii == host
}

func repositoryAlphaNumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func validateWorkingDirectory(value string) error {
	if len(value) == 0 || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
		strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") || strings.ContainsAny(value, "\\:%") {
		return errWorkingDirectory
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return errWorkingDirectory
		}
	}
	if value == "." {
		return nil
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errWorkingDirectory
		}
	}
	return nil
}
