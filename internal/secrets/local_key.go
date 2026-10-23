//go:build linux || darwin

package secrets

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// LoadLocalKeyFile reads exactly 32 binary bytes from an explicitly configured
// canonical absolute path. Linux and macOS require an effective-UID-owned regular
// file with mode 0400 or 0600 and no symlinks in any path component.
// Provision the file and its parent directories outside untrusted write access.
func LoadLocalKeyFile(keyID, path string) (*LocalKey, error) {
	return loadLocalKeyFile(keyID, path, io.ReadFull)
}

func loadLocalKeyFile(keyID, path string, read func(io.Reader, []byte) (int, error)) (*LocalKey, error) {
	if keyID == "" {
		return nil, ErrInvalidKey
	}
	fd, err := openKeyPath(path)
	if err != nil {
		return nil, ErrInvalidKey
	}
	file := os.NewFile(uintptr(fd), "")
	defer file.Close()
	var before, after, current unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !protectedKeyFile(before) {
		return nil, ErrInvalidKey
	}
	var material [33]byte // One extra byte detects trailing data; reads stay bounded.
	defer clear(material[:])
	n, err := read(file, material[:])
	if n != 32 || err != io.ErrUnexpectedEOF || unix.Fstat(fd, &after) != nil || !sameKeyFile(before, after) {
		return nil, ErrInvalidKey
	}
	// Rewalk without following symlinks: a renamed file/ancestor cannot silently
	// substitute the pathname while the opened descriptor remains valid.
	check, err := openKeyPath(path)
	if err != nil {
		return nil, ErrInvalidKey
	}
	defer unix.Close(check)
	if unix.Fstat(check, &current) != nil || !sameKeyFile(before, current) {
		return nil, ErrInvalidKey
	}
	return NewLocalKey(keyID, material[:32])
}

func protectedKeyFile(st unix.Stat_t) bool {
	mode := st.Mode & 0o7777
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == uint32(os.Geteuid()) &&
		(mode == 0o400 || mode == 0o600) && st.Size == 32
}

func sameKeyFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid &&
		a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func openKeyPath(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, ErrInvalidKey
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(path[1:], "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}
