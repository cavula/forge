//go:build linux || darwin

package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavula/forge/internal/testutil"
	"golang.org/x/sys/unix"
)

func keyFile(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sensitive-key-path")
	if err := os.WriteFile(path, bytes.Repeat([]byte("K"), 32), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireKeyError(t *testing.T, key *LocalKey, err error) {
	t.Helper()
	if key != nil || err != ErrInvalidKey {
		t.Fatal("invalid file did not fail closed with a generic error")
	}
}

func TestLoadLocalKeyFileRoundTripAndPrivateCopy(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o600} {
		path := keyFile(t)
		material := make([]byte, 32)
		for i := range material {
			material[i] = byte(i)
		}
		material[31] = 255
		if err := os.WriteFile(path, material, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		key, err := LoadLocalKeyFile("mounted-key", path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		peer, _ := NewLocalKey("mounted-key", material)
		e, err := key.Seal(testContext, []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := peer.Open(testContext, e)
		if err != nil || string(got) != "payload" {
			t.Fatal("loaded key was not copied into private storage")
		}
	}
}

func TestLoadLocalKeyFileRejectsConfigurationAndSize(t *testing.T) {
	path := keyFile(t)
	t.Setenv("FORGE_MASTER_KEY_FILE", path)
	t.Setenv("FORGE_MASTER_KEY", "environment-key-must-not-be-used")
	for _, candidate := range []string{"", "relative/key", "/", path + "/", filepath.Dir(path) + "/./sensitive-key-path", path + "\x00", path + "-missing"} {
		key, err := LoadLocalKeyFile("configured-id", candidate)
		requireKeyError(t, key, err)
		testutil.NoSecrets(t, fmt.Sprintf("%+v", err), candidate, "configured-id", "environment-key-must-not-be-used")
	}
	key, err := LoadLocalKeyFile("", path)
	requireKeyError(t, key, err)
	for _, size := range []int{0, 31, 33, 4096} {
		if err := os.WriteFile(path, bytes.Repeat([]byte("K"), size), 0o600); err != nil {
			t.Fatal(err)
		}
		key, err := LoadLocalKeyFile("key", path)
		requireKeyError(t, key, err)
	}
}

func TestLoadLocalKeyFileRejectsPermissionsAndSpecialFiles(t *testing.T) {
	path := keyFile(t)
	for _, mode := range []os.FileMode{0, 0o200, 0o700, 0o640, 0o604, 0o644, 0o660, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		key, err := LoadLocalKeyFile("key", path)
		requireKeyError(t, key, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, create := range []func() error{
		func() error { return os.Mkdir(path, 0o700) },
		func() error { return unix.Mkfifo(path, 0o600) },
	} {
		if err := create(); err != nil {
			t.Fatal(err)
		}
		key, err := LoadLocalKeyFile("key", path)
		requireKeyError(t, key, err)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	// Wrong ownership is always checked, even where an unprivileged test cannot chown.
	if protectedKeyFile(unix.Stat_t{Mode: unix.S_IFREG | 0o400, Uid: uint32(os.Geteuid()) + 1, Size: 32}) {
		t.Fatal("foreign owner accepted")
	}
}

func TestLoadLocalKeyFileRejectsSymlinkComponents(t *testing.T) {
	path := keyFile(t)
	for _, target := range []string{path, filepath.Dir(path)} {
		link := filepath.Join(filepath.Dir(path), "alias")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		candidate := link
		if target == filepath.Dir(path) {
			candidate = filepath.Join(link, filepath.Base(path))
		}
		key, err := LoadLocalKeyFile("key", candidate)
		requireKeyError(t, key, err)
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadLocalKeyFileRejectsReadAndReplacementRaces(t *testing.T) {
	for name, change := range map[string]func(string) error{
		"append":    func(p string) error { return os.WriteFile(p, bytes.Repeat([]byte("X"), 33), 0o600) },
		"overwrite": func(p string) error { return os.WriteFile(p, bytes.Repeat([]byte("X"), 32), 0o600) },
		"chmod":     func(p string) error { return os.Chmod(p, 0o644) },
		"unlink":    os.Remove,
		"replace": func(p string) error {
			if err := os.Rename(p, p+"-old"); err != nil {
				return err
			}
			return os.WriteFile(p, bytes.Repeat([]byte("X"), 32), 0o600)
		},
		"replace parent": func(p string) error {
			dir := filepath.Dir(p)
			if err := os.Rename(dir, dir+"-old"); err != nil {
				return err
			}
			if err := os.Mkdir(dir, 0o700); err != nil {
				return err
			}
			return os.WriteFile(p, bytes.Repeat([]byte("X"), 32), 0o600)
		},
		"symlink parent": func(p string) error {
			dir := filepath.Dir(p)
			if err := os.Rename(dir, dir+"-old"); err != nil {
				return err
			}
			return os.Symlink(dir+"-old", dir)
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := keyFile(t)
			t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(path) + "-old") })
			key, err := loadLocalKeyFile("key", path, func(r io.Reader, b []byte) (int, error) {
				n, err := io.ReadFull(r, b)
				if changeErr := change(path); changeErr != nil {
					t.Fatal(changeErr)
				}
				return n, err
			})
			requireKeyError(t, key, err)
		})
	}
	t.Run("growth before read", func(t *testing.T) {
		path := keyFile(t)
		key, err := loadLocalKeyFile("key", path, func(r io.Reader, b []byte) (int, error) {
			if err := os.WriteFile(path, bytes.Repeat([]byte("X"), 34), 0o600); err != nil {
				t.Fatal(err)
			}
			return io.ReadFull(r, b)
		})
		requireKeyError(t, key, err)
	})
	path := keyFile(t)
	key, err := loadLocalKeyFile("sensitive-id", path, func(_ io.Reader, b []byte) (int, error) {
		if len(b) != 33 {
			t.Fatal("unbounded read")
		}
		return 0, errors.New(path + " KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK")
	})
	requireKeyError(t, key, err)
	testutil.NoSecrets(t, fmt.Sprintf("%+v", err), path, "sensitive-id", "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK")
}
