//go:build linux

package vpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsureAcceptLocal_AlreadyEnabled performs no write when the setting is 1.
func TestEnsureAcceptLocal_AlreadyEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accept_local")
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("seed accept_local: %v", err)
	}

	if err := ensureAcceptLocal(path, "net.ipv4.conf.test.accept_local"); err != nil {
		t.Fatalf("ensureAcceptLocal on already-enabled path: %v", err)
	}
	if !isAcceptLocalEnabled(path) {
		t.Fatal("accept_local should remain 1")
	}
}

// TestEnsureAcceptLocal_EnablesAndToleratesReadOnly covers both branches that the
// startup prerequisite relies on: a writable setting is enabled in place, and a
// read-only one is tolerated with a warning instead of failing startup.
func TestEnsureAcceptLocal_EnablesAndToleratesReadOnly(t *testing.T) {
	t.Run("writable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "accept_local")
		if err := os.WriteFile(path, []byte("0\n"), 0o600); err != nil {
			t.Fatalf("seed accept_local: %v", err)
		}
		if err := ensureAcceptLocal(path, "net.ipv4.conf.test.accept_local"); err != nil {
			t.Fatalf("ensureAcceptLocal: %v", err)
		}
		if !isAcceptLocalEnabled(path) {
			t.Fatalf("expected accept_local to be enabled, got %q", readTrimmed(t, path))
		}
	})

	t.Run("unwritable is tolerated", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file permission bits")
		}
		path := filepath.Join(t.TempDir(), "accept_local")
		if err := os.WriteFile(path, []byte("0\n"), 0o400); err != nil {
			t.Fatalf("seed read-only accept_local: %v", err)
		}
		// The per-device setting is applied at TUN creation, so a host-wide failure
		// must not abort startup.
		if err := ensureAcceptLocal(path, "net.ipv4.conf.test.accept_local"); err != nil {
			t.Fatalf("expected read-only accept_local to be tolerated, got: %v", err)
		}
	})

	t.Run("missing path is tolerated", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "does-not-exist", "accept_local")
		if err := ensureAcceptLocal(path, "net.ipv4.conf.test.accept_local"); err != nil {
			t.Fatalf("expected missing accept_local to be tolerated, got: %v", err)
		}
	})
}

// TestIsAcceptLocalEnabled_ReadsValue pins the value parsing used by both the
// host-wide check and the per-device fallback.
func TestIsAcceptLocalEnabled_ReadsValue(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{"enabled", "1\n", true},
		{"enabled no newline", "1", true},
		{"padded", " 1 \n", true},
		{"disabled", "0\n", false},
		{"garbage", "yes\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_"))
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
			if got := isAcceptLocalEnabled(path); got != tc.want {
				t.Fatalf("isAcceptLocalEnabled(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}

	if isAcceptLocalEnabled(filepath.Join(dir, "absent")) {
		t.Fatal("a missing path must not report enabled")
	}
}

func readTrimmed(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(data))
}
