package endpoint

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTunDeviceUnavailableBadPath proves the typed error surface: opening a
// nonexistent TUN control device must fail with an error wrapping
// ErrTunUnavailable (hermetic — no kernel TUN required).
func TestTunDeviceUnavailableBadPath(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "no-such-tun")
	_, err := openTunDevice(badPath, "awg0", 1420)
	if err == nil {
		t.Fatalf("expected error opening tun at %s", badPath)
	}
	if !errors.Is(err, ErrTunUnavailable) {
		t.Errorf("expected ErrTunUnavailable in chain, got: %v", err)
	}
}

// TestTunDeviceRealInterface exercises the real /dev/net/tun data path. It
// skips on hosts without the TUN device (WSL, unprivileged containers) — the
// compile path is still verified by the rest of the package tests.
func TestTunDeviceRealInterface(t *testing.T) {
	if _, err := os.Stat(TunDevicePath); err != nil {
		t.Skipf("tun device %s not available on this host: %v", TunDevicePath, err)
	}

	dev, err := OpenTunDevice("awg-test0", 1420)
	if err != nil {
		if errors.Is(err, ErrTunUnavailable) {
			t.Skipf("tun device present but not usable (permissions): %v", err)
		}
		t.Fatalf("OpenTunDevice failed: %v", err)
	}

	if dev.Name() == "" {
		t.Error("expected non-empty interface name")
	}
	if dev.MTU() != 1420 {
		t.Errorf("expected MTU 1420, got %d", dev.MTU())
	}

	// Close must unblock a concurrent Read.
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		_, err := dev.Read(buf)
		readErr <- err
	}()

	if err := dev.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("expected pending Read to fail after Close")
		}
	case <-waitTimeout(t):
		t.Fatal("pending Read did not unblock after Close")
	}

	// Operations after Close must fail.
	if _, err := dev.Write([]byte("x")); err == nil {
		t.Error("expected error writing to closed tun device")
	}
	buf := make([]byte, 10)
	if _, err := dev.Read(buf); err == nil {
		t.Error("expected error reading from closed tun device")
	}
}

// waitTimeout yields a bounded abort channel for Close/Read synchronization.
func waitTimeout(t *testing.T) <-chan time.Time {
	t.Helper()
	return time.After(5 * time.Second)
}
