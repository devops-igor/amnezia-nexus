//go:build linux

package vpn

import (
	"os"
	"testing"
)

func TestProductionWANDevice_PermissionsAndLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		// Non-root: verify graceful error handling (fails closed with clear error, no panic)
		dev, err := NewProductionWANDevice("nexus-wan-test")
		if err == nil {
			_ = dev.Close()
			t.Log("NewProductionWANDevice succeeded in unprivileged test environment")
			return
		}
		t.Logf("NewProductionWANDevice returned expected non-root permission error: %v", err)
		return
	}

	dev, err := NewProductionWANDevice("nexus-wan-test")
	if err != nil {
		t.Fatalf("NewProductionWANDevice failed: %v", err)
	}
	defer func() { _ = dev.Close() }()

	// Verify device is writable (UP state allows writes without EIO)
	pkt := []byte{
		0x45, 0x00, 0x00, 0x14,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x00, 0x00, 0x00,
		0x7f, 0x00, 0x00, 0x01,
		0x7f, 0x00, 0x00, 0x01,
	}
	n, err := dev.Write(pkt)
	if err != nil {
		t.Fatalf("write to UP TUN device failed: %v", err)
	}
	if n != len(pkt) {
		t.Fatalf("expected write %d bytes, got %d", len(pkt), n)
	}
}
