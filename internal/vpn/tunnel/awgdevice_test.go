package tunnel

import (
	"bytes"
	"testing"
	"time"
)

func TestAWGClientDevice_ReadWrite(t *testing.T) {
	pub, priv, _ := GenerateCurve25519KeyPair()
	dev, err := NewAWGClientDevice("test-awg", "127.0.0.1:51820", priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("Failed to create AWGClientDevice: %v", err)
	}
	defer dev.Close()

	if dev.Name() != "test-awg" {
		t.Errorf("expected name 'test-awg', got %q", dev.Name())
	}
	if dev.MTU() != 1340 {
		t.Errorf("expected mtu 1340, got %d", dev.MTU())
	}

	testPkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1}

	// Inject a packet into the device (from forwarder)
	n, err := dev.Write(testPkt)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(testPkt) {
		t.Errorf("expected to write %d bytes, wrote %d", len(testPkt), n)
	}

	// Read from vtun's inPackets (as amneziawg-go would via Read)

	dev.vtun.events <- 1 // Avoid block

	// Wait for packet
	select {
	case pkt := <-dev.vtun.inPackets:
		if !bytes.Equal(pkt, testPkt) {
			t.Errorf("expected injected packet, got %x", pkt)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for packet in vtun")
	}

	// Now simulate amneziawg-go writing a decrypted packet out to vtun
	replyPkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	n, err = dev.vtun.Write([][]byte{replyPkt}, 0)
	if err != nil {
		t.Fatalf("vtun Write failed: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 packet written, got %d", n)
	}

	// Read from dev (as forwarder would)
	readBuf := make([]byte, 1500)
	devReadCh := make(chan struct{})
	go func() {
		n, err := dev.Read(readBuf)
		if err != nil {
			t.Errorf("Read failed: %v", err)
		}
		if n != len(replyPkt) {
			t.Errorf("expected to read %d bytes, got %d", len(replyPkt), n)
		}
		if !bytes.Equal(readBuf[:n], replyPkt) {
			t.Errorf("expected reply packet, got %x", readBuf[:n])
		}
		close(devReadCh)
	}()

	select {
	case <-devReadCh:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for dev.Read")
	}
}

func TestVirtualTUN_DropCounter(t *testing.T) {
	pub, priv, _ := GenerateCurve25519KeyPair()
	dev, err := NewAWGClientDevice("test-drop", "127.0.0.1:51820", priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("Failed to create AWGClientDevice: %v", err)
	}
	defer dev.Close()

	if dev.DroppedPackets() != 0 {
		t.Fatalf("expected initial drop count 0, got %d", dev.DroppedPackets())
	}

	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}

	// Fill the outPackets channel buffer (capacity 1024)
	for i := 0; i < 1024; i++ {
		n, err := dev.vtun.Write([][]byte{pkt}, 0)
		if err != nil {
			t.Fatalf("unexpected error on write %d: %v", i, err)
		}
		if n != 1 {
			t.Fatalf("expected 1 written, got %d", n)
		}
	}

	if dev.DroppedPackets() != 0 {
		t.Fatalf("expected 0 drops when queue is full but not overflowing, got %d", dev.DroppedPackets())
	}
	if dev.vtun.DroppedPackets() != 0 {
		t.Fatalf("expected vtun.DroppedPackets() 0, got %d", dev.vtun.DroppedPackets())
	}

	// Next writes should be dropped and increment dropCount
	const dropsCount = 10
	for i := 0; i < dropsCount; i++ {
		n, err := dev.vtun.Write([][]byte{pkt}, 0)
		if err != nil {
			t.Fatalf("unexpected error on dropped write %d: %v", i, err)
		}
		if n != 1 {
			t.Fatalf("expected n=1 reported, got %d", n)
		}
	}

	if dev.DroppedPackets() != dropsCount {
		t.Errorf("expected %d dropped packets, got %d", dropsCount, dev.DroppedPackets())
	}
	if dev.vtun.DroppedPackets() != dropsCount {
		t.Errorf("expected vtun.DroppedPackets() == %d, got %d", dropsCount, dev.vtun.DroppedPackets())
	}
}

func TestAWGClientDevice_CreatedAtAndClosed(t *testing.T) {
	before := time.Now()
	pub, priv, _ := GenerateCurve25519KeyPair()
	dev, err := NewAWGClientDevice("test-lifecycle", "127.0.0.1:51820", priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}
	defer dev.Close()
	after := time.Now()

	if dev.CreatedAt().Before(before) || dev.CreatedAt().After(after) {
		t.Errorf("CreatedAt %v not within [%v, %v]", dev.CreatedAt(), before, after)
	}

	if dev.IsClosed() {
		t.Error("expected IsClosed() to be false initially")
	}

	customTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	dev.SetCreatedAtForTest(customTime)
	if dev.CreatedAt() != customTime {
		t.Errorf("expected custom CreatedAt %v, got %v", customTime, dev.CreatedAt())
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !dev.IsClosed() {
		t.Error("expected IsClosed() to be true after Close()")
	}

	// Double close should be idempotent
	if err := dev.Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}

	// Read on closed device returns error
	buf := make([]byte, 100)
	_, err = dev.Read(buf)
	if err == nil {
		t.Error("expected error reading from closed device, got nil")
	}
}

func TestAWGClientDevice_LastHandshakeTimeHook(t *testing.T) {
	pub, priv, _ := GenerateCurve25519KeyPair()
	dev, err := NewAWGClientDevice("test-handshake", "127.0.0.1:51820", priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}
	defer dev.Close()

	// By default with no real peer, LastHandshakeTime returns zero
	if !dev.LastHandshakeTime().IsZero() {
		t.Errorf("expected zero handshake time initially, got %v", dev.LastHandshakeTime())
	}

	// Override with custom timestamp
	targetTime := time.Now().Add(-45 * time.Second).Truncate(time.Second)
	dev.SetLastHandshakeTimeForTest(func() time.Time {
		return targetTime
	})
	if dev.LastHandshakeTime() != targetTime {
		t.Errorf("expected LastHandshakeTime %v, got %v", targetTime, dev.LastHandshakeTime())
	}

	// Override with zero time
	dev.SetLastHandshakeTimeForTest(func() time.Time {
		return time.Time{}
	})
	if !dev.LastHandshakeTime().IsZero() {
		t.Errorf("expected zero handshake time, got %v", dev.LastHandshakeTime())
	}
}
