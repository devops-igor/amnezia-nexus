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
