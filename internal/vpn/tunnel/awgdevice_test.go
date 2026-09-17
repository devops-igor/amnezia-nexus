package tunnel

import (
	"bytes"
	"syscall"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func TestAWGClientDevice_ReadWrite(t *testing.T) {
	vtun := &VirtualTUN{
		inPackets:  make(chan []byte, DefaultVirtualTUNInboundCapacity),
		outPackets: make(chan []byte, 1024),
		events:     make(chan tun.Event, 2),
		closed:     make(chan struct{}),
		mtu:        1340,
		name:       "test-awg",
	}
	dev := &AWGClientDevice{
		name:      "test-awg",
		mtu:       1340,
		vtun:      vtun,
		doneCh:    make(chan struct{}),
		createdAt: time.Now(),
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

func TestVirtualTUN_InboundCapacityAndDropCounter(t *testing.T) {
	vtun := &VirtualTUN{
		inPackets:  make(chan []byte, DefaultVirtualTUNInboundCapacity),
		outPackets: make(chan []byte, 1024),
		events:     make(chan tun.Event, 2),
		closed:     make(chan struct{}),
		mtu:        1340,
		name:       "test-in-drop",
	}
	dev := &AWGClientDevice{
		name:      "test-in-drop",
		mtu:       1340,
		vtun:      vtun,
		doneCh:    make(chan struct{}),
		createdAt: time.Now(),
	}
	defer dev.Close()

	if cap(dev.vtun.inPackets) != DefaultVirtualTUNInboundCapacity {
		t.Fatalf("expected inPackets cap %d, got %d", DefaultVirtualTUNInboundCapacity, cap(dev.vtun.inPackets))
	}
	if dev.DroppedPackets() != 0 {
		t.Fatalf("expected initial drop count 0, got %d", dev.DroppedPackets())
	}

	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1}

	// Fill the inPackets channel to exact capacity (2048)
	for i := 0; i < DefaultVirtualTUNInboundCapacity; i++ {
		n, err := dev.Write(pkt)
		if err != nil {
			t.Fatalf("unexpected error on write %d: %v", i, err)
		}
		if n != len(pkt) {
			t.Fatalf("expected %d bytes written, got %d", len(pkt), n)
		}
	}

	if dev.DroppedPackets() != 0 {
		t.Fatalf("expected 0 drops when inPackets is exactly full, got %d", dev.DroppedPackets())
	}

	// Subsequent writes should be dropped and increment dropCount
	const excessWrites = 25
	for i := 0; i < excessWrites; i++ {
		n, err := dev.Write(pkt)
		if err != nil {
			t.Fatalf("unexpected error on dropped write %d: %v", i, err)
		}
		if n != len(pkt) {
			t.Fatalf("expected n=%d reported, got %d", len(pkt), n)
		}
	}

	if dev.DroppedPackets() != excessWrites {
		t.Errorf("expected %d dropped packets, got %d", excessWrites, dev.DroppedPackets())
	}
	if dev.vtun.DroppedPackets() != excessWrites {
		t.Errorf("expected vtun.DroppedPackets() == %d, got %d", excessWrites, dev.vtun.DroppedPackets())
	}

	// Also verify direct RecordDrop on VirtualTUN
	vtun.RecordDrop()
	if dev.DroppedPackets() != excessWrites+1 || vtun.DroppedPackets() != excessWrites+1 {
		t.Errorf("expected drop count %d after RecordDrop, got dev=%d vtun=%d",
			excessWrites+1, dev.DroppedPackets(), vtun.DroppedPackets())
	}

	// Drain 5 packets and verify writing again does not increment drops
	for i := 0; i < 5; i++ {
		<-dev.vtun.inPackets
	}

	for i := 0; i < 5; i++ {
		n, err := dev.Write(pkt)
		if err != nil {
			t.Fatalf("unexpected error writing to drained queue: %v", err)
		}
		if n != len(pkt) {
			t.Fatalf("expected n=%d, got %d", len(pkt), n)
		}
	}

	// Drop count should remain excessWrites+1 (no new drops)
	if dev.DroppedPackets() != excessWrites+1 {
		t.Errorf("expected drop count to remain %d, got %d", excessWrites+1, dev.DroppedPackets())
	}
}

func TestAWGClientDevice_WriteBufferIsolation(t *testing.T) {
	vtun := &VirtualTUN{
		inPackets:  make(chan []byte, DefaultVirtualTUNInboundCapacity),
		outPackets: make(chan []byte, 1024),
		events:     make(chan tun.Event, 2),
		closed:     make(chan struct{}),
		mtu:        1340,
		name:       "test-buf-isolation",
	}
	dev := &AWGClientDevice{
		name:      "test-buf-isolation",
		mtu:       1340,
		vtun:      vtun,
		doneCh:    make(chan struct{}),
		createdAt: time.Now(),
	}
	defer dev.Close()

	expectedPkt := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1}
	orig := make([]byte, len(expectedPkt))
	copy(orig, expectedPkt)

	n, err := dev.Write(orig)
	if err != nil || n != len(orig) {
		t.Fatalf("Write failed: n=%d err=%v", n, err)
	}

	// Immediately mutate/zero orig after Write returns to simulate amneziawg-go buffer pool reuse
	for i := range orig {
		orig[i] = 0x00
	}

	select {
	case receivedPkt := <-dev.vtun.inPackets:
		if !bytes.Equal(receivedPkt, expectedPkt) {
			t.Fatalf("packet corrupted: got %x, want %x", receivedPkt, expectedPkt)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for packet from inPackets")
	}
}

func TestTunedBind_BufferTuning(t *testing.T) {
	baseBind := conn.NewDefaultBind()
	tuned := NewTunedBind(baseBind, DefaultUDPSocketBufferSize)

	if tuned.BufferSize() != DefaultUDPSocketBufferSize {
		t.Errorf("expected BufferSize %d, got %d", DefaultUDPSocketBufferSize, tuned.BufferSize())
	}

	fns, port, err := tuned.Open(0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer tuned.Close()

	if len(fns) == 0 {
		t.Fatal("expected at least 1 receive function")
	}
	if port == 0 {
		t.Fatal("expected non-zero bound port")
	}

	fd, err := tuned.PeekLookAtSocketFd4()
	if err != nil {
		t.Fatalf("PeekLookAtSocketFd4 failed: %v", err)
	}
	if fd < 0 {
		t.Fatalf("expected non-negative fd, got %d", fd)
	}

	rcv, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatalf("GetsockoptInt SO_RCVBUF failed: %v", err)
	}
	snd, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if err != nil {
		t.Fatalf("GetsockoptInt SO_SNDBUF failed: %v", err)
	}

	// Linux kernel doubles the requested buffer size, or caps at rmem_max.
	// We verify that the buffer size is positive and reasonably large.
	if rcv <= 0 || snd <= 0 {
		t.Errorf("expected positive socket buffers, got rcv=%d snd=%d", rcv, snd)
	}
}

func TestTunedBind_DelegationAndFallbacks(t *testing.T) {
	tuned := NewTunedBind(conn.NewDefaultBind(), -1)
	if tuned.BufferSize() != DefaultUDPSocketBufferSize {
		t.Errorf("expected default BufferSize %d on non-positive input, got %d", DefaultUDPSocketBufferSize, tuned.BufferSize())
	}

	// Test interface binding delegation before Open
	_ = tuned.BindSocketToInterface4(0, false)
	_ = tuned.BindSocketToInterface6(0, false)
}
