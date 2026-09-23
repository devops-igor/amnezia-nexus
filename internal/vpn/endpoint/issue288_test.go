package endpoint

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
)

// setupIssue288Listener creates a test listener configured with default AWG headers
// and ephemeral in-memory server keys.
func setupIssue288Listener(t *testing.T) (*Listener, [32]byte) {
	t.Helper()
	keysMgr := NewServerKeysManager(nil)
	_, sPub, err := keysMgr.EnsureKeypair(context.Background())
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}
	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
	}
	el, err := NewListener(cfg, nil, nil, nil, nil, keysMgr)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}
	return el, sPub
}

func TestDistinguishUnroutableDatagramsFromFailedInitiations(t *testing.T) {
	ctx := context.Background()

	// Test 1: Unroutable datagram (ErrNotInitiation) from unknown sender -> 0 rejections, 0 rejection logs.
	t.Run("Test1_UnroutableDatagram_ErrNotInitiation", func(t *testing.T) {
		el, _ := setupIssue288Listener(t)
		var logBuf safeLogBuffer
		origOutput := captureLogOutput(&logBuf)
		defer restoreLogOutput(origOutput)

		sender := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 101), Port: 40001}
		pkt := make([]byte, el.config.S1+initiationWireLen)
		binary.LittleEndian.PutUint32(pkt[el.config.S1:el.config.S1+4], 99999)

		el.handleDatagram(ctx, pkt, sender)

		if rejects := el.HandshakeRejections(); rejects != 0 {
			t.Fatalf("HandshakeRejections = %d, want 0", rejects)
		}
		if strings.Contains(logBuf.String(), "rejected handshake initiation") {
			t.Fatalf("unexpected rejection log emitted: %s", logBuf.String())
		}
	})

	// Test 2: Datagram too short (ErrDatagramTooShort) -> 0 rejections, 0 rejection logs.
	t.Run("Test2_DatagramTooShort_ErrDatagramTooShort", func(t *testing.T) {
		el, _ := setupIssue288Listener(t)
		var logBuf safeLogBuffer
		origOutput := captureLogOutput(&logBuf)
		defer restoreLogOutput(origOutput)

		sender := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 102), Port: 40002}
		pkt := make([]byte, 32)

		el.handleDatagram(ctx, pkt, sender)

		if rejects := el.HandshakeRejections(); rejects != 0 {
			t.Fatalf("HandshakeRejections = %d, want 0", rejects)
		}
		if strings.Contains(logBuf.String(), "rejected handshake initiation") {
			t.Fatalf("unexpected rejection log emitted: %s", logBuf.String())
		}
	})

	// Test 3: Genuine initiation failure (ErrMAC1Failed) -> increments HandshakeRejections, emits rejection log.
	t.Run("Test3_GenuineInitiationFailure_ErrMAC1Failed", func(t *testing.T) {
		el, _ := setupIssue288Listener(t)
		var logBuf safeLogBuffer
		origOutput := captureLogOutput(&logBuf)
		defer restoreLogOutput(origOutput)

		sender := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 103), Port: 40003}
		pkt := make([]byte, el.config.S1+initiationWireLen)
		binary.LittleEndian.PutUint32(pkt[el.config.S1:el.config.S1+4], health.DefaultH1)

		el.handleDatagram(ctx, pkt, sender)

		if rejects := el.HandshakeRejections(); rejects != 1 {
			t.Fatalf("HandshakeRejections = %d, want 1", rejects)
		}
		if !strings.Contains(logBuf.String(), "rejected handshake initiation from "+sender.String()) {
			t.Fatalf("expected rejection log for sender %s, got: %s", sender, logBuf.String())
		}
		if !strings.Contains(logBuf.String(), ErrMAC1Failed.Error()) {
			t.Fatalf("expected log to mention %v, got: %s", ErrMAC1Failed, logBuf.String())
		}
	})

	// Test 4: Genuine initiation failure (ErrTimestampStale) -> increments HandshakeRejections, emits rejection log.
	t.Run("Test4_GenuineInitiationFailure_ErrTimestampStale", func(t *testing.T) {
		el, sPub := setupIssue288Listener(t)
		var logBuf safeLogBuffer
		origOutput := captureLogOutput(&logBuf)
		defer restoreLogOutput(origOutput)

		clientPriv := make([]byte, 32)
		if _, err := rand.Read(clientPriv); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		// Initiation packet with timestamp 400s in the past (outside 300s anti-replay window).
		stalePkt := buildInitiationAt(t, sPub[:], clientPriv, time.Now().Add(-400*time.Second))
		sender := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 104), Port: 40004}

		el.handleDatagram(ctx, stalePkt, sender)

		if rejects := el.HandshakeRejections(); rejects != 1 {
			t.Fatalf("HandshakeRejections = %d, want 1", rejects)
		}
		if !strings.Contains(logBuf.String(), "rejected handshake initiation from "+sender.String()) {
			t.Fatalf("expected rejection log for sender %s, got: %s", sender, logBuf.String())
		}
		if !strings.Contains(logBuf.String(), ErrTimestampStale.Error()) {
			t.Fatalf("expected log to mention %v, got: %s", ErrTimestampStale, logBuf.String())
		}
	})

	// Test 5: Transport datagram (message type 4) from unknown sender -> 0 rejections, 0 rejection logs.
	t.Run("Test5_TransportDatagram_UnknownSender", func(t *testing.T) {
		el, _ := setupIssue288Listener(t)
		var logBuf safeLogBuffer
		origOutput := captureLogOutput(&logBuf)
		defer restoreLogOutput(origOutput)

		sender := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 105), Port: 40005}
		// Plausible transport datagram with message type 4 (DefaultH4).
		pkt := make([]byte, el.config.S4+transportDataHeaderLen+32)
		binary.LittleEndian.PutUint32(pkt[el.config.S4:el.config.S4+4], health.DefaultH4)

		el.handleDatagram(ctx, pkt, sender)

		if rejects := el.HandshakeRejections(); rejects != 0 {
			t.Fatalf("HandshakeRejections = %d, want 0", rejects)
		}
		if strings.Contains(logBuf.String(), "rejected handshake initiation") {
			t.Fatalf("unexpected rejection log emitted: %s", logBuf.String())
		}
	})
}
