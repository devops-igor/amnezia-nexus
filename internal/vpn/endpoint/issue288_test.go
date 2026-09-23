package endpoint

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
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

// TestEstablishedPeer_GenuineHandshakeFailure_IncrementsCounterAndLogs verifies that
// genuine handshake initiation verification failures (such as ErrMAC1Failed or ErrTimestampStale)
// originating from an established peer address are not swallowed as transport data, but are
// correctly counted as handshake rejections and emit rejection logs (issue #288 rework).
func TestEstablishedPeer_GenuineHandshakeFailure_IncrementsCounterAndLogs(t *testing.T) {
	ctx := context.Background()
	el, sPub := setupIssue288Listener(t)

	var routedPackets [][]byte
	var mu sync.Mutex
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		mu.Lock()
		defer mu.Unlock()
		pktCopy := make([]byte, len(pkt))
		copy(pktCopy, pkt)
		routedPackets = append(routedPackets, pktCopy)
		return nil
	})

	var logBuf safeLogBuffer
	origOutput := captureLogOutput(&logBuf)
	defer restoreLogOutput(origOutput)

	peerKey := "established-peer-static-key"
	clientAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 200), Port: 45000}
	recvKey := make([]byte, 32)
	sendKey := make([]byte, 32)
	for i := range recvKey {
		recvKey[i] = byte(i + 1)
		sendKey[i] = byte(i + 33)
	}
	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: recvKey,
		SendKey: sendKey,
	})
	el.rememberPeer(clientAddr, peerKey, 50001)

	// 1. Send genuine initiation failure with invalid MAC1 (ErrMAC1Failed) from established peer address.
	failMAC1Pkt := make([]byte, el.config.S1+initiationWireLen)
	binary.LittleEndian.PutUint32(failMAC1Pkt[el.config.S1:el.config.S1+4], health.DefaultH1)

	el.handleDatagram(ctx, failMAC1Pkt, clientAddr)

	if rejects := el.HandshakeRejections(); rejects != 1 {
		t.Fatalf("HandshakeRejections = %d, want 1 after ErrMAC1Failed from established peer", rejects)
	}
	if !strings.Contains(logBuf.String(), "rejected handshake initiation from "+clientAddr.String()) {
		t.Fatalf("expected rejection log for established peer genuine handshake failure, got: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), ErrMAC1Failed.Error()) {
		t.Fatalf("expected rejection log to mention %v, got: %s", ErrMAC1Failed, logBuf.String())
	}

	mu.Lock()
	if len(routedPackets) != 0 {
		t.Fatalf("expected 0 routed packets, got %d", len(routedPackets))
	}
	mu.Unlock()

	// 2. Send genuine initiation failure with stale timestamp (ErrTimestampStale) from established peer address.
	clientPriv := make([]byte, 32)
	if _, err := rand.Read(clientPriv); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	stalePkt := buildInitiationAt(t, sPub[:], clientPriv, time.Now().Add(-400*time.Second))

	// Reset log throttle so the second rejection log is not suppressed within the same second
	el.rejectLogUntil.Store(0)

	el.handleDatagram(ctx, stalePkt, clientAddr)

	if rejects := el.HandshakeRejections(); rejects != 2 {
		t.Fatalf("HandshakeRejections = %d, want 2 after ErrTimestampStale from established peer", rejects)
	}
	if !strings.Contains(logBuf.String(), ErrTimestampStale.Error()) {
		t.Fatalf("expected rejection log to mention %v, got: %s", ErrTimestampStale, logBuf.String())
	}

	mu.Lock()
	if len(routedPackets) != 0 {
		t.Fatalf("expected 0 routed packets after second failed initiation, got %d", len(routedPackets))
	}
	mu.Unlock()
}

// TestValidTransportPacket_WithS1MatchingH1_DeliveredWithoutLoss verifies that
// when a legitimate transport data packet happens to have bytes at offset S1 that
// numerically fall within the configured H1 range (causing ParseInitiation to attempt
// MAC1 verification and return ErrMAC1Failed), the listener disambiguates it via
// handleTransportData before rejection and successfully decrypts and delivers the packet,
// with zero packet loss and zero HandshakeRejections increments (issue #288 Round 2).
func TestValidTransportPacket_WithS1MatchingH1_DeliveredWithoutLoss(t *testing.T) {
	ctx := context.Background()

	keysMgr := NewServerKeysManager(nil)
	_, _, err := keysMgr.EnsureKeypair(ctx)
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}

	h1 := models.NewHeaderRange(100, 140)
	h4 := models.NewHeaderRange(200, 240)
	s1 := 36
	s4 := 16

	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
		H1:          h1,
		S1:          s1,
		H4:          h4,
		S4:          s4,
	}
	el, err := NewListener(cfg, nil, nil, nil, nil, keysMgr)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	var routedPackets [][]byte
	var mu sync.Mutex
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		mu.Lock()
		defer mu.Unlock()
		pktCopy := make([]byte, len(pkt))
		copy(pktCopy, pkt)
		routedPackets = append(routedPackets, pktCopy)
		return nil
	})

	var logBuf safeLogBuffer
	origOutput := captureLogOutput(&logBuf)
	defer restoreLogOutput(origOutput)

	peerKey := "established-collision-peer"
	clientAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 210), Port: 46000}
	recvKey := make([]byte, chacha20poly1305.KeySize)
	sendKey := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey {
		recvKey[i] = byte(i + 15)
		sendKey[i] = byte(i + 45)
	}
	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: recvKey,
		SendKey: sendKey,
	})
	el.rememberPeer(clientAddr, peerKey, 60001)

	// Prepare AEAD cipher for the receiver key
	aead, err := chacha20poly1305.New(recvKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}

	// Craft transport packet with valid H4 header at offset S4, and craft ciphertext
	// such that the 4 bytes at offset S1 (which is offset 4 within the ciphertext)
	// match h1.Lo (100).
	var nonce [chacha20poly1305.NonceSize]byte
	var counter uint64 = 7
	binary.LittleEndian.PutUint64(nonce[4:12], counter)

	// In transport packet:
	// datagram = s4Junk (s4 bytes) + transportHeader (16 bytes) + ciphertext
	// Offset of ciphertext in datagram is s4 + 16 = 32.
	// We want datagram[s1:s1+4] (offset 36..40, which is ciphertext[4:8]) to equal h1.Lo.
	cipherOffsetInDatagram := s4 + transportDataHeaderLen
	targetOffsetInCipher := s1 - cipherOffsetInDatagram // 36 - 32 = 4

	// Determine keystream at targetOffsetInCipher by encrypting a zero buffer
	payloadLen := 64
	zeroPlaintext := make([]byte, payloadLen)
	trialCipher := aead.Seal(nil, nonce[:], zeroPlaintext, nil)
	keystreamVal := binary.LittleEndian.Uint32(trialCipher[targetOffsetInCipher : targetOffsetInCipher+4])

	// Now craft plaintext so that plaintext ^ keystream == h1.Lo
	finalPlaintext := make([]byte, payloadLen)
	copy(finalPlaintext, []byte("valid-ip-payload-data-routed-successfully"))
	desiredPlainVal := h1.Lo ^ keystreamVal
	binary.LittleEndian.PutUint32(finalPlaintext[targetOffsetInCipher:targetOffsetInCipher+4], desiredPlainVal)

	ciphertext := aead.Seal(nil, nonce[:], finalPlaintext, nil)

	// Verify our craft: ciphertext[targetOffsetInCipher:targetOffsetInCipher+4] must equal h1.Lo
	if got := binary.LittleEndian.Uint32(ciphertext[targetOffsetInCipher : targetOffsetInCipher+4]); got != h1.Lo {
		t.Fatalf("crafted ciphertext mismatch: got %d, want %d", got, h1.Lo)
	}

	// Build full transport datagram
	s4Junk := make([]byte, s4)
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], h4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 60001) // receiver index
	binary.LittleEndian.PutUint64(hdr[8:16], counter)

	datagram := append(s4Junk, hdr[:]...)
	datagram = append(datagram, ciphertext...)

	// Verify datagram[s1:s1+4] matches h1.Lo
	if got := binary.LittleEndian.Uint32(datagram[s1 : s1+4]); got != h1.Lo {
		t.Fatalf("datagram at offset s1 mismatch: got %d, want %d", got, h1.Lo)
	}

	// Dispatch datagram through listener
	el.handleDatagram(ctx, datagram, clientAddr)

	// Verification 1: packet must NOT be rejected as a failed handshake
	if rejects := el.HandshakeRejections(); rejects != 0 {
		t.Fatalf("HandshakeRejections = %d, want 0 (transport packet was falsely counted as handshake rejection)", rejects)
	}
	if strings.Contains(logBuf.String(), "rejected handshake initiation") {
		t.Fatalf("unexpected handshake rejection log emitted for valid transport packet: %s", logBuf.String())
	}

	// Verification 2: packet must be successfully decrypted and delivered to router
	mu.Lock()
	defer mu.Unlock()
	if len(routedPackets) != 1 {
		t.Fatalf("expected 1 routed packet, got %d", len(routedPackets))
	}
	if !bytes.Equal(routedPackets[0], finalPlaintext) {
		t.Fatalf("routed packet mismatch: got %x, want %x", routedPackets[0], finalPlaintext)
	}
}
