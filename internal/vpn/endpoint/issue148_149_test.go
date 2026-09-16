package endpoint

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func captureLogOutput(w io.Writer) io.Writer {
	orig := log.Writer()
	log.SetOutput(w)
	return orig
}

func restoreLogOutput(orig io.Writer) {
	log.SetOutput(orig)
}

func TestTransportDecryptionLoggingRateLimited_Issue148(t *testing.T) {
	db := setupTestDB(t)
	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
		S4:          16,
		H4:          models.DegenerateHeaderRange(health.DefaultH4),
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	peerKey1 := "test-peer-key-rate-limit-1"
	clientAddr1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:45111")
	recvKey1 := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey1 {
		recvKey1[i] = byte(i + 1)
	}
	sendKey1 := make([]byte, chacha20poly1305.KeySize)
	for i := range sendKey1 {
		sendKey1[i] = byte(i + 33)
	}
	el.storeTransportKeys(peerKey1, &TransportKeys{
		RecvKey: recvKey1,
		SendKey: sendKey1,
	})
	el.rememberPeer(clientAddr1, peerKey1, 10001)

	// Second peer for testing independent per-peer rate limiting
	peerKey2 := "test-peer-key-rate-limit-2"
	clientAddr2, _ := net.ResolveUDPAddr("udp", "127.0.0.1:45222")
	recvKey2 := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey2 {
		recvKey2[i] = byte(i + 50)
	}
	el.storeTransportKeys(peerKey2, &TransportKeys{
		RecvKey: recvKey2,
		SendKey: recvKey2,
	})
	el.rememberPeer(clientAddr2, peerKey2, 10002)

	// Create datagram with valid H4 header but invalid ciphertext (wrong key)
	s4Junk := make([]byte, cfg.S4)
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 10001)
	binary.LittleEndian.PutUint64(hdr[8:16], 1)

	wrongKey := make([]byte, chacha20poly1305.KeySize)
	wrongKey[0] = 0xAA
	wrongAEAD, err := chacha20poly1305.New(wrongKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New wrongKey failed: %v", err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], 1)
	badCiphertext := wrongAEAD.Seal(nil, nonce[:], []byte("bad-payload-data"), nil)

	failDatagram1 := append(s4Junk, hdr[:]...)
	failDatagram1 = append(failDatagram1, badCiphertext...)

	var logBuf safeLogBuffer
	origOutput := captureLogOutput(&logBuf)
	defer restoreLogOutput(origOutput)

	ctx := context.Background()

	// 1. Send 50 rapid failing datagrams for peer 1
	for i := 0; i < 50; i++ {
		el.handleDatagram(ctx, failDatagram1, clientAddr1)
	}

	// Should be logged exactly once due to 5-second per-peer rate limit
	countPeer1 := strings.Count(logBuf.String(), "transport data decryption failed for peer "+peerKey1)
	if countPeer1 != 1 {
		t.Fatalf("expected exactly 1 decryption failure log for peer 1 within throttle window, got %d. Logs:\n%s", countPeer1, logBuf.String())
	}

	// 2. Peer 2 should have its own rate limiter and log immediately when it fails
	binary.LittleEndian.PutUint32(hdr[4:8], 10002)
	failDatagram2 := append(s4Junk, hdr[:]...)
	failDatagram2 = append(failDatagram2, badCiphertext...)

	for i := 0; i < 20; i++ {
		el.handleDatagram(ctx, failDatagram2, clientAddr2)
	}

	countPeer2 := strings.Count(logBuf.String(), "transport data decryption failed for peer "+peerKey2)
	if countPeer2 != 1 {
		t.Fatalf("expected exactly 1 decryption failure log for peer 2, got %d. Logs:\n%s", countPeer2, logBuf.String())
	}

	// Peer 1 count should still be 1
	countPeer1After := strings.Count(logBuf.String(), "transport data decryption failed for peer "+peerKey1)
	if countPeer1After != 1 {
		t.Fatalf("peer 1 count changed unexpectedly to %d", countPeer1After)
	}

	// 3. Advance peer 1's rate limiter timestamp past expiry to simulate throttle window elapsed
	st1, ok := el.peerByAddr(clientAddr1.String())
	if !ok {
		t.Fatal("peer 1 not found in peersByAddr")
	}
	st1.decryptLogUntil.Store(time.Now().Unix() - 1)

	// Send another failing datagram for peer 1
	el.handleDatagram(ctx, failDatagram1, clientAddr1)

	countPeer1Expired := strings.Count(logBuf.String(), "transport data decryption failed for peer "+peerKey1)
	if countPeer1Expired != 2 {
		t.Fatalf("expected exactly 2 logs after rate limit expiry, got %d. Logs:\n%s", countPeer1Expired, logBuf.String())
	}
}

func TestTransportDecryptionDecoupledFromHandshakeRejects_Issue149(t *testing.T) {
	db := setupTestDB(t)
	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
		S4:          16,
		H4:          models.DegenerateHeaderRange(health.DefaultH4),
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	peerKey := "test-peer-key-decoupling"
	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:46111")
	recvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey {
		recvKey[i] = byte(i + 10)
	}
	sendKey := make([]byte, chacha20poly1305.KeySize)
	for i := range sendKey {
		sendKey[i] = byte(i + 40)
	}
	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: recvKey,
		SendKey: sendKey,
	})
	el.rememberPeer(clientAddr, peerKey, 20001)

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

	ctx := context.Background()
	initialRejects := el.HandshakeRejections()

	// 1. Send failing transport datagrams (valid H4, wrong ciphertext) from KNOWN peer
	s4Junk := make([]byte, cfg.S4)
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 20001)
	binary.LittleEndian.PutUint64(hdr[8:16], 1)

	wrongKey := make([]byte, chacha20poly1305.KeySize)
	wrongKey[0] = 0xBB
	wrongAEAD, _ := chacha20poly1305.New(wrongKey)
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], 1)
	badCiphertext := wrongAEAD.Seal(nil, nonce[:], []byte("wrong-ciphertext"), nil)

	failDatagram := append(s4Junk, hdr[:]...)
	failDatagram = append(failDatagram, badCiphertext...)

	for i := 0; i < 30; i++ {
		el.handleDatagram(ctx, failDatagram, clientAddr)
	}

	// Verify decoupling: HandshakeRejections must NOT increase
	if after := el.HandshakeRejections(); after != initialRejects {
		t.Fatalf("HandshakeRejections incremented on transport decryption failure: got %d, want %d", after, initialRejects)
	}

	// Verify no rejected handshake initiation logs were emitted for clientAddr
	if strings.Contains(logBuf.String(), "rejected handshake initiation from "+clientAddr.String()) {
		t.Fatalf("unexpected handshake rejection log for established peer: %s", logBuf.String())
	}

	// Verify corrupt packet was dropped and NOT routed
	mu.Lock()
	if len(routedPackets) != 0 {
		t.Fatalf("expected 0 routed packets, got %d", len(routedPackets))
	}
	mu.Unlock()

	// 2. Send corrupted H4 datagrams from KNOWN peer (neither H1 nor H4)
	corruptDatagram := make([]byte, len(failDatagram))
	copy(corruptDatagram, failDatagram)
	corruptDatagram[cfg.S4] ^= 0xEE
	corruptDatagram[cfg.S4+1] ^= 0xEE

	for i := 0; i < 20; i++ {
		el.handleDatagram(ctx, corruptDatagram, clientAddr)
	}

	if after := el.HandshakeRejections(); after != initialRejects {
		t.Fatalf("HandshakeRejections incremented on corrupt packet from established peer: got %d, want %d", after, initialRejects)
	}
	if strings.Contains(logBuf.String(), "rejected handshake initiation from "+clientAddr.String()) {
		t.Fatalf("unexpected handshake rejection log for established peer: %s", logBuf.String())
	}

	// 3. Send invalid datagram from UNKNOWN sender: MUST increment HandshakeRejections
	// Use full-length plausible datagram (> s1 + 148 bytes) with invalid message type
	// so ParseInitiation fails with ErrNotInitiation (not ErrDatagramTooShort) and logs rejection.
	unknownAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:49999")
	unknownDatagram := make([]byte, 200)
	binary.LittleEndian.PutUint32(unknownDatagram[0:4], 99999)
	el.handleDatagram(ctx, unknownDatagram, unknownAddr)

	if after := el.HandshakeRejections(); after != initialRejects+1 {
		t.Fatalf("HandshakeRejections failed to increment on unknown sender datagram: got %d, want %d", after, initialRejects+1)
	}
	if !strings.Contains(logBuf.String(), "rejected handshake initiation from "+unknownAddr.String()) {
		t.Fatalf("expected handshake rejection log for unknown sender, got:\n%s", logBuf.String())
	}

	// 4. Send valid transport datagram from KNOWN peer: MUST decrypt and route normally
	aead, err := chacha20poly1305.New(recvKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}
	testPayload := []byte("valid-ip-packet-content")
	var validCounter uint64 = 2
	binary.LittleEndian.PutUint64(nonce[4:12], validCounter)
	validCiphertext := aead.Seal(nil, nonce[:], testPayload, nil)

	binary.LittleEndian.PutUint64(hdr[8:16], validCounter)
	validDatagram := append(s4Junk, hdr[:]...)
	validDatagram = append(validDatagram, validCiphertext...)

	el.handleDatagram(ctx, validDatagram, clientAddr)

	mu.Lock()
	if len(routedPackets) != 1 {
		t.Fatalf("expected 1 routed packet, got %d", len(routedPackets))
	}
	if !bytes.Equal(routedPackets[0], testPayload) {
		t.Fatalf("routed packet mismatch: got %s, want %s", string(routedPackets[0]), string(testPayload))
	}
	mu.Unlock()

	// Handshake rejections counter must still remain initialRejects + 1
	if after := el.HandshakeRejections(); after != initialRejects+1 {
		t.Fatalf("HandshakeRejections unexpectedly changed: got %d, want %d", after, initialRejects+1)
	}
}

func TestConcurrentTransportDecryptionFailures_ThreadSafety(t *testing.T) {
	db := setupTestDB(t)
	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
		S4:          16,
		H4:          models.DegenerateHeaderRange(health.DefaultH4),
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	peerKey := "test-peer-key-concurrent"
	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:47111")
	recvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey {
		recvKey[i] = byte(i + 7)
	}
	sendKey := make([]byte, chacha20poly1305.KeySize)
	for i := range sendKey {
		sendKey[i] = byte(i + 27)
	}
	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: recvKey,
		SendKey: sendKey,
	})
	el.rememberPeer(clientAddr, peerKey, 30001)

	s4Junk := make([]byte, cfg.S4)
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 30001)
	binary.LittleEndian.PutUint64(hdr[8:16], 1)

	wrongKey := make([]byte, chacha20poly1305.KeySize)
	wrongKey[0] = 0xCC
	wrongAEAD, _ := chacha20poly1305.New(wrongKey)
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], 1)
	badCiphertext := wrongAEAD.Seal(nil, nonce[:], []byte("concurrent-bad-payload"), nil)

	failDatagram := append(s4Junk, hdr[:]...)
	failDatagram = append(failDatagram, badCiphertext...)

	var logBuf safeLogBuffer
	origOutput := captureLogOutput(&logBuf)
	defer restoreLogOutput(origOutput)

	ctx := context.Background()
	const numGoroutines = 10
	const itersPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < itersPerGoroutine; i++ {
				el.handleDatagram(ctx, failDatagram, clientAddr)
			}
		}()
	}

	wg.Wait()

	// Decoupling: zero handshake rejections from established peer
	if rejects := el.HandshakeRejections(); rejects != 0 {
		t.Fatalf("expected 0 handshake rejections from established peer under concurrency, got %d", rejects)
	}

	// Rate limiting: exactly 1 log line even across 500 concurrent failure events within 5s window
	logCount := strings.Count(logBuf.String(), "transport data decryption failed for peer "+peerKey)
	if logCount != 1 {
		t.Fatalf("expected exactly 1 rate-limited log under concurrency, got %d. Logs:\n%s", logCount, logBuf.String())
	}
}
