package endpoint

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// setupIssue295LiveTestListener creates a test listener with database, authenticator,
// randomized header ranges, and Header Protection enabled.
func setupIssue295LiveTestListener(t *testing.T) (*Listener, [32]byte, []byte, int64) {
	t.Helper()
	db := setupTestDB(t)
	ctx := context.Background()

	hpKey := make([]byte, 32)
	if _, err := rand.Read(hpKey); err != nil {
		t.Fatalf("rand.Read(hpKey) failed: %v", err)
	}

	h1 := models.NewHeaderRange(100, 140)
	h2 := models.NewHeaderRange(200, 240)
	h4 := models.NewHeaderRange(400, 440)
	s1 := 16
	s2 := 16
	s4 := 16

	cfg := ListenerConfig{
		ListenPort:          getFreeUDPPort(t),
		SubnetCIDR:          "10.100.0.0/24",
		MTU:                 1420,
		IdleTimeout:         1 * time.Minute,
		HeaderProtectionKey: base64.StdEncoding.EncodeToString(hpKey),
		H1:                  h1,
		S1:                  s1,
		H2:                  h2,
		S2:                  s2,
		H4:                  h4,
		S4:                  s4,
	}

	keysMgr := NewServerKeysManager(db)
	el, err := NewListener(cfg, db, nil, nil, nil, keysMgr)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	var genMu sync.Mutex
	peerGens := make(map[string]uint64)
	el.SetIncomingPeerHandler(func(ctx context.Context, peerPublicKey string) (*models.VPNSession, *models.BackendTunnel, error) {
		auth := NewDBAuthenticator(db)
		user, _, authErr := auth.AuthenticatePeer(ctx, peerPublicKey)
		if authErr != nil {
			return nil, nil, authErr
		}
		ip, allocErr := el.IPAM().Allocate(peerPublicKey)
		if allocErr != nil {
			return nil, nil, allocErr
		}
		genMu.Lock()
		peerGens[peerPublicKey]++
		curGen := peerGens[peerPublicKey]
		genMu.Unlock()
		sess, sessErr := el.SessionManager().CreateSession(ctx, user.ID, peerPublicKey, ip.String(), 1, "", curGen)
		return sess, &models.BackendTunnel{ID: 1}, sessErr
	})

	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	_, sPub, err := keysMgr.EnsureKeypair(ctx)
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "rekey-srv", Host: "10.0.0.1"})
	_, _ = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sID, InterfaceName: "awg-be-1", PublicKey: "pubkey", PrivateKey: "privkey", Endpoint: "10.0.0.1:51820",
	})

	return el, sPub, hpKey, sID
}

// newTestClient generates a client static keypair and registers it in the DB connection table.
func newTestClient(t *testing.T, db *database.DB, sID int64, username string) ([]byte, string) {
	t.Helper()
	clientPriv := make([]byte, 32)
	if _, err := rand.Read(clientPriv); err != nil {
		t.Fatalf("rand.Read(clientPriv) failed: %v", err)
	}
	clientPub, err := curve25519.X25519(clientPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519 failed: %v", err)
	}
	peerKey := base64.StdEncoding.EncodeToString(clientPub)

	ctx := context.Background()
	uID, err := db.CreateUser(ctx, &models.User{Username: username, Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	_, err = db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: peerKey,
	})
	if err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}
	return clientPriv, peerKey
}

// craftClientTransportDatagram builds an AWG transport datagram with Header Protection.
func craftClientTransportDatagram(
	t *testing.T,
	keys *TransportKeys,
	h4Val uint32,
	s4 int,
	hpKey []byte,
	counter uint64,
	payload []byte,
) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(keys.RecvKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}

	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	ciphertext := aead.Seal(nil, nonce[:], payload, nil)

	s4Junk := make([]byte, s4)
	if _, err := rand.Read(s4Junk); err != nil {
		t.Fatalf("rand.Read(s4Junk) failed: %v", err)
	}

	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], h4Val)
	binary.LittleEndian.PutUint32(hdr[4:8], keys.LocalIndex)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)

	// Apply header protection
	if len(hpKey) == 32 && s4 >= health.HeaderCipherNonceSize {
		cip := health.NewHeaderProtectionCipher(hpKey, s4Junk[:health.HeaderCipherNonceSize])
		if cip == nil {
			t.Fatal("failed to create client-side HP cipher")
		}
		cip.XORKeyStream(hdr[:], hdr[:])
	}

	datagram := append(s4Junk, hdr[:]...)
	datagram = append(datagram, ciphertext...)
	return datagram
}

// performClientHandshakeUnconfirmed performs the responder exchange through
// receipt/verification of the handshake response, but deliberately does not
// send authenticated transport. Nexus must therefore keep the derived key in
// next and continue using the previously confirmed current key.
func performClientHandshakeUnconfirmed(
	t *testing.T,
	clientConn *net.UDPConn,
	serverPub [32]byte,
	clientPriv []byte,
	hpKey []byte,
	h1 models.HeaderRange,
	s1 int,
	h2 models.HeaderRange,
	s2 int,
) *health.NoiseClientState {
	t.Helper()
	pkt, state, err := health.BuildAWGInitiationPacketObfuscated(serverPub[:], clientPriv, nil, hpKey, h1, s1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated failed: %v", err)
	}

	if _, err := clientConn.Write(pkt); err != nil {
		t.Fatalf("write initiation failed: %v", err)
	}

	respBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read handshake response failed: %v", err)
	}

	if !health.VerifyAWGResponsePacketObfuscated(respBuf[:n], state, hpKey, h2, s2) {
		t.Fatal("VerifyAWGResponsePacketObfuscated rejected response")
	}

	return state
}

// performClientHandshake performs a complete test handshake including the
// initiator's immediate authenticated confirmation of the responder key. Most
// legacy #295 tests exercise already-confirmed rollover; #329 tests use
// performClientHandshakeUnconfirmed when they need the pending-next window.
func performClientHandshake(
	t *testing.T,
	el *Listener,
	clientConn *net.UDPConn,
	serverPub [32]byte,
	clientPriv []byte,
	hpKey []byte,
	h1 models.HeaderRange,
	s1 int,
	h2 models.HeaderRange,
	s2 int,
) *health.NoiseClientState {
	t.Helper()
	state := performClientHandshakeUnconfirmed(t, clientConn, serverPub, clientPriv, hpKey, h1, s1, h2, s2)

	clientPub, err := curve25519.X25519(clientPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive client public key: %v", err)
	}
	peerKey := base64.StdEncoding.EncodeToString(clientPub)

	var next *TransportKeys
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, _, next = el.PeerKeypairStateForTest(peerKey)
		if next != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if next == nil {
		t.Fatalf("expected staged responder next key for %s", peerKey)
	}

	status, ok := el.ConfirmResponderTransportKeyForTest(peerKey, next)
	if !ok || status != "current" {
		t.Fatalf("failed to confirm responder next key: status=%q ok=%v", status, ok)
	}
	st := el.updatePeerEndpointAfterDecryption(clientConn.LocalAddr().(*net.UDPAddr), peerKey, next.RemoteIndex, true)
	if st != nil {
		st.lastSeen.Store(time.Now().UnixNano())
	}

	return state
}

// TestRekeyRollover_PreviousKeyInFlightAcceptance verifies that when a client rekeys,
// transport packets encrypted with the previous keypair remain acceptable and routable,
// and packets encrypted with the new keypair work concurrently.
func TestRekeyRollover_PreviousKeyInFlightAcceptance(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	serverAddr, ok := el.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el.GetListenAddr())
	}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	var routedPackets [][]byte
	var routedPeers []string
	var mu sync.Mutex
	el.SetClientPacketRouter(func(peerKey string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		pktCopy := make([]byte, len(packet))
		copy(pktCopy, packet)
		routedPackets = append(routedPackets, pktCopy)
		routedPeers = append(routedPeers, peerKey)
		return nil
	})

	var logBuf safeLogBuffer
	origOutput := captureLogOutput(&logBuf)
	defer restoreLogOutput(origOutput)

	// Step 1: Register client in DB and perform Initial Handshake (Handshake 1, gen 1)
	clientPriv, peerKey := newTestClient(t, el.db, sID, "rekey_peer_1")
	state1 := performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	_ = state1

	curr1, prev1 := el.PeerKeypairsForTest(peerKey)
	if curr1 == nil {
		t.Fatal("expected current transport keys after handshake 1")
	}
	if prev1 != nil {
		t.Fatal("expected nil previous transport keys after handshake 1")
	}
	if curr1.Generation != 1 {
		t.Fatalf("expected generation 1, got %d", curr1.Generation)
	}
	if curr1.LocalIndex == 0 {
		t.Fatal("expected non-zero LocalIndex on current keys")
	}
	keys1 := curr1

	// Step 2: Client performs Rekey (Handshake 2, gen 2)
	state2 := performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	_ = state2

	curr2, prev2 := el.PeerKeypairsForTest(peerKey)
	if curr2 == nil || prev2 == nil {
		t.Fatalf("expected both current and previous transport keys after rekey: curr=%v prev=%v", curr2, prev2)
	}
	if curr2.Generation != 2 {
		t.Fatalf("expected current generation 2, got %d", curr2.Generation)
	}
	if prev2.Generation != 1 {
		t.Fatalf("expected previous generation 1, got %d", prev2.Generation)
	}
	if prev2 != keys1 {
		t.Fatal("previous keyset does not match keyset from Handshake 1")
	}
	keys2 := curr2

	// Step 3: In-flight packet using previous keypair (keys1) arrives AFTER rekey completes
	pktOldPayload := []byte("in-flight-packet-using-key1")
	oldDatagram := craftClientTransportDatagram(t, keys1, el.config.H4.Lo, el.config.S4, hpKey, 1, pktOldPayload)

	if _, err := clientConn.Write(oldDatagram); err != nil {
		t.Fatalf("failed to send old key transport packet: %v", err)
	}

	// Give worker pool time to process
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 1 {
		t.Fatalf("expected 1 routed packet for in-flight old key, got %d", len(routedPackets))
	}
	if !bytes.Equal(routedPackets[0], pktOldPayload) {
		t.Fatalf("routed packet mismatch: got %q, want %q", routedPackets[0], pktOldPayload)
	}
	if routedPeers[0] != peerKey {
		t.Fatalf("routed peer mismatch: got %q, want %q", routedPeers[0], peerKey)
	}
	mu.Unlock()

	// Verify log contains previous key utilization message
	if !strings.Contains(logBuf.String(), "accepted transport packet with previous keypair for peer "+peerKey) {
		t.Errorf("expected previous keypair acceptance log, got:\n%s", logBuf.String())
	}

	// Step 4: Current key packet (keys2) works concurrently
	pktNewPayload := []byte("new-session-packet-using-key2")
	newDatagram := craftClientTransportDatagram(t, keys2, el.config.H4.Lo, el.config.S4, hpKey, 1, pktNewPayload)

	if _, err := clientConn.Write(newDatagram); err != nil {
		t.Fatalf("failed to send new key transport packet: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 2 {
		t.Fatalf("expected 2 routed packets total, got %d", len(routedPackets))
	}
	if !bytes.Equal(routedPackets[1], pktNewPayload) {
		t.Fatalf("second routed packet mismatch: got %q, want %q", routedPackets[1], pktNewPayload)
	}
	mu.Unlock()
}

// TestRekeyRollover_ExpiredOldKeyRejected verifies that packets encrypted under an expired
// previous keypair are rejected and dropped without affecting current keys.
func TestRekeyRollover_ExpiredOldKeyRejected(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	serverAddr := el.GetListenAddr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	var routedPackets [][]byte
	var mu sync.Mutex
	el.SetClientPacketRouter(func(peerKey string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		routedPackets = append(routedPackets, append([]byte(nil), packet...))
		return nil
	})

	var logBuf safeLogBuffer
	origOutput := captureLogOutput(&logBuf)
	defer restoreLogOutput(origOutput)

	clientPriv, peerKey := newTestClient(t, el.db, sID, "expire_peer")

	// Handshake 1
	performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	keys1, _ := el.PeerKeypairsForTest(peerKey)

	// Handshake 2 (rekey)
	performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	keys2, prevKeys := el.PeerKeypairsForTest(peerKey)

	if prevKeys == nil || prevKeys != keys1 {
		t.Fatal("expected prevKeys to match keys1")
	}

	// Mark previous key as expired (in the past)
	prevKeys.SetExpiresAt(time.Now().Add(-10 * time.Second))

	initialRejections := el.HandshakeRejections()

	// Send packet using expired key
	expiredPayload := []byte("expired-key-payload")
	expiredDatagram := craftClientTransportDatagram(t, prevKeys, el.config.H4.Lo, el.config.S4, hpKey, 1, expiredPayload)

	if _, err := clientConn.Write(expiredDatagram); err != nil {
		t.Fatalf("failed to write expired datagram: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Verify packet was dropped (not routed)
	mu.Lock()
	if len(routedPackets) != 0 {
		t.Fatalf("expected 0 routed packets for expired key, got %d", len(routedPackets))
	}
	mu.Unlock()

	// Handshake rejections must not be incremented (decoupled)
	if after := el.HandshakeRejections(); after != initialRejections {
		t.Fatalf("HandshakeRejections incremented on expired transport packet: got %d, want %d", after, initialRejections)
	}

	// Verify log contains expired status
	if !strings.Contains(logBuf.String(), "status=expired") {
		t.Errorf("expected status=expired log, got:\n%s", logBuf.String())
	}

	// Current key (keys2) still works normally
	validPayload := []byte("valid-current-key-payload")
	validDatagram := craftClientTransportDatagram(t, keys2, el.config.H4.Lo, el.config.S4, hpKey, 1, validPayload)
	if _, err := clientConn.Write(validDatagram); err != nil {
		t.Fatalf("failed to write valid datagram: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 1 {
		t.Fatalf("expected 1 routed packet for current key, got %d", len(routedPackets))
	}
	if !bytes.Equal(routedPackets[0], validPayload) {
		t.Fatalf("routed packet mismatch: got %q, want %q", routedPackets[0], validPayload)
	}
	mu.Unlock()
}

// TestRekeyRollover_AntiReplayProtection verifies that replayed transport packets
// across both previous and current keypairs are rejected by the sliding window filter.
func TestRekeyRollover_AntiReplayProtection(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	serverAddr := el.GetListenAddr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	var routedPackets [][]byte
	var mu sync.Mutex
	el.SetClientPacketRouter(func(peerKey string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		routedPackets = append(routedPackets, append([]byte(nil), packet...))
		return nil
	})

	var logBuf safeLogBuffer
	origOutput := captureLogOutput(&logBuf)
	defer restoreLogOutput(origOutput)

	clientPriv, peerKey := newTestClient(t, el.db, sID, "replay_peer")

	// Handshake 1
	performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	keys1, _ := el.PeerKeypairsForTest(peerKey)

	// Handshake 2 (rekey)
	performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	keys2, prevKeys := el.PeerKeypairsForTest(peerKey)
	if prevKeys != keys1 {
		t.Fatal("expected prevKeys to match keys1")
	}

	// 1. Send counter 1 with previous key (keys1) -> ACCEPTED
	p1 := []byte("counter-1-packet")
	d1 := craftClientTransportDatagram(t, prevKeys, el.config.H4.Lo, el.config.S4, hpKey, 1, p1)
	if _, err := clientConn.Write(d1); err != nil {
		t.Fatalf("write d1: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 1 {
		t.Fatalf("expected 1 routed packet, got %d", len(routedPackets))
	}
	mu.Unlock()

	// 2. Replay counter 1 with previous key (keys1) -> REJECTED
	if _, err := clientConn.Write(d1); err != nil {
		t.Fatalf("write d1 replay: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 1 {
		t.Fatalf("replay of counter 1 was accepted! routed count = %d", len(routedPackets))
	}
	mu.Unlock()

	// Verify log contains replay rejection
	if !strings.Contains(logBuf.String(), "transport data replay rejected for peer "+peerKey) {
		t.Errorf("expected replay rejection log, got:\n%s", logBuf.String())
	}

	// 3. Send counter 5 with previous key -> ACCEPTED
	p5 := []byte("counter-5-packet")
	d5 := craftClientTransportDatagram(t, prevKeys, el.config.H4.Lo, el.config.S4, hpKey, 5, p5)
	if _, err := clientConn.Write(d5); err != nil {
		t.Fatalf("write d5: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 2 {
		t.Fatalf("expected 2 routed packets, got %d", len(routedPackets))
	}
	mu.Unlock()

	// 4. Send counter 3 with previous key (in-window out-of-order) -> ACCEPTED
	p3 := []byte("counter-3-packet")
	d3 := craftClientTransportDatagram(t, prevKeys, el.config.H4.Lo, el.config.S4, hpKey, 3, p3)
	if _, err := clientConn.Write(d3); err != nil {
		t.Fatalf("write d3: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 3 {
		t.Fatalf("expected 3 routed packets, got %d", len(routedPackets))
	}
	mu.Unlock()

	// 5. Replay counter 3 with previous key -> REJECTED
	if _, err := clientConn.Write(d3); err != nil {
		t.Fatalf("write d3 replay: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 3 {
		t.Fatalf("duplicate counter 3 was accepted! routed count = %d", len(routedPackets))
	}
	mu.Unlock()

	// 6. Current key (keys2) has independent replay filter: counter 1 on keys2 -> ACCEPTED
	pNew1 := []byte("new-key-counter-1")
	dNew1 := craftClientTransportDatagram(t, keys2, el.config.H4.Lo, el.config.S4, hpKey, 1, pNew1)
	if _, err := clientConn.Write(dNew1); err != nil {
		t.Fatalf("write dNew1: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 4 {
		t.Fatalf("expected 4 routed packets, got %d", len(routedPackets))
	}
	mu.Unlock()

	// Replay counter 1 on current keys -> REJECTED
	if _, err := clientConn.Write(dNew1); err != nil {
		t.Fatalf("write dNew1 replay: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 4 {
		t.Fatalf("duplicate counter 1 on new key was accepted! routed count = %d", len(routedPackets))
	}
	mu.Unlock()
}

// TestRekeyRollover_ReceiverIndexRouting_MultiPeer verifies that packets are routed
// directly to the correct peer and generation using the receiver index header field.
func TestRekeyRollover_ReceiverIndexRouting_MultiPeer(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	serverAddr := el.GetListenAddr().(*net.UDPAddr)

	connA, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP connA: %v", err)
	}
	defer func() { _ = connA.Close() }()

	connB, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP connB: %v", err)
	}
	defer func() { _ = connB.Close() }()

	routedMap := make(map[string][][]byte)
	var mu sync.Mutex
	el.SetClientPacketRouter(func(peerKey string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		routedMap[peerKey] = append(routedMap[peerKey], append([]byte(nil), packet...))
		return nil
	})

	// Handshake Peer A
	privA, peerKeyA := newTestClient(t, el.db, sID, "multi_peer_A")
	performClientHandshake(t, el, connA, sPub, privA, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	performClientHandshake(t, el, connA, sPub, privA, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2) // rekey
	currA, prevA := el.PeerKeypairsForTest(peerKeyA)

	// Handshake Peer B
	privB, peerKeyB := newTestClient(t, el.db, sID, "multi_peer_B")
	performClientHandshake(t, el, connB, sPub, privB, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	performClientHandshake(t, el, connB, sPub, privB, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2) // rekey
	currB, prevB := el.PeerKeypairsForTest(peerKeyB)

	// IndexTable must contain exactly 4 entries: prevA, currA, prevB, currB
	if count := el.IndexTableCountForTest(); count != 4 {
		t.Fatalf("expected 4 entries in indexTable, got %d", count)
	}

	// Send packet for Peer A's previous key
	pPrevA := []byte("pkt-peer-A-prev")
	dPrevA := craftClientTransportDatagram(t, prevA, el.config.H4.Lo, el.config.S4, hpKey, 1, pPrevA)
	if _, err := connA.Write(dPrevA); err != nil {
		t.Fatalf("write dPrevA: %v", err)
	}

	// Send packet for Peer B's previous key
	pPrevB := []byte("pkt-peer-B-prev")
	dPrevB := craftClientTransportDatagram(t, prevB, el.config.H4.Lo, el.config.S4, hpKey, 1, pPrevB)
	if _, err := connB.Write(dPrevB); err != nil {
		t.Fatalf("write dPrevB: %v", err)
	}

	// Send packet for Peer A's current key
	pCurrA := []byte("pkt-peer-A-curr")
	dCurrA := craftClientTransportDatagram(t, currA, el.config.H4.Lo, el.config.S4, hpKey, 1, pCurrA)
	if _, err := connA.Write(dCurrA); err != nil {
		t.Fatalf("write dCurrA: %v", err)
	}

	// Send packet for Peer B's current key
	pCurrB := []byte("pkt-peer-B-curr")
	dCurrB := craftClientTransportDatagram(t, currB, el.config.H4.Lo, el.config.S4, hpKey, 1, pCurrB)
	if _, err := connB.Write(dCurrB); err != nil {
		t.Fatalf("write dCurrB: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(routedMap[peerKeyA]) != 2 {
		t.Fatalf("expected 2 packets for Peer A, got %d", len(routedMap[peerKeyA]))
	}
	containsPacket := func(list [][]byte, target []byte) bool {
		for _, item := range list {
			if bytes.Equal(item, target) {
				return true
			}
		}
		return false
	}

	if !containsPacket(routedMap[peerKeyA], pPrevA) || !containsPacket(routedMap[peerKeyA], pCurrA) {
		t.Fatalf("Peer A packet content mismatch: %v", routedMap[peerKeyA])
	}

	if len(routedMap[peerKeyB]) != 2 {
		t.Fatalf("expected 2 packets for Peer B, got %d", len(routedMap[peerKeyB]))
	}
	if !containsPacket(routedMap[peerKeyB], pPrevB) || !containsPacket(routedMap[peerKeyB], pCurrB) {
		t.Fatalf("Peer B packet content mismatch: %v", routedMap[peerKeyB])
	}
}

// TestRekeyRollover_DeterministicRetirementAndBoundedMemory verifies bounded keypair
// retention (at most 1 previous key per peer) and deterministic pruning of expired/disconnected keys.
func TestRekeyRollover_DeterministicRetirementAndBoundedMemory(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	ctx := context.Background()
	serverAddr := el.GetListenAddr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	clientPriv, peerKey := newTestClient(t, el.db, sID, "retire_peer")

	// Handshake 1: Gen 1
	performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	k1, prev1 := el.PeerKeypairsForTest(peerKey)
	if k1 == nil || prev1 != nil {
		t.Fatalf("unexpected state after H1: k1=%v prev=%v", k1, prev1)
	}
	idx1 := k1.LocalIndex
	if count := el.IndexTableCountForTest(); count != 1 {
		t.Fatalf("expected 1 entry in indexTable, got %d", count)
	}

	// Handshake 2: Gen 2
	performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	k2, prev2 := el.PeerKeypairsForTest(peerKey)
	if k2.Generation != 2 || prev2 != k1 {
		t.Fatalf("unexpected state after H2: k2.gen=%d prev=%v", k2.Generation, prev2)
	}
	idx2 := k2.LocalIndex
	if count := el.IndexTableCountForTest(); count != 2 {
		t.Fatalf("expected 2 entries in indexTable, got %d", count)
	}

	// Handshake 3: Gen 3 -> k1 MUST be retired and purged from indexTable
	performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	k3, prev3 := el.PeerKeypairsForTest(peerKey)
	if k3.Generation != 3 || prev3 != k2 {
		t.Fatalf("unexpected state after H3: k3.gen=%d prev=%v", k3.Generation, prev3)
	}
	idx3 := k3.LocalIndex

	// IndexTable count must still be 2 (idx3 and idx2), NOT 3!
	if count := el.IndexTableCountForTest(); count != 2 {
		t.Fatalf("expected 2 entries in indexTable after H3 (bounded memory), got %d", count)
	}

	// Verify idx1 was purged from indexTable
	if _, ok := el.lookupKeypairByIndex(idx1); ok {
		t.Fatal("idx1 should have been purged from indexTable after Gen 3")
	}
	// Verify idx2 and idx3 are present
	if _, ok := el.lookupKeypairByIndex(idx2); !ok {
		t.Fatal("idx2 should be present in indexTable")
	}
	if _, ok := el.lookupKeypairByIndex(idx3); !ok {
		t.Fatal("idx3 should be present in indexTable")
	}

	// Periodic sweep: expire k2 (previous key) and run sweep
	prev3.SetExpiresAt(time.Now().Add(-10 * time.Second))
	_, sweepErr := el.SweepTimedOutSessions(ctx)
	if sweepErr != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", sweepErr)
	}

	// k2 should now be pruned: pkp.previous == nil and idx2 removed from indexTable
	currAfterSweep, prevAfterSweep := el.PeerKeypairsForTest(peerKey)
	if currAfterSweep == nil || prevAfterSweep != nil {
		t.Fatalf("expected pkp.previous to be nil after sweep of expired key, got %v", prevAfterSweep)
	}
	if count := el.IndexTableCountForTest(); count != 1 {
		t.Fatalf("expected 1 entry in indexTable after sweep, got %d", count)
	}
	if _, ok := el.lookupKeypairByIndex(idx2); ok {
		t.Fatal("idx2 should have been purged from indexTable after sweep")
	}

	// Complete disconnection: DisconnectPeer prunes all remaining keys and indexTable entries
	if err := el.DisconnectPeer(ctx, peerKey); err != nil {
		t.Fatalf("DisconnectPeer failed: %v", err)
	}

	if count := el.IndexTableCountForTest(); count != 0 {
		t.Fatalf("expected 0 entries in indexTable after DisconnectPeer, got %d", count)
	}
	if _, ok := el.lookupKeypairByIndex(idx3); ok {
		t.Fatal("idx3 should have been purged from indexTable after DisconnectPeer")
	}
	currFinal, prevFinal := el.PeerKeypairsForTest(peerKey)
	if currFinal != nil || prevFinal != nil {
		t.Fatalf("expected nil keypairs after disconnect: curr=%v prev=%v", currFinal, prevFinal)
	}
}

// TestTransportKeys_ValidateCounter_Unit tests counter validation, sliding window,
// and concurrent safety on TransportKeys directly.
func TestTransportKeys_ValidateCounter_Unit(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	tk, err := NewTransportKeys(key, key)
	if err != nil {
		t.Fatalf("NewTransportKeys: %v", err)
	}

	// Counter 0: valid on first use
	if !tk.ValidateCounter(0) {
		t.Fatal("counter 0 should be valid on first use")
	}
	// Counter 0 duplicate: rejected
	if tk.ValidateCounter(0) {
		t.Fatal("counter 0 duplicate should be rejected")
	}

	// In-order counters
	for i := uint64(1); i <= 100; i++ {
		if !tk.ValidateCounter(i) {
			t.Fatalf("counter %d should be accepted", i)
		}
	}
	// Duplicates rejected
	for i := uint64(1); i <= 100; i++ {
		if tk.ValidateCounter(i) {
			t.Fatalf("duplicate counter %d should be rejected", i)
		}
	}

	// Out-of-order jump forward
	if !tk.ValidateCounter(500) {
		t.Fatal("jump to counter 500 should be accepted")
	}
	// In-window unread counter
	if !tk.ValidateCounter(499) {
		t.Fatal("unread counter 499 in window should be accepted")
	}
	// Duplicate 499 rejected
	if tk.ValidateCounter(499) {
		t.Fatal("duplicate 499 should be rejected")
	}

	// Way behind window (sliding window is 2048 packets)
	if !tk.ValidateCounter(5000) {
		t.Fatal("jump to counter 5000 should be accepted")
	}
	if tk.ValidateCounter(100) {
		t.Fatal("counter 100 is >2048 packets behind and must be rejected")
	}

	// Concurrent thread safety test
	const numGoroutines = 20
	const iters = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		gIdx := uint64(g)
		go func() {
			defer wg.Done()
			for i := uint64(0); i < iters; i++ {
				c := 10000 + gIdx*iters + i
				_ = tk.ValidateCounter(c)
			}
		}()
	}
	wg.Wait()
}

// TestTransportKeys_IsExpired_Unit tests key expiration logic.
func TestTransportKeys_IsExpired_Unit(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	tk, err := NewTransportKeys(key, key)
	if err != nil {
		t.Fatalf("NewTransportKeys: %v", err)
	}

	// Zero ExpiresAt: not expired
	if tk.IsExpired() {
		t.Fatal("zero ExpiresAt should not be expired")
	}

	// Future ExpiresAt: not expired
	tk.ExpiresAt = time.Now().Add(10 * time.Minute)
	if tk.IsExpired() {
		t.Fatal("future ExpiresAt should not be expired")
	}

	// Past ExpiresAt: expired
	tk.ExpiresAt = time.Now().Add(-1 * time.Minute)
	if !tk.IsExpired() {
		t.Fatal("past ExpiresAt should be expired")
	}

	// Nil receiver: expired (safe default)
	var nilTK *TransportKeys
	if !nilTK.IsExpired() {
		t.Fatal("nil receiver should report expired")
	}
}

// TestTransportKeys_NextSendCounter_Unit verifies that NextSendCounter() starts at 0,
// increments monotonically, safely handles nil, and generates unique nonces under concurrency.
func TestTransportKeys_NextSendCounter_Unit(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	tk, err := NewTransportKeys(key, key)
	if err != nil {
		t.Fatalf("NewTransportKeys: %v", err)
	}

	// Nil receiver safety
	var nilTK *TransportKeys
	if c := nilTK.NextSendCounter(); c != 0 {
		t.Fatalf("nilTK.NextSendCounter() = %d, want 0", c)
	}

	// Sequential increments
	for i := uint64(0); i < 100; i++ {
		got := tk.NextSendCounter()
		if got != i {
			t.Fatalf("NextSendCounter() = %d, want %d", got, i)
		}
	}

	// Concurrent increments: verify all counters are unique and no gaps
	const numGoroutines = 20
	const iters = 100
	var wg sync.WaitGroup
	var counters sync.Map

	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				c := tk.NextSendCounter()
				if _, loaded := counters.LoadOrStore(c, struct{}{}); loaded {
					t.Errorf("duplicate counter generated: %d", c)
				}
			}
		}()
	}
	wg.Wait()

	// tk should now have emitted exactly 100 + 20*100 = 2100 counters (0..2099)
	for expected := uint64(100); expected < 2100; expected++ {
		if _, ok := counters.Load(expected); !ok {
			t.Fatalf("missing counter in concurrent test: %d", expected)
		}
	}
	if next := tk.NextSendCounter(); next != 2100 {
		t.Fatalf("expected next counter 2100, got %d", next)
	}
}

// TestRekeyRollover_BoundedCompatibilityFallback verifies that packets with unknown
// receiver indices (e.g. synthetic test keys without local index registration) fall back
// to sender-address based peer lookup, attempting current keys first, then previous keys.
func TestRekeyRollover_BoundedCompatibilityFallback(t *testing.T) {
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

	peerKey := "test-peer-fallback"
	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:48111")

	recvKey1 := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey1 {
		recvKey1[i] = byte(i + 1)
	}
	sendKey1 := make([]byte, chacha20poly1305.KeySize)
	for i := range sendKey1 {
		sendKey1[i] = byte(i + 31)
	}
	// Handshake 1 with LocalIndex = 0 (synthetic)
	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: recvKey1,
		SendKey: sendKey1,
	})
	el.rememberPeer(clientAddr, peerKey, 70001)

	// Handshake 2 with LocalIndex = 0 (synthetic)
	recvKey2 := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey2 {
		recvKey2[i] = byte(i + 51)
	}
	sendKey2 := make([]byte, chacha20poly1305.KeySize)
	for i := range sendKey2 {
		sendKey2[i] = byte(i + 81)
	}
	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: recvKey2,
		SendKey: sendKey2,
	})

	var routedPackets [][]byte
	var mu sync.Mutex
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		mu.Lock()
		defer mu.Unlock()
		routedPackets = append(routedPackets, append([]byte(nil), pkt...))
		return nil
	})

	ctx := context.Background()

	// 1. Send packet encrypted with key2 (current): should decrypt via current key fallback
	aead2, _ := chacha20poly1305.New(recvKey2)
	payload2 := []byte("payload-key2-current")
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], 1)
	c2 := aead2.Seal(nil, nonce[:], payload2, nil)

	s4Junk := make([]byte, cfg.S4)
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 99999) // unknown index
	binary.LittleEndian.PutUint64(hdr[8:16], 1)

	datagram2 := append(append(s4Junk, hdr[:]...), c2...)
	el.handleDatagram(ctx, datagram2, clientAddr)

	mu.Lock()
	if len(routedPackets) != 1 || !bytes.Equal(routedPackets[0], payload2) {
		t.Fatalf("expected packet 2 routed via current key fallback, got %v", routedPackets)
	}
	mu.Unlock()

	// 2. Send packet encrypted with key1 (previous): current key decrypt fails, previous key succeeds!
	aead1, _ := chacha20poly1305.New(recvKey1)
	payload1 := []byte("payload-key1-previous")
	binary.LittleEndian.PutUint64(nonce[4:12], 2)
	c1 := aead1.Seal(nil, nonce[:], payload1, nil)
	binary.LittleEndian.PutUint64(hdr[8:16], 2)

	datagram1 := append(append(s4Junk, hdr[:]...), c1...)
	el.handleDatagram(ctx, datagram1, clientAddr)

	mu.Lock()
	if len(routedPackets) != 2 || !bytes.Equal(routedPackets[1], payload1) {
		t.Fatalf("expected packet 1 routed via previous key fallback, got %v", routedPackets)
	}
	mu.Unlock()
}

// TestRekeyRollover_ConcurrentFallbackAndRotation_Race executes simultaneous fallback
// decryption and keypair rotation under go test -race to verify candidateFallbackKeys
// lock synchronization under el.mu.RLock (Finding 1).
func TestRekeyRollover_ConcurrentFallbackAndRotation_Race(t *testing.T) {
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

	peerKey := "race-peer-fallback"
	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:48222")
	el.rememberPeer(clientAddr, peerKey, 80001)

	var routedCount atomic.Uint64
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		routedCount.Add(1)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Key holder to safely share current and previous recvKeys between rotator and workers
	var keyMu sync.RWMutex
	var currentRecvKey []byte
	var prevRecvKey []byte

	// 1. Goroutine rotating transport keys continuously
	wg.Add(1)
	go func() {
		defer wg.Done()
		gen := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
				gen++
				recvKey := make([]byte, chacha20poly1305.KeySize)
				sendKey := make([]byte, chacha20poly1305.KeySize)
				_, _ = rand.Read(recvKey)
				_, _ = rand.Read(sendKey)

				keyMu.Lock()
				prevRecvKey = currentRecvKey
				currentRecvKey = recvKey
				keyMu.Unlock()

				el.storeTransportKeys(peerKey, &TransportKeys{
					RecvKey: recvKey,
					SendKey: sendKey,
				})
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// 2. Multiple worker goroutines decrypting packets via fallback path
	numWorkers := 4
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			var counter uint64
			s4Junk := make([]byte, cfg.S4)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					counter++
					keyMu.RLock()
					k := currentRecvKey
					if counter%2 == 0 && prevRecvKey != nil {
						k = prevRecvKey
					}
					keyMu.RUnlock()

					if len(k) == 0 {
						time.Sleep(1 * time.Millisecond)
						continue
					}

					aead, err := chacha20poly1305.New(k)
					if err != nil {
						continue
					}
					payload := []byte(fmt.Sprintf("worker-%d-pkt-%d", workerID, counter))
					var nonce [chacha20poly1305.NonceSize]byte
					binary.LittleEndian.PutUint64(nonce[4:12], counter)
					ciphertext := aead.Seal(nil, nonce[:], payload, nil)

					var hdr [transportDataHeaderLen]byte
					binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
					binary.LittleEndian.PutUint32(hdr[4:8], 99999) // unknown index to force fallback
					binary.LittleEndian.PutUint64(hdr[8:16], counter)

					datagram := append(append(s4Junk, hdr[:]...), ciphertext...)
					el.handleDatagram(ctx, datagram, clientAddr)
				}
			}
		}(i)
	}

	wg.Wait()

	if routedCount.Load() == 0 {
		t.Fatal("expected at least some packets to be successfully routed during concurrent test")
	}
}

// TestRekeyRollover_SweepTimedOutSessions_SkipsPruningIfNewerActiveSessionExists verifies that
// SweepTimedOutSessions does not prune crypto state or endpoint mapping when a peer has
// re-established a newer active session concurrently (Finding 2).
func TestRekeyRollover_SweepTimedOutSessions_SkipsPruningIfNewerActiveSessionExists(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
	}

	ipam, _ := NewIPAM(cfg.SubnetCIDR)
	sm := NewSessionManager(db, ipam)

	el, err := NewListener(cfg, db, nil, ipam, sm, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	peerKey := "peer-concurrent-rekey"
	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:48333")

	uID, err := db.CreateUser(ctx, &models.User{Username: "user-sweep", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "srv-sweep", Host: "10.0.0.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sID, InterfaceName: "awg-be-1", PublicKey: "pubkey", PrivateKey: "privkey", Endpoint: "10.0.0.1:51820",
	})

	// 1. Establish session 1 for peer
	sess1, err := sm.CreateSession(ctx, uID, peerKey, "10.100.0.50", tID, "conn-1")
	if err != nil {
		t.Fatalf("CreateSession sess1 failed: %v", err)
	}
	keys1 := &TransportKeys{LocalIndex: 11111, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	el.storeTransportKeys(peerKey, keys1)
	el.rememberPeer(clientAddr, peerKey, keys1.LocalIndex)

	// Make sess1 appear timed out
	sm.SetSessionLastSeen(peerKey, time.Now().UTC().Add(-10*time.Minute))

	// Verify sess1 is active before concurrent rekey
	active1, ok := sm.GetSession(peerKey)
	if !ok || active1.ID != sess1.ID {
		t.Fatalf("expected sess1 active, got %+v", active1)
	}

	// 2. Peer establishes session 2 concurrently (e.g. rekey/reconnect)
	sess2, err := sm.CreateSession(ctx, uID, peerKey, "10.100.0.50", tID, "conn-1")
	if err != nil {
		t.Fatalf("CreateSession sess2 failed: %v", err)
	}
	keys2 := &TransportKeys{LocalIndex: 22222, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	el.storeTransportKeys(peerKey, keys2)

	// 3. Now call SweepTimedOutSessions: sess2 is fresh, so sess2 is not timed out.
	// When sweep evaluates the timed out sess1, it detects active sess2 and preserves crypto state.
	timedOut, err := el.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	for _, s := range timedOut {
		if s.ID == sess2.ID {
			t.Fatalf("sess2 should not have timed out")
		}
	}

	// 4. Crypto state for peerKey MUST NOT be pruned because sess2 is active!
	cur, _ := el.PeerKeypairsForTest(peerKey)
	if cur == nil || cur.LocalIndex != keys2.LocalIndex {
		t.Fatalf("expected keys2 (index %d) retained for peer, got %+v", keys2.LocalIndex, cur)
	}
	if entry, found := el.lookupKeypairByIndex(keys2.LocalIndex); !found || entry.keys != keys2 {
		t.Fatalf("expected indexTable entry for keys2 retained, found=%v", found)
	}
	if _, ok := el.peerByAddr(clientAddr.String()); !ok {
		t.Fatal("expected peer address mapping retained for active session")
	}

	// 5. Negative check: when sess2 genuinely times out with no newer session, keypairs ARE pruned
	sm.SetSessionLastSeen(peerKey, time.Now().UTC().Add(-10*time.Minute))
	timedOut2, err := el.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions 2 failed: %v", err)
	}
	if len(timedOut2) == 0 {
		t.Fatal("expected sess2 to be swept")
	}
	cur2, prev2 := el.PeerKeypairsForTest(peerKey)
	if cur2 != nil || prev2 != nil {
		t.Fatalf("expected crypto state pruned after genuine timeout, got cur=%+v prev=%+v", cur2, prev2)
	}
}

// TestRekeyRollover_AllocateReceiverIndex_CollisionAvoidance tests that allocateReceiverIndex
// skips collided indices and assigns unique non-zero receiver indices (Finding 3).
func TestRekeyRollover_AllocateReceiverIndex_CollisionAvoidance(t *testing.T) {
	db := setupTestDB(t)
	cfg := ListenerConfig{
		ListenPort: getFreeUDPPort(t),
		SubnetCIDR: "10.100.0.0/24",
		MTU:        1420,
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	// 1. Seed indexTable with reserved indices
	preExisting := []uint32{0x00010001, 0x00020002, 0x00030003}
	el.mu.Lock()
	for _, idx := range preExisting {
		el.indexTable[idx] = &keypairEntry{peerKey: "pre-existing", keys: &TransportKeys{LocalIndex: idx}}
	}
	el.mu.Unlock()

	// 2. Allocate single index and verify it doesn't collide with pre-existing
	allocated := el.allocateReceiverIndex("test-peer")
	if allocated == 0 {
		t.Fatal("allocated index must be non-zero")
	}
	for _, idx := range preExisting {
		if allocated == idx {
			t.Fatalf("allocated index collided with pre-existing index %d", idx)
		}
	}
	// Verify reserved in indexTable
	entry, found := el.lookupKeypairByIndex(allocated)
	if !found || entry == nil || entry.peerKey != "test-peer" {
		t.Fatalf("allocated index %d not properly registered in indexTable", allocated)
	}

	// 3. Concurrent allocation test: 20 goroutines x 50 allocations
	const workers = 20
	const perWorker = 50
	var allocatedIndices sync.Map
	var collisions atomic.Uint64

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				idx := el.allocateReceiverIndex(fmt.Sprintf("peer-w%d-%d", workerID, i))
				if idx == 0 {
					collisions.Add(1)
				}
				if _, loaded := allocatedIndices.LoadOrStore(idx, true); loaded {
					collisions.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()

	if collisions.Load() != 0 {
		t.Fatalf("detected %d collisions during concurrent receiver index allocation", collisions.Load())
	}

	// 4. Test BuildResponse with preallocated index
	serverPriv, serverPub := newTestServerKeypair(t)
	packet, _, err := health.BuildAWGInitiationPacket(serverPub, nil, nil, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket failed: %v", err)
	}
	info, err := ParseInitiation(serverPriv, packet, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("ParseInitiation failed: %v", err)
	}

	targetIdx := el.allocateReceiverIndex("target-peer")
	resp, tk, err := BuildResponse(serverPriv, info, health.DefaultH2, health.DefaultS2, nil, targetIdx)
	if err != nil {
		t.Fatalf("BuildResponse failed: %v", err)
	}
	if tk.LocalIndex != targetIdx {
		t.Fatalf("expected tk.LocalIndex=%d, got %d", targetIdx, tk.LocalIndex)
	}
	wireIdx := binary.LittleEndian.Uint32(resp[health.DefaultS2+4 : health.DefaultS2+8])
	if wireIdx != targetIdx {
		t.Fatalf("expected wire sender index=%d, got %d", targetIdx, wireIdx)
	}

	// 5. Test BuildResponse with preallocatedIdx = 0 (fallback to random)
	resp2, tk2, err := BuildResponse(serverPriv, info, health.DefaultH2, health.DefaultS2, nil, 0)
	if err != nil {
		t.Fatalf("BuildResponse with 0 failed: %v", err)
	}
	if tk2.LocalIndex == 0 {
		t.Fatal("expected non-zero random LocalIndex when preallocatedIdx is 0")
	}
	wireIdx2 := binary.LittleEndian.Uint32(resp2[health.DefaultS2+4 : health.DefaultS2+8])
	if wireIdx2 != tk2.LocalIndex {
		t.Fatalf("wire index mismatch: got %d want %d", wireIdx2, tk2.LocalIndex)
	}
}

// TestRekeyRollover_DisconnectPeer_ValidatesSessionBeforePruning tests that DisconnectPeer
// validates the session exists in sessionMgr before pruning crypto state, returning
// ErrPeerNotFound without mutating state if not found (Finding 4).
func TestRekeyRollover_DisconnectPeer_ValidatesSessionBeforePruning(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	cfg := ListenerConfig{
		ListenPort: getFreeUDPPort(t),
		SubnetCIDR: "10.100.0.0/24",
		MTU:        1420,
	}

	ipam, _ := NewIPAM(cfg.SubnetCIDR)
	sm := NewSessionManager(db, ipam)

	el, err := NewListener(cfg, db, nil, ipam, sm, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	ghostPeer := "ghost-peer-disconnect"
	ghostKeys := &TransportKeys{LocalIndex: 55555, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	el.storeTransportKeys(ghostPeer, ghostKeys)

	// Verify ghostPeer has keys in listener
	cur, _ := el.PeerKeypairsForTest(ghostPeer)
	if cur == nil || cur.LocalIndex != ghostKeys.LocalIndex {
		t.Fatalf("expected ghostKeys stored, got %+v", cur)
	}

	// Disconnect non-existent peer
	err = el.DisconnectPeer(ctx, ghostPeer)
	if !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("expected ErrPeerNotFound, got %v", err)
	}

	// Crypto state MUST NOT have been pruned!
	curAfter, _ := el.PeerKeypairsForTest(ghostPeer)
	if curAfter == nil || curAfter.LocalIndex != ghostKeys.LocalIndex {
		t.Fatalf("ghostPeer crypto state was mutated on ErrPeerNotFound! got %+v", curAfter)
	}
	if k, ok := el.TransportKeysFor(ghostPeer); !ok || k != ghostKeys {
		t.Fatal("ghostPeer noiseKeys was cleared on ErrPeerNotFound")
	}

	// Now register a real peer with session
	realPeer := "real-peer-disconnect"
	uIDReal, err := db.CreateUser(ctx, &models.User{Username: "user-real-disc", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	sIDReal, _ := db.CreateServer(ctx, &models.Server{Name: "srv-real-disc", Host: "10.0.0.1"})
	tIDReal, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sIDReal, InterfaceName: "awg-be-real", PublicKey: "pubkey", PrivateKey: "privkey", Endpoint: "10.0.0.1:51820",
	})
	realKeys := &TransportKeys{LocalIndex: 66666, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	_, err = sm.CreateSession(ctx, uIDReal, realPeer, "10.100.0.60", tIDReal, "conn-real")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	el.storeTransportKeys(realPeer, realKeys)

	// Disconnect real peer
	err = el.DisconnectPeer(ctx, realPeer)
	if err != nil {
		t.Fatalf("expected nil error on real peer disconnect, got %v", err)
	}

	// Real peer crypto state MUST be pruned
	curReal, prevReal := el.PeerKeypairsForTest(realPeer)
	if curReal != nil || prevReal != nil {
		t.Fatalf("expected real peer keys pruned, got cur=%+v prev=%+v", curReal, prevReal)
	}
	if _, ok := el.TransportKeysFor(realPeer); ok {
		t.Fatal("expected real peer noiseKeys cleared")
	}
}

// TestRekeyRollover_OutboundReceiverIndex_PrefersCurrentKeysRemoteIndex verifies Finding 1:
// When K1 is active, the client rekeys to K2 (with remote index R2).
// When a late K1 packet is accepted, it must NOT overwrite the peer's outbound receiver index with R1.
// A subsequent SendToPeer() must prefer keys.RemoteIndex (R2), placing R2 in the outbound header,
// and allowing the client to decrypt successfully with K2 (and failing with K1).
func TestRekeyRollover_OutboundReceiverIndex_PrefersCurrentKeysRemoteIndex(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	serverAddr, ok := el.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el.GetListenAddr())
	}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	var routedPackets [][]byte
	var mu sync.Mutex
	el.SetClientPacketRouter(func(peerKey string, packet []byte) error {
		mu.Lock()
		defer mu.Unlock()
		routedPackets = append(routedPackets, append([]byte(nil), packet...))
		return nil
	})

	// Handshake 1: Establish initial keypair K1
	clientPriv, peerKey := newTestClient(t, el.db, sID, "rekey_peer_r2")
	_ = performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)

	k1, prev1 := el.PeerKeypairsForTest(peerKey)
	if k1 == nil || prev1 != nil {
		t.Fatalf("unexpected keypairs after Handshake 1: curr=%v prev=%v", k1, prev1)
	}
	r1 := k1.RemoteIndex
	if r1 == 0 {
		t.Fatal("expected non-zero RemoteIndex for K1")
	}

	// Handshake 2: Rekey to K2
	_ = performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)

	k2, prev2 := el.PeerKeypairsForTest(peerKey)
	if k2 == nil || prev2 == nil {
		t.Fatalf("unexpected keypairs after Handshake 2: curr=%v prev=%v", k2, prev2)
	}
	r2 := k2.RemoteIndex
	if r2 == 0 {
		t.Fatal("expected non-zero RemoteIndex for K2")
	}
	if r1 == r2 {
		t.Fatalf("expected different remote indices for K1 and K2: r1=%d r2=%d", r1, r2)
	}

	// Late K1 packet arrives after rekey
	latePayload := []byte("late-k1-packet-payload")
	lateDatagram := craftClientTransportDatagram(t, k1, el.config.H4.Lo, el.config.S4, hpKey, 5, latePayload)
	if _, err := clientConn.Write(lateDatagram); err != nil {
		t.Fatalf("failed to send late K1 datagram: %v", err)
	}

	// Allow worker pool to process inbound packet
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 1 || !bytes.Equal(routedPackets[0], latePayload) {
		t.Fatalf("expected late K1 packet routed successfully, got %v", routedPackets)
	}
	mu.Unlock()

	// Verify st.receiverIdx was NOT corrupted with R1
	clientSenderAddr := clientConn.LocalAddr().String()
	st, found := el.peerByAddr(clientSenderAddr)
	if !found || st == nil {
		t.Fatalf("expected activePeerState found for sender %s", clientSenderAddr)
	}
	if stRecv := st.receiverIdx.Load(); stRecv != r2 {
		t.Fatalf("st.receiverIdx was overwritten with previous remote index! got %d, want %d", stRecv, r2)
	}

	// Immediately invoke SendToPeer()
	outboundMsg := []byte("outbound-reply-after-late-k1")
	if err := el.SendToPeer(peerKey, outboundMsg); err != nil {
		t.Fatalf("SendToPeer failed: %v", err)
	}

	// Read outbound datagram on clientConn
	replyBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(replyBuf)
	if err != nil {
		t.Fatalf("client failed to read SendToPeer packet: %v", err)
	}

	datagramOut := replyBuf[:n]
	s4 := el.config.S4
	if len(datagramOut) < s4+transportDataHeaderLen+len(outboundMsg)+chacha20poly1305.Overhead {
		t.Fatalf("outbound datagram too short: %d", len(datagramOut))
	}

	// Unmask header using HP key
	recvCip := health.NewHeaderProtectionCipher(hpKey, datagramOut[:health.HeaderCipherNonceSize])
	if recvCip == nil {
		t.Fatal("failed to create client unmask cipher")
	}
	unmaskedHdr := make([]byte, transportDataHeaderLen)
	recvCip.XORKeyStream(unmaskedHdr, datagramOut[s4:s4+transportDataHeaderLen])

	outboundReceiverIdx := binary.LittleEndian.Uint32(unmaskedHdr[4:8])
	if outboundReceiverIdx != r2 {
		t.Fatalf("SendToPeer sent incorrect receiverIdx: got %d, want R2=%d (R1=%d)", outboundReceiverIdx, r2, r1)
	}

	outboundCounter := binary.LittleEndian.Uint64(unmaskedHdr[8:16])
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], outboundCounter)

	// Client decrypts with K2
	k2AEAD, err := chacha20poly1305.New(k2.SendKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New for K2 failed: %v", err)
	}
	decryptedK2, err := k2AEAD.Open(nil, nonce[:], datagramOut[s4+transportDataHeaderLen:], nil)
	if err != nil {
		t.Fatalf("client failed to decrypt outbound packet with K2: %v", err)
	}
	if !bytes.Equal(decryptedK2, outboundMsg) {
		t.Fatalf("decrypted payload mismatch: got %q, want %q", decryptedK2, outboundMsg)
	}

	// Client decrypts with K1 MUST fail
	k1AEAD, err := chacha20poly1305.New(k1.SendKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New for K1 failed: %v", err)
	}
	if _, err := k1AEAD.Open(nil, nonce[:], datagramOut[s4+transportDataHeaderLen:], nil); err == nil {
		t.Fatal("client unexpectedly succeeded decrypting K2 ciphertext with K1 key")
	}
}

// TestRekeyRollover_SweepInterleavedRekey_PreservesNewKeys tests Finding 2:
// When a session times out, but an interleaved rekey establishes a newer session
// before the sweep prunes crypto state, prunePeerKeypairsIfMatch aborts and preserves
// the new session's keys, index table entry, and address mapping.
func TestRekeyRollover_SweepInterleavedRekey_PreservesNewKeys(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	cfg := ListenerConfig{
		ListenPort: getFreeUDPPort(t),
		SubnetCIDR: "10.100.0.0/24",
		MTU:        1420,
	}

	ipam, _ := NewIPAM(cfg.SubnetCIDR)
	sm := NewSessionManager(db, ipam)

	el, err := NewListener(cfg, db, nil, ipam, sm, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	peerKey := "peer-interleaved-rekey"
	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:49111")

	uID, err := db.CreateUser(ctx, &models.User{Username: "user-interleaved", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "srv-interleaved", Host: "10.0.0.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sID, InterfaceName: "awg-be-1", PublicKey: "pubkey", PrivateKey: "privkey", Endpoint: "10.0.0.1:51820",
	})

	// 1. Establish session 1 for peer
	sess1, err := sm.CreateSession(ctx, uID, peerKey, "10.100.0.50", tID, "conn-1")
	if err != nil {
		t.Fatalf("CreateSession sess1 failed: %v", err)
	}
	keys1 := &TransportKeys{LocalIndex: 33333, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	el.storeTransportKeys(peerKey, keys1, sess1.ID)
	el.rememberPeer(clientAddr, peerKey, keys1.LocalIndex)

	if sessID := el.PeerSessionIDForTest(peerKey); sessID != sess1.ID {
		t.Fatalf("expected session ID %s, got %s", sess1.ID, sessID)
	}

	// 2. sess1 times out
	sm.SetSessionLastSeen(peerKey, time.Now().UTC().Add(-10*time.Minute))
	timedOut, err := sm.CheckTimeouts(ctx, 1*time.Minute)
	if err != nil || len(timedOut) == 0 {
		t.Fatalf("expected sess1 in timedOut, got %v", timedOut)
	}

	// 3. Interleaved rekey establishes session 2 before sweep prunes
	sess2, err := sm.CreateSession(ctx, uID, peerKey, "10.100.0.50", tID, "conn-1")
	if err != nil {
		t.Fatalf("CreateSession sess2 failed: %v", err)
	}
	keys2 := &TransportKeys{LocalIndex: 44444, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	el.storeTransportKeys(peerKey, keys2, sess2.ID)

	if sessID := el.PeerSessionIDForTest(peerKey); sessID != sess2.ID {
		t.Fatalf("expected session ID %s after rekey, got %s", sess2.ID, sessID)
	}

	// 4. Sweep processes the timed-out sess1 using prunePeerKeypairsIfMatch
	pruned := el.prunePeerKeypairsIfMatch(sess1.PeerPublicKey, sess1.ID)
	if pruned {
		t.Fatal("prunePeerKeypairsIfMatch should have aborted pruning when expectedSessionID does not match")
	}

	// Verify keys2, indexTable entry, and address mapping are preserved
	cur, _ := el.PeerKeypairsForTest(peerKey)
	if cur == nil || cur.LocalIndex != keys2.LocalIndex {
		t.Fatalf("expected keys2 preserved, got %+v", cur)
	}
	if entry, found := el.lookupKeypairByIndex(keys2.LocalIndex); !found || entry.keys != keys2 {
		t.Fatalf("expected indexTable entry for keys2 preserved, found=%v", found)
	}
	if _, ok := el.peerByAddr(clientAddr.String()); !ok {
		t.Fatal("expected peer address mapping preserved for active session")
	}
	if k, ok := el.TransportKeysFor(peerKey); !ok || k != keys2 {
		t.Fatal("expected TransportKeysFor to return keys2")
	}

	// 5. Test DisconnectPeer with stale session ID
	// If DisconnectPeer tries to prune an older session ID, it should abort and preserve keys2
	prunedOldDisc := el.prunePeerKeypairsIfMatch(peerKey, sess1.ID)
	if prunedOldDisc {
		t.Fatal("prunePeerKeypairsIfMatch should abort for stale session ID during disconnect")
	}

	// 6. When sess2 genuinely times out, sweep prunes successfully
	sm.SetSessionLastSeen(peerKey, time.Now().UTC().Add(-10*time.Minute))
	timedOut2, err := el.SweepTimedOutSessions(ctx)
	if err != nil || len(timedOut2) == 0 {
		t.Fatalf("expected sess2 swept on genuine timeout, got %v", timedOut2)
	}
	curFinal, prevFinal := el.PeerKeypairsForTest(peerKey)
	if curFinal != nil || prevFinal != nil {
		t.Fatalf("expected keys pruned after genuine timeout, got cur=%+v prev=%+v", curFinal, prevFinal)
	}
	if _, ok := el.TransportKeysFor(peerKey); ok {
		t.Fatal("expected noiseKeys cleared after genuine timeout")
	}
}

// TestRekeyRollover_PreviousKeyLoggingThrottled verifies Finding 3:
// Previous-key acceptance logging is throttled to at most once per second per peer,
// preventing log flooding under sustained rollover traffic.
func TestRekeyRollover_PreviousKeyLoggingThrottled(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	serverAddr, ok := el.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el.GetListenAddr())
	}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	var routedPackets atomic.Int64
	el.SetClientPacketRouter(func(peerKey string, packet []byte) error {
		routedPackets.Add(1)
		return nil
	})

	var logBuf safeLogBuffer
	origOutput := captureLogOutput(&logBuf)
	defer restoreLogOutput(origOutput)

	// Handshake 1 & Handshake 2
	clientPriv, peerKey := newTestClient(t, el.db, sID, "rekey_peer_throttle")
	_ = performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)
	_ = performClientHandshake(t, el, clientConn, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)

	_, prev := el.PeerKeypairsForTest(peerKey)
	if prev == nil {
		t.Fatal("expected previous keypair after rekey")
	}

	// Send 30 consecutive packets using previous keypair (prev) rapidly within the same second
	const numPackets = 30
	for i := uint64(1); i <= numPackets; i++ {
		pkt := craftClientTransportDatagram(t, prev, el.config.H4.Lo, el.config.S4, hpKey, i, []byte(fmt.Sprintf("pkt-%d", i)))
		if _, err := clientConn.Write(pkt); err != nil {
			t.Fatalf("failed to send packet %d: %v", i, err)
		}
	}

	// Give workers time to process
	time.Sleep(100 * time.Millisecond)

	if routed := routedPackets.Load(); routed != numPackets {
		t.Fatalf("expected %d routed packets, got %d", numPackets, routed)
	}

	// Count occurrences of previous key acceptance log message
	targetLog := "accepted transport packet with previous keypair for peer " + peerKey
	count := strings.Count(logBuf.String(), targetLog)
	if count != 1 {
		t.Fatalf("expected previous key acceptance log to be throttled to 1 occurrence, got %d\nLog content:\n%s",
			count, logBuf.String())
	}
}

// TestHandshakeCommit_StaleSessionDisconnectSuppressesTransportAndResponse verifies that
// if an active session is disconnected while a handshake worker is paused prior to committing
// transport state, commitHandshakeTransportState detects that the session is no longer active,
// aborts installation, releases the allocated receiver index, prevents address registration,
// suppresses the handshake response transmission, and leaves no transport state for the peer.
func TestHandshakeCommit_StaleSessionDisconnectSuppressesTransportAndResponse(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	ctx := context.Background()
	serverAddr, ok := el.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el.GetListenAddr())
	}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	clientPriv, peerKey := newTestClient(t, el.db, sID, "stale_handshake_peer")

	hookFired := make(chan string, 1)
	resumeHook := make(chan struct{})

	el.SetPreTransportCommitHookForTest(func(pKey string, sessID string) {
		if pKey == peerKey {
			hookFired <- sessID
			<-resumeHook
		}
	})

	// Handshake initiates -> creates session S_1
	pkt, _, err := health.BuildAWGInitiationPacketObfuscated(sPub[:], clientPriv, nil, hpKey, el.config.H1, el.config.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated failed: %v", err)
	}

	if _, err := clientConn.Write(pkt); err != nil {
		t.Fatalf("write initiation failed: %v", err)
	}

	var sessID string
	select {
	case sessID = <-hookFired:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for preTransportCommitHook to fire")
	}

	// Verify session S_1 exists and is connected
	sess, ok := el.SessionManager().GetSessionByID(sessID)
	if !ok || sess == nil || sess.Status != "connected" {
		t.Fatalf("expected active connected session S_1 before disconnect, got %+v", sess)
	}

	// Disconnect session S_1 via DisconnectSession
	if err := el.DisconnectSession(ctx, sessID); err != nil {
		t.Fatalf("DisconnectSession failed: %v", err)
	}

	// Resume worker -> commitHandshakeTransportState executes
	close(resumeHook)

	// Worker should drop response and not send anything
	_ = clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	respBuf := make([]byte, 2048)
	n, err := clientConn.Read(respBuf)
	if err == nil {
		t.Fatalf("expected no handshake response transmitted over UDP, got %d bytes", n)
	}

	// Assert:
	// 1. commitHandshakeTransportState returned false (verified directly via CommitHandshakeTransportStateForTest)
	dummyKeys := &TransportKeys{LocalIndex: 77777, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	if el.CommitHandshakeTransportStateForTest(peerKey, sessID, dummyKeys, 77777, serverAddr, 0) {
		t.Fatal("expected commitHandshakeTransportState to return false for stale disconnected session")
	}

	// 2. No transport state exists for the peer (HasTransportStateForPeer is false, noiseKeys has no entry)
	if el.HasTransportStateForPeer(peerKey) {
		t.Fatal("expected HasTransportStateForPeer to return false")
	}
	if _, ok := el.TransportKeysFor(peerKey); ok {
		t.Fatal("expected noiseKeys to have no entry for peer")
	}
	cur, prev := el.PeerKeypairsForTest(peerKey)
	if cur != nil || prev != nil {
		t.Fatalf("expected nil peerKeypairs, got cur=%+v, prev=%+v", cur, prev)
	}

	// 3. Allocated receiver index was released from indexTable
	if count := el.IndexTableCountForTest(); count != 0 {
		t.Fatalf("expected indexTable to be empty, got %d entries", count)
	}

	// 4. peersByAddr has no entry for the sender
	if el.HasPeerAddrForTest(peerKey) {
		t.Fatal("expected peersByAddr to have no entry for sender")
	}
	clientLocalAddr := clientConn.LocalAddr().String()
	if _, ok := el.peerByAddr(clientLocalAddr); ok {
		t.Fatalf("expected no peersByAddr entry for %s", clientLocalAddr)
	}
}

// TestHandshakeCommit_ConcurrentHandshakeReplacementProtectsNewerSession verifies that
// when concurrent handshakes H1 and H2 race for the same peer, and H2 creates a replacement
// session S2 and commits transport keys K2 before H1 resumes, H1's commit is dropped,
// K2/S2 remains active, and stale K1 keys do not clobber K2.
func TestHandshakeCommit_ConcurrentHandshakeReplacementProtectsNewerSession(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	serverAddr, ok := el.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el.GetListenAddr())
	}

	clientConn1, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP conn1: %v", err)
	}
	defer func() { _ = clientConn1.Close() }()

	clientConn2, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP conn2: %v", err)
	}
	defer func() { _ = clientConn2.Close() }()

	clientPriv, peerKey := newTestClient(t, el.db, sID, "concurrent_replacement_peer")

	var h1Fired atomic.Bool
	h1PauseChan := make(chan struct{})
	h1FiredChan := make(chan string, 1)

	el.SetPreTransportCommitHookForTest(func(pKey string, sessID string) {
		if pKey != peerKey {
			return
		}
		if h1Fired.CompareAndSwap(false, true) {
			h1FiredChan <- sessID
			<-h1PauseChan
		}
	})

	// Handshake H_1 initiates -> creates session S_1
	pkt1, _, err := health.BuildAWGInitiationPacketObfuscated(sPub[:], clientPriv, nil, hpKey, el.config.H1, el.config.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated H1: %v", err)
	}
	if _, err := clientConn1.Write(pkt1); err != nil {
		t.Fatalf("write initiation H1: %v", err)
	}

	var s1ID string
	select {
	case s1ID = <-h1FiredChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for H1 worker to pause at preTransportCommitHook")
	}

	// Handshake H_2 initiates for the same peer while H1 is paused
	pkt2, state2, err := health.BuildAWGInitiationPacketObfuscated(sPub[:], clientPriv, nil, hpKey, el.config.H1, el.config.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated H2: %v", err)
	}
	if _, err := clientConn2.Write(pkt2); err != nil {
		t.Fatalf("write initiation H2: %v", err)
	}

	// Worker H2 creates replacement session S_2, commits transport keys K_2, and sends response
	respBuf2 := make([]byte, 2048)
	_ = clientConn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n2, err := clientConn2.Read(respBuf2)
	if err != nil {
		t.Fatalf("failed to read H2 response: %v", err)
	}
	if !health.VerifyAWGResponsePacketObfuscated(respBuf2[:n2], state2, hpKey, el.config.H2, el.config.S2) {
		t.Fatal("VerifyAWGResponsePacketObfuscated rejected H2 response")
	}

	// Verify K_2 / S_2 state before resuming H1
	k2Current, k2Prev := el.PeerKeypairsForTest(peerKey)
	if k2Current == nil {
		t.Fatal("expected current transport keys K2 for peer after H2")
	}
	if k2Prev != nil {
		t.Fatalf("expected nil previous keys for peer after replacement H2, got %+v", k2Prev)
	}
	s2ID := el.PeerSessionIDForTest(peerKey)
	if s2ID == "" || s2ID == s1ID {
		t.Fatalf("expected distinct active session ID for S2, got %s (S1=%s)", s2ID, s1ID)
	}
	k2LocalIdx := k2Current.LocalIndex

	// Resume H_1 with stale S_1 -> worker H_1 commits
	close(h1PauseChan)

	// Worker H1 should drop response and not send anything
	_ = clientConn1.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	respBuf1 := make([]byte, 2048)
	n1, err := clientConn1.Read(respBuf1)
	if err == nil {
		t.Fatalf("expected H1 response to be dropped, but read %d bytes", n1)
	}

	// Assert:
	// 1. H1 commit is dropped/rejected: CommitHandshakeTransportStateForTest with S1 returns false
	dummyKeys := &TransportKeys{LocalIndex: 88888, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	if el.CommitHandshakeTransportStateForTest(peerKey, s1ID, dummyKeys, 88888, serverAddr, 0) {
		t.Fatal("expected commitHandshakeTransportState to return false for superseded S1")
	}

	// 2. K_2 / S_2 remains the active current keypair in peerKeypairs and noiseKeys
	curFinal, prevFinal := el.PeerKeypairsForTest(peerKey)
	if curFinal == nil || curFinal != k2Current {
		t.Fatalf("expected current keypair to remain K2, got %+v (want %+v)", curFinal, k2Current)
	}
	if curFinal.LocalIndex != k2LocalIdx {
		t.Fatalf("expected current LocalIndex to remain %d, got %d", k2LocalIdx, curFinal.LocalIndex)
	}
	if prevFinal != nil {
		t.Fatalf("expected prev keypair to remain nil, got %+v", prevFinal)
	}

	tk, ok := el.TransportKeysFor(peerKey)
	if !ok || tk != k2Current {
		t.Fatalf("expected noiseKeys to retain K2, got %+v (found=%v)", tk, ok)
	}
	if sid := el.PeerSessionIDForTest(peerKey); sid != s2ID {
		t.Fatalf("expected peer session ID to remain S2 (%s), got %s", s2ID, sid)
	}

	// 3. Stale K_1 keys did NOT clobber K_2: K2 is usable for data routing
	var routedPackets [][]byte
	var mu sync.Mutex
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		mu.Lock()
		defer mu.Unlock()
		routedPackets = append(routedPackets, append([]byte(nil), pkt...))
		return nil
	})

	k2Payload := []byte("payload-using-k2-after-h1-drop")
	d2 := craftClientTransportDatagram(t, k2Current, el.config.H4.Lo, el.config.S4, hpKey, 1, k2Payload)
	if _, err := clientConn2.Write(d2); err != nil {
		t.Fatalf("failed to write data packet with K2: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(routedPackets) != 1 || !bytes.Equal(routedPackets[0], k2Payload) {
		t.Fatalf("expected 1 routed packet with K2 payload, got %v", routedPackets)
	}
	mu.Unlock()
}

// TestListener_PrunePeerTransportStateForGeneration_Unit tests the three branches of
// PrunePeerTransportStateForGeneration:
// 1. currentGen > timedOutGen: newer generation committed -> do not prune, return false.
// 2. currentGen == timedOutGen: prune transport state, advance fence to at least timedOutGen + 1, return true.
// 3. currentGen < timedOutGen: prune transport state, advance fence to at least timedOutGen + 1, return true.
func TestListener_PrunePeerTransportStateForGeneration_Unit(t *testing.T) {
	db := setupTestDB(t)
	cfg := ListenerConfig{
		ListenPort: getFreeUDPPort(t),
		SubnetCIDR: "10.100.0.0/24",
		MTU:        1420,
	}
	ipam, _ := NewIPAM(cfg.SubnetCIDR)
	sm := NewSessionManager(db, ipam)
	el, err := NewListener(cfg, db, nil, ipam, sm, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	peerKey := "peer-unit-prune-gen"
	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:45678")

	// Branch 1: currentGen > timedOutGen -> newer generation committed, do NOT prune
	k2 := &TransportKeys{LocalIndex: 20202, Generation: 2, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	if !el.CommitHandshake(peerKey, 2, k2, clientAddr, 999) {
		t.Fatal("CommitHandshake gen 2 failed")
	}
	if el.PeerGeneration(peerKey) != 2 {
		t.Fatalf("expected PeerGeneration 2, got %d", el.PeerGeneration(peerKey))
	}

	// Attempt to prune with timedOutGen = 1 (stale timeout)
	if pruned := el.PrunePeerTransportStateForGeneration(peerKey, 1); pruned {
		t.Fatal("expected PrunePeerTransportStateForGeneration(gen 1) to return false when currentGen is 2")
	}
	// Assert K2 and fence survived
	if el.PeerGeneration(peerKey) != 2 {
		t.Fatalf("expected PeerGeneration to remain 2, got %d", el.PeerGeneration(peerKey))
	}
	if tk, ok := el.TransportKeysFor(peerKey); !ok || tk != k2 {
		t.Fatal("expected K2 to survive stale timeout pruning")
	}
	if _, ok := el.peerByAddr(clientAddr.String()); !ok {
		t.Fatal("expected peer address mapping to survive stale timeout pruning")
	}
	if _, found := el.lookupKeypairByIndex(k2.LocalIndex); !found {
		t.Fatal("expected indexTable entry to survive stale timeout pruning")
	}

	// Branch 2: currentGen == timedOutGen -> genuine timeout, PRUNE and advance fence to timedOutGen + 1
	if pruned := el.PrunePeerTransportStateForGeneration(peerKey, 2); !pruned {
		t.Fatal("expected PrunePeerTransportStateForGeneration(gen 2) to return true when currentGen is 2")
	}
	if el.PeerGeneration(peerKey) != 3 {
		t.Fatalf("expected PeerGeneration advanced to 3, got %d", el.PeerGeneration(peerKey))
	}
	if _, ok := el.TransportKeysFor(peerKey); ok {
		t.Fatal("expected transport keys to be pruned")
	}
	if _, ok := el.peerByAddr(clientAddr.String()); ok {
		t.Fatal("expected peer address mapping to be pruned")
	}
	if _, found := el.lookupKeypairByIndex(k2.LocalIndex); found {
		t.Fatal("expected indexTable entry to be pruned")
	}

	// Branch 3: currentGen < timedOutGen -> uninitialized or older fence, PRUNE and advance fence to timedOutGen + 1
	peerKey2 := "peer-unit-prune-gen-uninit"
	k1 := &TransportKeys{LocalIndex: 30303, Generation: 1, SendKey: make([]byte, 32), RecvKey: make([]byte, 32)}
	el.storeTransportKeys(peerKey2, k1) // stored without CommitHandshake, peerGenerations is 0
	if el.PeerGeneration(peerKey2) != 0 {
		t.Fatalf("expected PeerGeneration 0, got %d", el.PeerGeneration(peerKey2))
	}

	if pruned := el.PrunePeerTransportStateForGeneration(peerKey2, 5); !pruned {
		t.Fatal("expected PrunePeerTransportStateForGeneration(gen 5) to return true when currentGen is 0")
	}
	if el.PeerGeneration(peerKey2) != 6 {
		t.Fatalf("expected PeerGeneration advanced to 6, got %d", el.PeerGeneration(peerKey2))
	}
	if _, ok := el.TransportKeysFor(peerKey2); ok {
		t.Fatal("expected transport keys for peerKey2 to be pruned")
	}
}

// TestSweepTimedOutSessions_ConcurrentReplacementHandshake_PreservesNewGeneration reproduces
// the race condition where SweepTimedOutSessions discovers a timed-out session S1 (gen 1),
// but before pruning executes, a concurrent replacement handshake H2 commits session S2 (gen 2)
// and transport keys K2. Atomic generation-owned timeout pruning (PrunePeerTransportStateForGeneration)
// ensures that K2, its indexTable entry, peersByAddr mapping, S2 session, and send gate eligibility
// survive the sweep without being clobbered or suppressed.
func TestSweepTimedOutSessions_ConcurrentReplacementHandshake_PreservesNewGeneration(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	ctx := context.Background()
	serverAddr, ok := el.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el.GetListenAddr())
	}

	clientConn1, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP conn1: %v", err)
	}
	defer func() { _ = clientConn1.Close() }()

	clientPriv, peerKey := newTestClient(t, el.db, sID, "sweep_barrier_peer")

	// 1. Initial Handshake H1: establishes S1 (gen 1) and commits K1
	pkt1, state1, err := health.BuildAWGInitiationPacketObfuscated(sPub[:], clientPriv, nil, hpKey, el.config.H1, el.config.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated H1: %v", err)
	}
	if _, err := clientConn1.Write(pkt1); err != nil {
		t.Fatalf("write initiation H1: %v", err)
	}

	respBuf1 := make([]byte, 2048)
	_ = clientConn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n1, err := clientConn1.Read(respBuf1)
	if err != nil {
		t.Fatalf("failed to read H1 response: %v", err)
	}
	if !health.VerifyAWGResponsePacketObfuscated(respBuf1[:n1], state1, hpKey, el.config.H2, el.config.S2) {
		t.Fatal("VerifyAWGResponsePacketObfuscated rejected H1 response")
	}

	s1, ok := el.SessionManager().GetSession(peerKey)
	if !ok || s1 == nil || s1.Generation != 1 {
		t.Fatalf("expected active session S1 with generation 1, got %+v", s1)
	}
	k1Current, _ := el.PeerKeypairsForTest(peerKey)
	if k1Current == nil {
		t.Fatal("expected current transport keys K1 for peer after H1")
	}
	if el.PeerGeneration(peerKey) != 1 {
		t.Fatalf("expected committed peer generation 1, got %d", el.PeerGeneration(peerKey))
	}

	// 2. Mark S1 as timed out in the session manager
	el.SessionManager().SetSessionLastSeen(peerKey, time.Now().UTC().Add(-10*time.Minute))

	// 3. Configure test barrier hook: pauses sweep after discovering S1 (gen 1)
	// before PrunePeerTransportStateForGeneration runs.
	barrierHit := make(chan struct{})
	resumeSweep := make(chan struct{})

	el.SetPreSweepPruneHookForTest(func(pKey string, timedOutGen uint64) {
		if pKey == peerKey && timedOutGen == 1 {
			close(barrierHit)
			<-resumeSweep
		}
	})

	// 4. Trigger SweepTimedOutSessions in a background goroutine
	sweepDone := make(chan error, 1)
	go func() {
		_, sweepErr := el.SweepTimedOutSessions(ctx)
		sweepDone <- sweepErr
	}()

	// Wait for sweep to discover S1 and pause at the barrier
	select {
	case <-barrierHit:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for sweep to pause at preSweepPruneHook barrier")
	}

	// 5. While sweep is paused at the barrier, replacement handshake H2 arrives from clientConn2
	clientConn2, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP conn2: %v", err)
	}
	defer func() { _ = clientConn2.Close() }()

	pkt2, state2, err := health.BuildAWGInitiationPacketObfuscated(sPub[:], clientPriv, nil, hpKey, el.config.H1, el.config.S1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated H2: %v", err)
	}
	if _, err := clientConn2.Write(pkt2); err != nil {
		t.Fatalf("write initiation H2: %v", err)
	}

	respBuf2 := make([]byte, 2048)
	_ = clientConn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n2, err := clientConn2.Read(respBuf2)
	if err != nil {
		t.Fatalf("failed to read H2 response: %v", err)
	}
	if !health.VerifyAWGResponsePacketObfuscated(respBuf2[:n2], state2, hpKey, el.config.H2, el.config.S2) {
		t.Fatal("VerifyAWGResponsePacketObfuscated rejected H2 response")
	}

	// Verify H2 created S2 (gen 2) and CommitHandshake committed K2
	k2Current, _ := el.PeerKeypairsForTest(peerKey)
	if k2Current == nil || k2Current.LocalIndex == k1Current.LocalIndex {
		t.Fatalf("expected K2 committed for peer, got %+v", k2Current)
	}
	k2LocalIdx := k2Current.LocalIndex

	s2, ok := el.SessionManager().GetSession(peerKey)
	if !ok || s2 == nil || s2.Generation != 2 {
		t.Fatalf("expected active session S2 with generation 2, got %+v", s2)
	}
	if el.PeerGeneration(peerKey) != 2 {
		t.Fatalf("expected committed peer generation 2, got %d", el.PeerGeneration(peerKey))
	}

	// 6. Resume sweep: PrunePeerTransportStateForGeneration(peerKey, 1) runs.
	// Since currentGen (2) > timedOutGen (1), pruning must abort and return false!
	close(resumeSweep)

	select {
	case err := <-sweepDone:
		if err != nil {
			t.Fatalf("SweepTimedOutSessions failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SweepTimedOutSessions to complete after resume")
	}

	// 7. Assertions:
	// a. K2 survives:
	curFinal, prevFinal := el.PeerKeypairsForTest(peerKey)
	if curFinal == nil || curFinal.LocalIndex != k2LocalIdx {
		t.Fatalf("expected K2 (index %d) to survive sweep, got %+v", k2LocalIdx, curFinal)
	}
	if prevFinal != nil && prevFinal.LocalIndex != k1Current.LocalIndex {
		t.Fatalf("expected prevKeypair to be K1 (%d), got %+v", k1Current.LocalIndex, prevFinal)
	}
	tk, ok := el.TransportKeysFor(peerKey)
	if !ok || tk == nil || tk.LocalIndex != k2LocalIdx {
		t.Fatalf("expected TransportKeysFor to retain K2, got %+v (ok=%v)", tk, ok)
	}

	// b. indexTable entry survives:
	entry, found := el.lookupKeypairByIndex(k2LocalIdx)
	if !found || entry == nil || entry.keys == nil || entry.keys.LocalIndex != k2LocalIdx {
		t.Fatalf("expected indexTable entry for K2 (%d) to survive, found=%v entry=%+v", k2LocalIdx, found, entry)
	}

	// c. peersByAddr survives:
	client2Addr := clientConn2.LocalAddr().String()
	st, ok := el.peerByAddr(client2Addr)
	if !ok || st == nil || st.peerKey != peerKey {
		t.Fatalf("expected peersByAddr entry for %s to survive, got %+v (ok=%v)", client2Addr, st, ok)
	}

	// d. S2 session survives:
	activeSess, ok := el.SessionManager().GetSession(peerKey)
	if !ok || activeSess == nil || activeSess.ID != s2.ID || activeSess.Generation != 2 {
		t.Fatalf("expected active session S2 (gen 2) to survive, got %+v", activeSess)
	}
	if sid := el.PeerSessionIDForTest(peerKey); sid != s2.ID {
		t.Fatalf("expected PeerSessionID to remain S2 (%s), got %s", s2.ID, sid)
	}

	// e. Send gate eligibility survives:
	// PeerGeneration must remain 2 (not bumped to 3), so response send gate is NOT suppressed.
	currentFence := el.PeerGeneration(peerKey)
	if currentFence != 2 {
		t.Fatalf("expected generation fence to remain 2, got %d (fence must not be bumped by stale sweep)", currentFence)
	}
	if drops := el.StaleResponseDrops(); drops != 0 {
		t.Fatalf("expected 0 stale response drops, got %d", drops)
	}

	// f. Data plane routing with K2 succeeds without loss
	var routedPackets [][]byte
	var routerMu sync.Mutex
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		routerMu.Lock()
		defer routerMu.Unlock()
		routedPackets = append(routedPackets, append([]byte(nil), pkt...))
		return nil
	})

	k2Payload := []byte("payload-using-k2-after-sweep-atomic-prune")
	d2 := craftClientTransportDatagram(t, curFinal, el.config.H4.Lo, el.config.S4, hpKey, 1, k2Payload)
	if _, err := clientConn2.Write(d2); err != nil {
		t.Fatalf("failed to write transport datagram with K2: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	routerMu.Lock()
	if len(routedPackets) != 1 || !bytes.Equal(routedPackets[0], k2Payload) {
		t.Fatalf("expected 1 routed packet with K2 payload, got %v", routedPackets)
	}
	routerMu.Unlock()
}

// TestRekeyRollover_EndpointRoaming_PreservesSendCounterNonceUniqueness verifies that
// UDP endpoint roaming (e.g. NAT remapping or client changing IP/port) preserves the
// monotonicity and uniqueness of outbound AEAD send counter nonces under the active
// TransportKeys generation. Because sendCounter is bound to TransportKeys rather than
// per-address activePeerState, discovering a new source endpoint does not reset the
// outbound nonce counter to 0, preventing catastrophic nonce reuse under ChaCha20-Poly1305.
func TestRekeyRollover_EndpointRoaming_PreservesSendCounterNonceUniqueness(t *testing.T) {
	el, sPub, hpKey, sID := setupIssue295LiveTestListener(t)
	defer func() { _ = el.Stop() }()

	serverAddr, ok := el.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el.GetListenAddr())
	}

	var routedPackets [][]byte
	var routerMu sync.Mutex
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		routerMu.Lock()
		defer routerMu.Unlock()
		routedPackets = append(routedPackets, append([]byte(nil), pkt...))
		return nil
	})

	// 1. Establish initial session and keypair K1 with client at socket/address A
	clientConnA, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP connA: %v", err)
	}
	defer func() { _ = clientConnA.Close() }()

	clientPriv, peerKey := newTestClient(t, el.db, sID, "roam_peer_nonce_test")
	_ = performClientHandshake(t, el, clientConnA, sPub, clientPriv, hpKey, el.config.H1, el.config.S1, el.config.H2, el.config.S2)

	k1Current, _ := el.PeerKeypairsForTest(peerKey)
	if k1Current == nil || k1Current.SendKey == nil {
		t.Fatalf("expected active TransportKeys K1 for peer %s", peerKey)
	}

	clientAEAD, err := chacha20poly1305.New(k1Current.SendKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}

	readOutboundPacket := func(conn *net.UDPConn, wantCounter uint64, wantPayload []byte) {
		t.Helper()
		buf := make([]byte, 2048)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("failed to read outbound packet: %v", err)
		}
		datagram := buf[:n]
		s4 := el.config.S4
		if len(datagram) < s4+transportDataHeaderLen+len(wantPayload)+chacha20poly1305.Overhead {
			t.Fatalf("outbound datagram too short: %d", len(datagram))
		}

		recvCip := health.NewHeaderProtectionCipher(hpKey, datagram[:health.HeaderCipherNonceSize])
		if recvCip == nil {
			t.Fatal("failed to create client HP cipher")
		}
		unmaskedHdr := make([]byte, transportDataHeaderLen)
		recvCip.XORKeyStream(unmaskedHdr, datagram[s4:s4+transportDataHeaderLen])

		gotCounter := binary.LittleEndian.Uint64(unmaskedHdr[8:16])
		if gotCounter != wantCounter {
			t.Fatalf("outbound counter mismatch: got %d, want %d", gotCounter, wantCounter)
		}

		var nonce [chacha20poly1305.NonceSize]byte
		binary.LittleEndian.PutUint64(nonce[4:12], gotCounter)
		decrypted, err := clientAEAD.Open(nil, nonce[:], datagram[s4+transportDataHeaderLen:], nil)
		if err != nil {
			t.Fatalf("client failed to decrypt outbound packet with K1: %v", err)
		}
		if !bytes.Equal(decrypted, wantPayload) {
			t.Fatalf("payload mismatch: got %q, want %q", decrypted, wantPayload)
		}
	}

	// 2. Call el.SendToPeer() -> verify received at socket A, assert outbound counter is 0, verify client decrypts with K1.
	outMsg0 := []byte("server-outbound-packet-0")
	if err := el.SendToPeer(peerKey, outMsg0); err != nil {
		t.Fatalf("SendToPeer #0 failed: %v", err)
	}
	readOutboundPacket(clientConnA, 0, outMsg0)

	// 3. Call el.SendToPeer() again -> verify received at socket A, assert outbound counter is 1, verify client decrypts with K1.
	outMsg1 := []byte("server-outbound-packet-1")
	if err := el.SendToPeer(peerKey, outMsg1); err != nil {
		t.Fatalf("SendToPeer #1 failed: %v", err)
	}
	readOutboundPacket(clientConnA, 1, outMsg1)

	// 4. Create new client socket B (simulating client NAT rebinding / roaming).
	clientConnB, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP connB: %v", err)
	}
	defer func() { _ = clientConnB.Close() }()

	// Send valid inbound K1 transport packet from socket B (same LocalIndex / same K1).
	inboundMsgB := []byte("client-roamed-to-socket-b")
	dB := craftClientTransportDatagram(t, k1Current, el.config.H4.Lo, el.config.S4, hpKey, 1, inboundMsgB)
	if _, err := clientConnB.Write(dB); err != nil {
		t.Fatalf("write inbound transport from socket B failed: %v", err)
	}

	// Wait for listener to process inbound datagram and update peer endpoint
	waitForRoutedPacket := func(want []byte) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			routerMu.Lock()
			for _, p := range routedPackets {
				if bytes.Equal(p, want) {
					routerMu.Unlock()
					return
				}
			}
			routerMu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for routed packet %q", want)
	}
	waitForRoutedPacket(inboundMsgB)

	// Verify B becomes the newest recorded endpoint in Listener.
	stB, okB := el.peerByAddr(clientConnB.LocalAddr().String())
	if !okB || stB == nil || stB.peerKey != peerKey {
		t.Fatalf("expected peersByAddr entry for socket B (%s), got %+v", clientConnB.LocalAddr().String(), stB)
	}
	stA, okA := el.peerByAddr(clientConnA.LocalAddr().String())
	if !okA || stA == nil {
		t.Fatalf("expected peersByAddr entry for socket A (%s)", clientConnA.LocalAddr().String())
	}
	if stB.lastSeen.Load() <= stA.lastSeen.Load() {
		t.Fatalf("expected socket B lastSeen (%d) > socket A lastSeen (%d)", stB.lastSeen.Load(), stA.lastSeen.Load())
	}

	// 5. Call el.SendToPeer() -> verify packet is received at socket B, assert outbound counter is 2 (NOT 0!), verify client decrypts with K1.
	outMsg2 := []byte("server-outbound-packet-2")
	if err := el.SendToPeer(peerKey, outMsg2); err != nil {
		t.Fatalf("SendToPeer #2 failed: %v", err)
	}
	readOutboundPacket(clientConnB, 2, outMsg2)

	// 6. Send valid inbound K1 packet from socket A again (roaming back to A).
	// Advance client counter to 2 so anti-replay filter accepts it.
	inboundMsgA2 := []byte("client-roamed-back-to-socket-a")
	dA2 := craftClientTransportDatagram(t, k1Current, el.config.H4.Lo, el.config.S4, hpKey, 2, inboundMsgA2)
	if _, err := clientConnA.Write(dA2); err != nil {
		t.Fatalf("write inbound transport from socket A failed: %v", err)
	}
	waitForRoutedPacket(inboundMsgA2)

	// Verify A is now the newest recorded endpoint in Listener.
	if stA.lastSeen.Load() <= stB.lastSeen.Load() {
		t.Fatalf("expected socket A lastSeen (%d) > socket B lastSeen (%d) after roaming back", stA.lastSeen.Load(), stB.lastSeen.Load())
	}

	// 7. Call el.SendToPeer() -> verify packet is received at socket A, assert outbound counter is 3 (NOT 0, NOT 2!), verify client decrypts with K1.
	outMsg3 := []byte("server-outbound-packet-3")
	if err := el.SendToPeer(peerKey, outMsg3); err != nil {
		t.Fatalf("SendToPeer #3 failed: %v", err)
	}
	readOutboundPacket(clientConnA, 3, outMsg3)
}
