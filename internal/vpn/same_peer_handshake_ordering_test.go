package vpn

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	"golang.org/x/crypto/chacha20poly1305"
)

func confirmSamePeerHandshake(
	t *testing.T,
	svc *Service,
	clientConn *net.UDPConn,
	clientPub string,
	hpKey []byte,
	h4 models.HeaderRange,
	s4 int,
) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	var nextLocalIndex uint32
	var nextRecvKey []byte
	for time.Now().Before(deadline) {
		_, _, next := svc.endpoint.PeerKeypairStateForTest(clientPub)
		if next != nil {
			nextLocalIndex = next.LocalIndex
			nextRecvKey = append([]byte(nil), next.RecvKey...)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if nextLocalIndex == 0 || len(nextRecvKey) == 0 {
		t.Fatalf("timed out waiting for staged responder next for %s", clientPub)
	}

	aead, err := chacha20poly1305.New(nextRecvKey)
	if err != nil {
		t.Fatalf("build confirmation AEAD: %v", err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	const counter = uint64(0)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	ciphertext := aead.Seal(nil, nonce[:], nil, nil)

	if s4 < 0 {
		s4 = 0
	}
	s4Junk := make([]byte, s4)
	if _, err := rand.Read(s4Junk); err != nil {
		t.Fatalf("rand.Read confirmation S4: %v", err)
	}

	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], h4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], nextLocalIndex)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)
	if len(hpKey) == 32 && s4 >= health.HeaderCipherNonceSize {
		cip := health.NewHeaderProtectionCipher(hpKey, s4Junk[:health.HeaderCipherNonceSize])
		if cip == nil {
			t.Fatal("failed to create confirmation header-protection cipher")
		}
		cip.XORKeyStream(hdr[:], hdr[:])
	}

	datagram := append(s4Junk, hdr[:]...)
	datagram = append(datagram, ciphertext...)
	if _, err := clientConn.Write(datagram); err != nil {
		t.Fatalf("write confirmation keepalive: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, current, next := svc.endpoint.PeerKeypairStateForTest(clientPub)
		if current != nil && current.LocalIndex == nextLocalIndex && next == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for responder next->current promotion for %s", clientPub)
}

// TestSamePeerHandshakeRetirementOrderingRegression reproduces the same-peer
// handshake completion ordering race:
//   - G0 has an admitted write blocked on a release channel.
//   - Handshake H1 arrives, reserves generation G1, and pauses before commit.
//   - Handshake H2 reserves G2 and commits while the old route has an admitted write.
//   - Release G0 write and H1; H1's stale generation must be rejected.
//   - Assert:
//   - Active logical session and forwarder route remain G0.
//   - H1 did not overwrite H2 transport keys.
//   - H1 did not overwrite H2 endpoint.
//   - Control-plane and listener transport generation agree on G2.
func TestSamePeerHandshakeRetirementOrderingRegression(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)

	clientPub, clientPriv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("generate client keypair: %v", err)
	}
	clientPrivBytes, err := base64.StdEncoding.DecodeString(clientPriv)
	if err != nil {
		t.Fatalf("decode client privkey: %v", err)
	}

	if _, err := db.CreateConnection(t.Context(), &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: clientPub,
		Name:     "client-device",
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}

	if err := svc.Start(t.Context()); err != nil {
		t.Fatalf("start vpn service: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	serverAddr, ok := svc.endpoint.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", svc.endpoint.GetListenAddr())
	}
	cfg, err := svc.GetConfig(t.Context())
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	serverPubBytes, err := base64.StdEncoding.DecodeString(cfg.ServerPublicKey)
	if err != nil {
		t.Fatalf("decode server pubkey: %v", err)
	}
	hpKeyBytes, err := health.DecodeKey(cfg.HeaderProtectionKey)
	if err != nil {
		t.Fatalf("decode hpKey: %v", err)
	}

	// 1. Initial handshake G0 completes over UDP
	clientConn0, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("dial udp 0: %v", err)
	}
	defer clientConn0.Close()

	pkt0, state0, err := health.BuildAWGInitiationPacketObfuscated(serverPubBytes, clientPrivBytes, nil, hpKeyBytes, cfg.H1, cfg.S1)
	if err != nil {
		t.Fatalf("build initiation 0: %v", err)
	}
	if _, err := clientConn0.Write(pkt0); err != nil {
		t.Fatalf("write initiation 0: %v", err)
	}
	respBuf := make([]byte, 2048)
	_ = clientConn0.SetReadDeadline(time.Now().Add(3 * time.Second))
	n0, err := clientConn0.Read(respBuf)
	if err != nil {
		t.Fatalf("read response 0: %v", err)
	}
	if !health.VerifyAWGResponsePacketObfuscated(respBuf[:n0], state0, hpKeyBytes, cfg.H2, cfg.S2) {
		t.Fatal("response 0 failed verification")
	}
	confirmSamePeerHandshake(t, svc, clientConn0, clientPub, hpKeyBytes, cfg.H4, cfg.S4)

	sess0, ok := svc.sessionMgr.GetSession(clientPub)
	if !ok {
		t.Fatal("session G0 not found in SessionManager")
	}
	initialGeneration := sess0.Generation
	initialRouteRegistration := svc.forwarder.PeerRegistration(clientPub)
	h1Paused := make(chan struct{})
	h1Resume := make(chan struct{})
	var h1Fired atomic.Bool
	var releaseH1 sync.Once
	defer releaseH1.Do(func() { close(h1Resume) })
	svc.SetPreTransportCommitHookForTest(func(peer, _ string) {
		if peer == clientPub && h1Fired.CompareAndSwap(false, true) {
			close(h1Paused)
			<-h1Resume
		}
	})

	// 2. G0 has an admitted write blocked on a release channel
	dev := &statusBlockedDevice{started: make(chan struct{}, 1), release: make(chan struct{})}
	svc.forwarder.AttachPeerDevice(clientPub, dev)
	defer func() {
		select {
		case <-dev.release:
		default:
			close(dev.release)
		}
	}()

	if err := svc.forwarder.RouteBackendToClient(sess0.BackendTunnelID, []byte("g0-payload"), sess0.AssignedIP); err != nil {
		t.Fatalf("RouteBackendToClient G0: %v", err)
	}
	select {
	case <-dev.started:
	case <-time.After(2 * time.Second):
		t.Fatal("G0 write did not start")
	}

	// 3. H1 reserves G1 without replacing the live route, then pauses before commit.
	clientConn1, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("dial udp 1: %v", err)
	}
	defer clientConn1.Close()

	pkt1, _, err := health.BuildAWGInitiationPacketObfuscated(serverPubBytes, clientPrivBytes, nil, hpKeyBytes, cfg.H1, cfg.S1)
	if err != nil {
		t.Fatalf("build initiation 1: %v", err)
	}
	if _, err := clientConn1.Write(pkt1); err != nil {
		t.Fatalf("write initiation 1: %v", err)
	}

	select {
	case <-h1Paused:
	case <-time.After(3 * time.Second):
		t.Fatal("H1 did not reach the pre-commit hook")
	}
	h1Generation := svc.PeerGeneration(clientPub)
	if h1Generation <= initialGeneration || svc.forwarder.RouteSessionID(clientPub) != sess0.ID {
		t.Fatal("H1 did not reserve a generation on the same live route")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if svc.mu.TryLock() {
			svc.mu.Unlock()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("H1 retained Service.mu while waiting in pre-commit hook")
		}
		time.Sleep(time.Millisecond)
	}

	// 4. H2 advances G2 on the same session and completes its handshake.
	clientConn2, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("dial udp 2: %v", err)
	}
	defer clientConn2.Close()

	pkt2, state2, err := health.BuildAWGInitiationPacketObfuscated(serverPubBytes, clientPrivBytes, nil, hpKeyBytes, cfg.H1, cfg.S1)
	if err != nil {
		t.Fatalf("build initiation 2: %v", err)
	}
	if _, err := clientConn2.Write(pkt2); err != nil {
		t.Fatalf("write initiation 2: %v", err)
	}

	_ = clientConn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n2, err := clientConn2.Read(respBuf)
	if err != nil {
		t.Fatalf("read response H2: %v", err)
	}
	if !health.VerifyAWGResponsePacketObfuscated(respBuf[:n2], state2, hpKeyBytes, cfg.H2, cfg.S2) {
		t.Fatal("response H2 failed verification")
	}
	confirmSamePeerHandshake(t, svc, clientConn2, clientPub, hpKeyBytes, cfg.H4, cfg.S4)

	sess2, ok := svc.sessionMgr.GetSession(clientPub)
	if !ok {
		t.Fatal("session G2 not found in SessionManager")
	}
	if sess2.ID != sess0.ID || sess2.Generation <= h1Generation {
		t.Fatalf("H2 replaced the live session or did not advance generation: %+v", sess2)
	}
	h2Keys, ok := svc.endpoint.TransportKeysFor(clientPub)
	if !ok || h2Keys == nil {
		t.Fatal("H2 transport keys missing from Listener")
	}
	h2Endpoint := svc.endpoint.PeerEndpoint(clientPub)
	if h2Endpoint == nil || h2Endpoint.String() != clientConn2.LocalAddr().String() {
		t.Fatalf("H2 endpoint mismatch: got %v, want %v", h2Endpoint, clientConn2.LocalAddr())
	}

	// 5. Release G0 write and H1's paused commit.
	close(dev.release)
	releaseH1.Do(func() { close(h1Resume) })

	// 6. H1's old generation is rejected by the commit fence.
	deadline = time.Now().Add(3 * time.Second)
	for svc.endpoint.StaleHandshakeDrops() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("H1 stale handshake completion was not dropped by commit fence")
		}
		time.Sleep(time.Millisecond)
	}

	// Verify H1 did not send a response to clientConn1 (stale response discarded)
	_ = clientConn1.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := clientConn1.Read(respBuf); err == nil {
		t.Fatal("unexpected response received on H1 connection; stale response should not be sent")
	}

	// 7. Assertions:
	// - Active session remains G2
	activeSess, ok := svc.sessionMgr.GetSession(clientPub)
	if !ok {
		t.Fatal("active session not found in SessionManager")
	}
	if activeSess.ID != sess2.ID {
		t.Fatalf("active session ID mismatch: got %s, want %s (G2)", activeSess.ID, sess2.ID)
	}
	if activeSess.Generation != sess2.Generation {
		t.Fatalf("active session generation mismatch: got %d, want %d", activeSess.Generation, sess2.Generation)
	}

	// - Active forwarder route remains G2
	if routeSessID := svc.forwarder.RouteSessionID(clientPub); routeSessID != sess2.ID {
		t.Fatalf("forwarder route session ID mismatch: got %s, want %s (G2)", routeSessID, sess2.ID)
	}

	// - H1 did not overwrite H2 transport keys
	currentKeys, ok := svc.endpoint.TransportKeysFor(clientPub)
	if !ok || currentKeys == nil {
		t.Fatal("current transport keys missing from Listener")
	}
	if !bytes.Equal(currentKeys.SendKey, h2Keys.SendKey) || !bytes.Equal(currentKeys.RecvKey, h2Keys.RecvKey) {
		t.Fatal("H2 transport keys were overwritten by stale H1 handshake")
	}

	// - H1 did not overwrite H2 endpoint
	currentEndpoint := svc.endpoint.PeerEndpoint(clientPub)
	if currentEndpoint == nil || currentEndpoint.String() != clientConn2.LocalAddr().String() {
		t.Fatalf("H2 endpoint overwritten: got %v, want %v", currentEndpoint, clientConn2.LocalAddr())
	}

	// - Control-plane, forwarder, and listener transport generation all agree on G2
	expectedGen := sess2.Generation
	if svcGen := svc.PeerGeneration(clientPub); svcGen != expectedGen {
		t.Fatalf("control-plane Service generation mismatch: got %d, want %d", svcGen, expectedGen)
	}
	if sessGen := activeSess.Generation; sessGen != expectedGen {
		t.Fatalf("control-plane SessionManager generation mismatch: got %d, want %d", sessGen, expectedGen)
	}
	if fwdGen := svc.forwarder.PeerRegistration(clientPub); fwdGen != initialRouteRegistration {
		t.Fatalf("pure rekey changed route registration: got %d, want %d", fwdGen, initialRouteRegistration)
	}
	if epGen := svc.endpoint.PeerGeneration(clientPub); epGen != expectedGen {
		t.Fatalf("listener transport generation mismatch: got %d, want %d", epGen, expectedGen)
	}
}

// TestSamePeerHandshakeResponseSendRaceRegression reproduces the post-commit response
// send race condition:
//   - H1 commits gen 1, triggers postCommitHook, and pauses before response transmission.
//   - H2 for the same peer commits gen 2 and transmits response gen 2. Client receives response gen 2.
//   - H1 resumes.
//   - Assert:
//   - H1 detects it is stale at the send gate and does NOT transmit response gen 1.
//   - el.StaleResponseDrops() == 1.
//   - Client connection for H1 times out with no packet read.
//   - Transport keys and endpoint remain gen 2.
func TestSamePeerHandshakeResponseSendRaceRegression(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)

	clientPub, clientPriv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("generate client keypair: %v", err)
	}
	clientPrivBytes, err := base64.StdEncoding.DecodeString(clientPriv)
	if err != nil {
		t.Fatalf("decode client privkey: %v", err)
	}

	if _, err := db.CreateConnection(t.Context(), &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: clientPub,
		Name:     "client-device",
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}

	h1Committed := make(chan struct{})
	resumeH1 := make(chan struct{})
	defer func() {
		select {
		case <-resumeH1:
		default:
			close(resumeH1)
		}
	}()

	svc.endpoint.SetPostCommitHookForTest(func(peerKey string, gen uint64) {
		if peerKey == clientPub && gen == 1 {
			select {
			case <-h1Committed:
			default:
				close(h1Committed)
			}
			<-resumeH1
		}
	})

	if err := svc.Start(t.Context()); err != nil {
		t.Fatalf("start vpn service: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	serverAddr, ok := svc.endpoint.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", svc.endpoint.GetListenAddr())
	}
	cfg, err := svc.GetConfig(t.Context())
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	serverPubBytes, err := base64.StdEncoding.DecodeString(cfg.ServerPublicKey)
	if err != nil {
		t.Fatalf("decode server pubkey: %v", err)
	}
	hpKeyBytes, err := health.DecodeKey(cfg.HeaderProtectionKey)
	if err != nil {
		t.Fatalf("decode hpKey: %v", err)
	}

	// 1. Handshake H1 arrives from clientConn1, commits gen 1, and pauses in postCommitHook
	clientConn1, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("dial udp 1: %v", err)
	}
	defer clientConn1.Close()

	pkt1, _, err := health.BuildAWGInitiationPacketObfuscated(serverPubBytes, clientPrivBytes, nil, hpKeyBytes, cfg.H1, cfg.S1)
	if err != nil {
		t.Fatalf("build initiation 1: %v", err)
	}
	if _, err := clientConn1.Write(pkt1); err != nil {
		t.Fatalf("write initiation 1: %v", err)
	}

	// Wait deterministically for H1 to commit gen 1 and pause in postCommitHook
	select {
	case <-h1Committed:
	case <-time.After(3 * time.Second):
		t.Fatal("H1 did not reach postCommitHook")
	}

	// 2. Handshake H2 arrives from clientConn2 for the same peer, commits gen 2, and sends response
	clientConn2, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("dial udp 2: %v", err)
	}
	defer clientConn2.Close()

	pkt2, state2, err := health.BuildAWGInitiationPacketObfuscated(serverPubBytes, clientPrivBytes, nil, hpKeyBytes, cfg.H1, cfg.S1)
	if err != nil {
		t.Fatalf("build initiation 2: %v", err)
	}
	if _, err := clientConn2.Write(pkt2); err != nil {
		t.Fatalf("write initiation 2: %v", err)
	}

	respBuf := make([]byte, 2048)
	_ = clientConn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n2, err := clientConn2.Read(respBuf)
	if err != nil {
		t.Fatalf("read response H2: %v", err)
	}
	if !health.VerifyAWGResponsePacketObfuscated(respBuf[:n2], state2, hpKeyBytes, cfg.H2, cfg.S2) {
		t.Fatal("response H2 failed verification")
	}
	confirmSamePeerHandshake(t, svc, clientConn2, clientPub, hpKeyBytes, cfg.H4, cfg.S4)

	sess2, ok := svc.sessionMgr.GetSession(clientPub)
	if !ok {
		t.Fatal("session G2 not found in SessionManager")
	}
	h2Keys, ok := svc.endpoint.TransportKeysFor(clientPub)
	if !ok || h2Keys == nil {
		t.Fatal("H2 transport keys missing from Listener")
	}
	h2Endpoint := svc.endpoint.PeerEndpoint(clientPub)
	if h2Endpoint == nil || h2Endpoint.String() != clientConn2.LocalAddr().String() {
		t.Fatalf("H2 endpoint mismatch: got %v, want %v", h2Endpoint, clientConn2.LocalAddr())
	}

	// 3. Resume H1
	close(resumeH1)

	// Wait deterministically for H1 to reach the per-peer send gate and be suppressed
	deadline := time.Now().Add(3 * time.Second)
	for svc.endpoint.StaleResponseDrops() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("H1 stale response was not dropped at the send gate")
		}
		time.Sleep(time.Millisecond)
	}

	// 4. Assertions:
	// - H1 detects it is stale at the send gate and does NOT transmit response gen 1
	_ = clientConn1.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := clientConn1.Read(respBuf); err == nil {
		t.Fatal("unexpected response received on H1 connection; stale response should have been suppressed")
	}

	// - el.StaleResponseDrops() == 1
	if drops := svc.endpoint.StaleResponseDrops(); drops != 1 {
		t.Fatalf("StaleResponseDrops = %d, want 1", drops)
	}

	// - Transport keys and endpoint remain gen 2
	currentKeys, ok := svc.endpoint.TransportKeysFor(clientPub)
	if !ok || currentKeys == nil {
		t.Fatal("current transport keys missing")
	}
	if !bytes.Equal(currentKeys.SendKey, h2Keys.SendKey) || !bytes.Equal(currentKeys.RecvKey, h2Keys.RecvKey) {
		t.Fatal("H2 transport keys were corrupted")
	}
	currentEndpoint := svc.endpoint.PeerEndpoint(clientPub)
	if currentEndpoint == nil || currentEndpoint.String() != clientConn2.LocalAddr().String() {
		t.Fatalf("H2 endpoint corrupted: got %v, want %v", currentEndpoint, clientConn2.LocalAddr())
	}

	// - Active session remains gen 2
	activeSess, ok := svc.sessionMgr.GetSession(clientPub)
	if !ok || activeSess.ID != sess2.ID || activeSess.Generation != 2 {
		t.Fatalf("active session corrupted: got %+v, want gen 2 sess2", activeSess)
	}
}
