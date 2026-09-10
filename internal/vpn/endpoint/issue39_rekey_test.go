package endpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"golang.org/x/crypto/curve25519"
)

// Issue #39 defect 2: legit client rekey initiations (HP-masked, H1 within
// the configured RANGE) were rejected with "message type is not an AWG
// handshake initiation". AWG clients rekey every RekeyAfterTime (111-130 s);
// a rejected rekey leaves the session on the old key until RejectAfterTime
// and then kills the tunnel. The classification must accept every H1 value
// the configured range can emit, not just one fixed value.

// rekeyTestHeaders returns #37-style header ranges and junk sizes as used by
// the DEV portal config (true ranges, per-packet randomized H1/H2/H4).
func rekeyTestHeaders() (h1, h2 models.HeaderRange, s1, s2 int) {
	return models.NewHeaderRange(100, 140), models.NewHeaderRange(200, 240), 15, 18
}

// newRekeyTestListener builds a listener wired exactly like production
// (ranges + HP key + ephemeral-no-DB server keys) without starting it.
func newRekeyTestListener(t *testing.T) (*Listener, [32]byte, []byte) {
	t.Helper()
	hpKey := make([]byte, 32)
	if _, err := rand.Read(hpKey); err != nil {
		t.Fatalf("rand.Read(hpKey) failed: %v", err)
	}
	h1, _, s1, s2 := rekeyTestHeaders()
	cfg := ListenerConfig{
		ListenPort:          getFreeUDPPort(t),
		SubnetCIDR:          "10.100.0.0/24",
		MTU:                 1420,
		IdleTimeout:         1 * time.Minute,
		HeaderProtectionKey: base64.StdEncoding.EncodeToString(hpKey),
		H1:                  h1,
		S1:                  s1,
		H2:                  models.NewHeaderRange(200, 240),
		S2:                  s2,
	}
	keysMgr := NewServerKeysManager(nil)
	el, err := NewListener(cfg, nil, nil, nil, nil, keysMgr)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}
	_, sPub, err := keysMgr.EnsureKeypair(context.Background())
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}
	return el, sPub, hpKey
}

// TestParseInitiationAcceptsMaskedRekeyInRange feeds a valid AWG 3.1
// HP-masked rekey initiation whose H1 lies inside the configured range to
// the parse path. It must be classified as a handshake initiation (this is
// the exact packet a real client sends on every rekey with range headers).
func TestParseInitiationAcceptsMaskedRekeyInRange(t *testing.T) {
	h1, _, s1, _ := rekeyTestHeaders()

	serverPriv := make([]byte, 32)
	if _, err := rand.Read(serverPriv); err != nil {
		t.Fatalf("rand.Read(serverPriv) failed: %v", err)
	}
	sPub, err := curve25519.X25519(serverPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive server pub: %v", err)
	}
	hpKey := make([]byte, 32)
	if _, err := rand.Read(hpKey); err != nil {
		t.Fatalf("rand.Read(hpKey) failed: %v", err)
	}

	packet, _, err := health.BuildAWGInitiationPacketObfuscated(sPub, nil, nil, hpKey, h1, s1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacketObfuscated failed: %v", err)
	}

	info, err := ParseInitiation(serverPriv, packet, h1, s1, hpKey)
	if err != nil {
		t.Fatalf("ParseInitiation rejected a valid masked rekey initiation: %v", err)
	}
	if !info.HeaderProtected {
		t.Error("parsed initiation not marked HeaderProtected")
	}
	if len(info.ClientStaticPub) != 32 {
		t.Fatalf("client static pub length = %d, want 32", len(info.ClientStaticPub))
	}
}

// TestListenerAcceptsRekeyHandshakeOverUDP runs the full live-UDP flow:
// initial handshake, then a client REKEY (fresh ephemeral, fresh randomized
// H1 from the range, same socket). The rekey initiation must be answered
// with a response the client verifier accepts against the NEW state, and
// the stored transport keys must be refreshed.
func TestListenerAcceptsRekeyHandshakeOverUDP(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	hpKey := make([]byte, 32)
	if _, err := rand.Read(hpKey); err != nil {
		t.Fatalf("rand.Read(hpKey) failed: %v", err)
	}
	h1, h2, s1, s2 := rekeyTestHeaders()

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
	}
	keysMgr := NewServerKeysManager(nil)
	el, err := NewListener(cfg, db, nil, nil, nil, keysMgr)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}
	el.SetIncomingPeerHandler(func(ctx context.Context, peerPublicKey string) (*models.VPNSession, *models.BackendTunnel, error) {
		auth := NewDBAuthenticator(db)
		user, _, err := auth.AuthenticatePeer(ctx, peerPublicKey)
		if err != nil {
			return nil, nil, err
		}
		assignedIP, _ := el.IPAM().Allocate(peerPublicKey)
		sess, _ := el.SessionManager().CreateSession(ctx, user.ID, peerPublicKey, assignedIP.String(), 1)
		return sess, &models.BackendTunnel{ID: 1}, nil
	})
	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	_, sPub, err := keysMgr.EnsureKeypair(ctx)
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}

	clientPub64 := func(state *health.NoiseClientState) string {
		pub, err := curve25519.X25519(state.ClientPriv, curve25519.Basepoint)
		if err != nil {
			t.Fatalf("derive client pub: %v", err)
		}
		return base64.StdEncoding.EncodeToString(pub)
	}

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "rekey-host", Host: "10.0.0.1"})
	_, _ = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sID, InterfaceName: "awg-be-1", PublicKey: "pubkey", PrivateKey: "privkey", Endpoint: "10.0.0.1:51820",
	})

	serverAddr, ok := el.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el.GetListenAddr())
	}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// --- Initial handshake ---
	pkt1, state1, err := health.BuildAWGInitiationPacketObfuscated(sPub[:], nil, nil, hpKey, h1, s1)
	if err != nil {
		t.Fatalf("build initiation 1: %v", err)
	}
	peerKey := clientPub64(state1)
	uID, _ := db.CreateUser(ctx, &models.User{Username: "rekey_user", Enabled: true})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{UserID: uID, ServerID: sID, Protocol: "awg", ClientID: peerKey})

	if _, err := clientConn.Write(pkt1); err != nil {
		t.Fatalf("send initiation 1: %v", err)
	}
	buf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("no response to initial handshake: %v", err)
	}
	resp1 := append([]byte(nil), buf[:n]...)
	if !health.VerifyAWGResponsePacketObfuscated(resp1, state1, hpKey, h2, s2) {
		t.Fatal("initial handshake response failed client verification")
	}
	keys1, ok := el.TransportKeysFor(peerKey)
	if !ok || keys1 == nil {
		t.Fatal("no transport keys stored after initial handshake")
	}

	// --- Rekey: fresh ephemeral + fresh per-packet H1 from the range ---
	pkt2, state2, err := health.BuildAWGInitiationPacketObfuscated(sPub[:], state1.ClientPriv, nil, hpKey, h1, s1)
	if err != nil {
		t.Fatalf("build rekey initiation: %v", err)
	}
	if _, err := clientConn.Write(pkt2); err != nil {
		t.Fatalf("send rekey initiation: %v", err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("no response to rekey initiation (rejected as not-a-handshake?): %v", err)
	}
	resp2 := append([]byte(nil), buf[:n]...)
	if !health.VerifyAWGResponsePacketObfuscated(resp2, state2, hpKey, h2, s2) {
		t.Fatal("rekey response failed client verification against the NEW initiation state")
	}
	keys2, ok := el.TransportKeysFor(peerKey)
	if !ok || keys2 == nil {
		t.Fatal("transport keys missing after rekey")
	}
	if string(keys2.SendKey) == string(keys1.SendKey) {
		t.Error("transport keys were not refreshed by the rekey handshake")
	}
}

// TestHandshakeRejectionCounter verifies the exposed rejection counter: a
// datagram that fails initiation classification (message type outside H1)
// must increment it — making silent rekey rejections visible in stats.
func TestHandshakeRejectionCounter(t *testing.T) {
	el, _, _ := newRekeyTestListener(t)
	ctx := context.Background()

	before := el.HandshakeRejections()

	// Plaintext-shaped datagram whose message type is outside the H1 range:
	// classified as "not an AWG handshake initiation".
	pkt := make([]byte, 200)
	binaryLittleEndianPut(pkt[0:4], 99999)
	el.handleDatagram(ctx, pkt, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 51516})

	if after := el.HandshakeRejections(); after != before+1 {
		t.Fatalf("HandshakeRejections = %d after one rejected initiation, want %d", after, before+1)
	}

	// Non-handshake noise without a plausible size must not count.
	el.handleDatagram(ctx, []byte{0x01}, nil)
	if after := el.HandshakeRejections(); after != before+1 {
		t.Fatalf("tiny datagram changed rejection counter to %d, want %d", after, before+1)
	}
}

func binaryLittleEndianPut(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// TestPostRestartClientAutoRecovery pins the issue #39 restart-death-spiral
// contract: after the portal listener restarts (in-memory transport keys and
// peer addresses lost, server keypair persistent), a connected client must
// recover within RejectAfterTime by rekeying — its rekey initiation must be
// answered with a fresh handshake response and refreshed transport keys,
// with NO rejection counted. (In the field, these rekeys were rejected as
// "not an AWG handshake initiation" and the tunnel died until the user
// manually reconnected.)
func TestPostRestartClientAutoRecovery(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	hpKey := make([]byte, 32)
	if _, err := rand.Read(hpKey); err != nil {
		t.Fatalf("rand.Read(hpKey) failed: %v", err)
	}
	h1, h2, s1, s2 := rekeyTestHeaders()

	mkListener := func() *Listener {
		t.Helper()
		// Same persistent (DB-backed) server keys across the restart.
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
		}
		el, err := NewListener(cfg, db, nil, nil, nil, NewServerKeysManager(db))
		if err != nil {
			t.Fatalf("NewListener failed: %v", err)
		}
		el.SetIncomingPeerHandler(func(ctx context.Context, peerPublicKey string) (*models.VPNSession, *models.BackendTunnel, error) {
			user, _, err := NewDBAuthenticator(db).AuthenticatePeer(ctx, peerPublicKey)
			if err != nil {
				return nil, nil, err
			}
			ip, _ := el.IPAM().Allocate(peerPublicKey)
			sess, _ := el.SessionManager().CreateSession(ctx, user.ID, peerPublicKey, ip.String(), 1)
			return sess, &models.BackendTunnel{ID: 1}, nil
		})
		if err := el.Start(ctx); err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		return el
	}

	el1 := mkListener()
	_, sPub, err := NewServerKeysManager(db).EnsureKeypair(ctx)
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "restart-host", Host: "10.0.0.1"})
	_, _ = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sID, InterfaceName: "awg-be-1", PublicKey: "pubkey", PrivateKey: "privkey", Endpoint: "10.0.0.1:51820",
	})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "restart_user", Enabled: true})

	serverAddr, ok := el1.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el1.GetListenAddr())
	}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// Initial handshake before the restart.
	pkt1, state1, err := health.BuildAWGInitiationPacketObfuscated(sPub[:], nil, nil, hpKey, h1, s1)
	if err != nil {
		t.Fatalf("build initiation: %v", err)
	}
	pub1, err := curve25519.X25519(state1.ClientPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive client pub: %v", err)
	}
	peerKey := base64.StdEncoding.EncodeToString(pub1)
	_, _ = db.CreateConnection(ctx, &models.UserConnection{UserID: uID, ServerID: sID, Protocol: "awg", ClientID: peerKey})

	if _, err := clientConn.Write(pkt1); err != nil {
		t.Fatalf("send initiation: %v", err)
	}
	buf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientConn.Read(buf); err != nil {
		t.Fatalf("no response to initial handshake: %v", err)
	}

	// --- Portal restart: listener torn down (in-memory keys lost), a new
	// listener with the same persistent keypair comes up on a new port. The
	// client keeps its socket; a real client's OS would re-resolve the
	// service address, so the test re-dials to the new listener. ---
	_ = el1.Stop()
	el2 := mkListener()
	defer func() { _ = el2.Stop() }()
	rejectionsBefore := el2.HandshakeRejections()

	newAddr, ok := el2.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T", el2.GetListenAddr())
	}
	if err := clientConn.Close(); err != nil {
		t.Fatalf("close client conn: %v", err)
	}
	clientConn2, err := net.DialUDP("udp", nil, newAddr)
	if err != nil {
		t.Fatalf("re-dial after restart failed: %v", err)
	}
	defer func() { _ = clientConn2.Close() }()

	// The client rekeys (same static identity, fresh ephemeral + index).
	pkt2, state2, err := health.BuildAWGInitiationPacketObfuscated(sPub[:], state1.ClientPriv, nil, hpKey, h1, s1)
	if err != nil {
		t.Fatalf("build rekey initiation: %v", err)
	}
	if _, err := clientConn2.Write(pkt2); err != nil {
		t.Fatalf("send post-restart rekey initiation: %v", err)
	}
	_ = clientConn2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn2.Read(buf)
	if err != nil {
		t.Fatalf("post-restart rekey got no response (recovery impossible): %v", err)
	}
	if !health.VerifyAWGResponsePacketObfuscated(buf[:n], state2, hpKey, h2, s2) {
		t.Fatal("post-restart rekey response failed client verification")
	}
	keys2, ok := el2.TransportKeysFor(peerKey)
	if !ok || keys2 == nil {
		t.Fatal("transport keys not restored on the new listener after rekey")
	}
	if r := el2.HandshakeRejections(); r != rejectionsBefore {
		t.Fatalf("legit post-restart rekey was rejected (%d rejections), recovery broken", r-rejectionsBefore)
	}
}
