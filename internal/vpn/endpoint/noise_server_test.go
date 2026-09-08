package endpoint

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// newTestServerKeypair returns a fresh ephemeral server keypair via the
// ServerKeysManager (nil DB -> in-memory keypair).
func newTestServerKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	m := NewServerKeysManager(nil)
	p, pubArr, err := m.EnsureKeypair(context.Background())
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}
	return p[:], pubArr[:]
}

// TestServerRoleHandshakeRoundTrip is the wire-compatibility proof: a packet
// built by the locked client-role reference (health.BuildAWGInitiationPacket)
// must parse on the server side, and the server-built response must verify
// with the locked client verifier (health.VerifyAWGResponsePacket).
func TestServerRoleHandshakeRoundTrip(t *testing.T) {
	serverPriv, serverPub := newTestServerKeypair(t)

	packet, state, err := health.BuildAWGInitiationPacket(serverPub, nil, nil, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket failed: %v", err)
	}

	info, err := ParseInitiation(serverPriv, packet, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("ParseInitiation failed: %v", err)
	}

	// Parsed peer identity must match what the client used.
	clientPub, err := curve25519.X25519(state.ClientPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to derive client static pub: %v", err)
	}
	if !bytes.Equal(info.ClientStaticPub, clientPub) {
		t.Errorf("ClientStaticPub mismatch: got %x want %x", info.ClientStaticPub, clientPub)
	}
	clientEPub, err := curve25519.X25519(state.ClientEPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to derive client ephemeral pub: %v", err)
	}
	if !bytes.Equal(info.ClientEPub, clientEPub) {
		t.Errorf("ClientEPub mismatch: got %x want %x", info.ClientEPub, clientEPub)
	}
	if info.SenderIndex != state.SenderIndex {
		t.Errorf("SenderIndex mismatch: got %d want %d", info.SenderIndex, state.SenderIndex)
	}
	if len(info.H) != 32 || len(info.CK) != 32 {
		t.Errorf("hash/chain key lengths: H=%d CK=%d", len(info.H), len(info.CK))
	}

	resp, transportKeys, err := BuildResponse(serverPriv, info, health.DefaultH2, health.DefaultS2)
	if err != nil {
		t.Fatalf("BuildResponse failed: %v", err)
	}
	if transportKeys == nil || len(transportKeys.SendKey) != 32 || len(transportKeys.RecvKey) != 32 {
		t.Fatalf("bad transport keys: %+v", transportKeys)
	}
	if bytes.Equal(transportKeys.SendKey, transportKeys.RecvKey) {
		t.Errorf("SendKey and RecvKey must differ")
	}

	// Self-check the response framing: MAC1 keyed by the client static pub,
	// MAC2 all zeros, S2 junk prefix present.
	s2 := health.DefaultS2
	if len(resp) != s2+responseBodyLen+32 {
		t.Fatalf("response length %d, want %d", len(resp), s2+responseBodyLen+32)
	}
	mac1KeySum := blake2s.Sum256(concat(health.LabelMAC1, info.ClientStaticPub))
	mac1Hasher, err := blake2s.New128(mac1KeySum[:])
	if err != nil {
		t.Fatalf("failed to create MAC1 hasher: %v", err)
	}
	mac1Hasher.Write(resp[s2 : s2+responseBodyLen])
	if !hmac.Equal(mac1Hasher.Sum(nil), resp[s2+responseBodyLen:s2+responseBodyLen+16]) {
		t.Errorf("response MAC1 mismatch")
	}
	for _, b := range resp[s2+responseBodyLen+16:] {
		if b != 0 {
			t.Errorf("response MAC2 must be all zeros")
			break
		}
	}

	// THE proof: the locked client verifier must accept the server response.
	if !health.VerifyAWGResponsePacket(resp, state, health.DefaultH2, health.DefaultS2) {
		t.Fatal("VerifyAWGResponsePacket rejected the server-built response")
	}
}

func TestParseInitiationRejectsTruncated(t *testing.T) {
	serverPriv, serverPub := newTestServerKeypair(t)
	packet, _, err := health.BuildAWGInitiationPacket(serverPub, nil, nil, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket failed: %v", err)
	}

	for _, cut := range []int{1, 16, 32} {
		if _, err := ParseInitiation(serverPriv, packet[:len(packet)-cut], health.DefaultH1, health.DefaultS1); !errors.Is(err, ErrDatagramTooShort) {
			t.Errorf("truncated by %d bytes: expected ErrDatagramTooShort, got %v", cut, err)
		}
	}
}

func TestParseInitiationRejectsWrongServerKey(t *testing.T) {
	_, serverPubA := newTestServerKeypair(t)
	serverPrivB, _ := newTestServerKeypair(t)

	packet, _, err := health.BuildAWGInitiationPacket(serverPubA, nil, nil, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket failed: %v", err)
	}

	// MAC1 is keyed by the server public key, so the wrong server key must be
	// rejected (at the MAC1 layer at the latest).
	if _, err := ParseInitiation(serverPrivB, packet, health.DefaultH1, health.DefaultS1); err == nil {
		t.Errorf("expected rejection when parsing an initiation for server key A with server key B")
	}
}

// TestParseInitiationRejectsTamperedStatic flips a bit inside encrypted_static
// and RECOMPUTES MAC1 (using the client state's exported MAC1 key) so the
// tamper is isolated to the AEAD layer: MAC1 verifies, then ChaCha20Poly1305
// Open must fail with ErrDecryptStatic.
func TestParseInitiationRejectsTamperedStatic(t *testing.T) {
	serverPriv, serverPub := newTestServerKeypair(t)
	packet, state, err := health.BuildAWGInitiationPacket(serverPub, nil, nil, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket failed: %v", err)
	}

	s1 := health.DefaultS1
	packet[s1+40+10] ^= 0x01 // flip a bit inside encrypted_static

	mac1Hasher, err := blake2s.New128(state.MAC1Key)
	if err != nil {
		t.Fatalf("failed to create MAC1 hasher: %v", err)
	}
	mac1Hasher.Write(packet[s1 : s1+initiationBodyLen])
	copy(packet[s1+initiationBodyLen:s1+initiationBodyLen+16], mac1Hasher.Sum(nil))

	if _, err := ParseInitiation(serverPriv, packet, health.DefaultH1, health.DefaultS1); !errors.Is(err, ErrDecryptStatic) {
		t.Errorf("expected ErrDecryptStatic for tampered encrypted_static, got %v", err)
	}
}

func TestParseInitiationRejectsTamperedMAC1(t *testing.T) {
	serverPriv, serverPub := newTestServerKeypair(t)
	packet, _, err := health.BuildAWGInitiationPacket(serverPub, nil, nil, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket failed: %v", err)
	}

	s1 := health.DefaultS1
	packet[s1+116+3] ^= 0x01 // flip a bit inside MAC1

	if _, err := ParseInitiation(serverPriv, packet, health.DefaultH1, health.DefaultS1); !errors.Is(err, ErrMAC1Failed) {
		t.Errorf("expected ErrMAC1Failed for tampered MAC1, got %v", err)
	}
}

func TestParseInitiationRejectsGarbage(t *testing.T) {
	serverPriv, _ := newTestServerKeypair(t)

	garbage := make([]byte, 200)
	if _, err := rand.Read(garbage); err != nil {
		t.Fatalf("rand failed: %v", err)
	}
	if _, err := ParseInitiation(serverPriv, garbage, health.DefaultH1, health.DefaultS1); err == nil {
		t.Errorf("expected rejection of random garbage")
	}
}

// buildInitiationAt is a test-local, clock-injectable mirror of
// health.BuildAWGInitiationPacket. The health package is the locked
// client-role reference and must not be modified, so the stale-timestamp
// negative case (out-of-window TAI64N) needs this copy with a `now` parameter.
func buildInitiationAt(t *testing.T, serverPub, clientPriv []byte, now time.Time) []byte {
	t.Helper()

	clientPub, err := curve25519.X25519(clientPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to derive client pub: %v", err)
	}

	hSum := blake2s.Sum256(concat(health.InitialHash[:], serverPub))
	h := hSum[:]
	ck := health.InitialChainKey[:]

	clientEPriv := make([]byte, 32)
	if _, err := rand.Read(clientEPriv); err != nil {
		t.Fatalf("rand failed: %v", err)
	}
	clientEPub, err := curve25519.X25519(clientEPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to derive client ephemeral pub: %v", err)
	}

	hSum = blake2s.Sum256(concat(h, clientEPub))
	h = hSum[:]
	ck = health.KDF1(ck, clientEPub)

	ss1, err := curve25519.X25519(clientEPriv, serverPub)
	if err != nil {
		t.Fatalf("first DH failed: %v", err)
	}
	ck, key1 := health.KDF2(ck, ss1)

	aead1, err := chacha20poly1305.New(key1)
	if err != nil {
		t.Fatalf("failed to create aead1: %v", err)
	}
	nonce := nonceZero()
	encStatic := aead1.Seal(nil, nonce, clientPub, h)
	hSum = blake2s.Sum256(concat(h, encStatic))
	h = hSum[:]

	ss2, err := curve25519.X25519(clientPriv, serverPub)
	if err != nil {
		t.Fatalf("second DH failed: %v", err)
	}
	// The final chain key is not needed: only key2 feeds the transport AEAD.
	_, key2 := health.KDF2(ck, ss2)

	aead2, err := chacha20poly1305.New(key2)
	if err != nil {
		t.Fatalf("failed to create aead2: %v", err)
	}
	tai64n := make([]byte, 12)
	// #nosec G115 -- mirrors health.BuildAWGInitiationPacket TAI64N encoding.
	binary.BigEndian.PutUint64(tai64n[0:8], uint64(0x400000000000000A+now.Unix()))
	// #nosec G115 -- mirrors health.BuildAWGInitiationPacket TAI64N encoding.
	binary.BigEndian.PutUint32(tai64n[8:12], uint32(now.Nanosecond()&^0xFFFFFF))
	encTS := aead2.Seal(nil, nonce, tai64n, h)
	// The h/ck chain beyond encTS is unused by this builder: MAC1 covers body
	// (which embeds encTS) directly, so the trailing mix is skipped.

	body := make([]byte, 0, initiationBodyLen)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], health.DefaultH1)
	body = append(body, b4[:]...)
	binary.LittleEndian.PutUint32(b4[:], 12345) // sender index
	body = append(body, b4[:]...)
	body = append(body, clientEPub...)
	body = append(body, encStatic...)
	body = append(body, encTS...)

	mac1KeySum := blake2s.Sum256(concat(health.LabelMAC1, serverPub))
	mac1Hasher, err := blake2s.New128(mac1KeySum[:])
	if err != nil {
		t.Fatalf("failed to create MAC1 hasher: %v", err)
	}
	mac1Hasher.Write(body)

	packet := make([]byte, 0, health.DefaultS1+initiationWireLen)
	junk := make([]byte, health.DefaultS1)
	if _, err := rand.Read(junk); err != nil {
		t.Fatalf("rand failed: %v", err)
	}
	packet = append(packet, junk...)
	packet = append(packet, body...)
	packet = append(packet, mac1Hasher.Sum(nil)...)
	packet = append(packet, make([]byte, 16)...)
	return packet
}

func TestParseInitiationRejectsStaleTimestamp(t *testing.T) {
	serverPriv, serverPub := newTestServerKeypair(t)
	clientPriv := make([]byte, 32)
	if _, err := rand.Read(clientPriv); err != nil {
		t.Fatalf("rand failed: %v", err)
	}

	// Fresh timestamp must parse (sanity control for the mirror).
	fresh := buildInitiationAt(t, serverPub, clientPriv, time.Now())
	if _, err := ParseInitiation(serverPriv, fresh, health.DefaultH1, health.DefaultS1); err != nil {
		t.Fatalf("fresh-timestamp initiation should parse, got: %v", err)
	}

	// 400 seconds stale -> outside the 300s anti-replay window.
	stale := buildInitiationAt(t, serverPub, clientPriv, time.Now().Add(-400*time.Second))
	if _, err := ParseInitiation(serverPriv, stale, health.DefaultH1, health.DefaultS1); !errors.Is(err, ErrTimestampStale) {
		t.Errorf("expected ErrTimestampStale for 400s-old initiation, got %v", err)
	}
}

// TestEndpointListenerHandshakeOverUDP proves the full listener accept path:
// real initiation over UDP -> ParseInitiation -> AuthenticatePeer ->
// CreateSession -> WriteToUDP response -> client verifier accepts.
func TestEndpointListenerHandshakeOverUDP(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
	}

	keysMgr := NewServerKeysManager(nil)
	el, err := NewListener(cfg, db, nil, nil, nil, keysMgr)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}
	// Dummy handler for tests that acts like HandleIncomingPeer
	el.SetIncomingPeerHandler(func(ctx context.Context, peerPublicKey string) (*models.VPNSession, *models.BackendTunnel, error) {
		auth := NewDBAuthenticator(db)
		user, _, err := auth.AuthenticatePeer(ctx, peerPublicKey)
		if err != nil {
			return nil, nil, err
		}
		// Allocate IP and create session just like HandleIncomingPeer
		assignedIP, _ := el.IPAM().Allocate(peerPublicKey)
		sess, _ := el.SessionManager().CreateSession(ctx, user.ID, peerPublicKey, assignedIP.String(), 1)
		return sess, &models.BackendTunnel{ID: 1}, nil
	})
	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	// Resolve the server keypair the listener uses, then act as the client.
	_, sPub, err := keysMgr.EnsureKeypair(ctx)
	if err != nil {
		t.Fatalf("EnsureKeypair failed: %v", err)
	}
	packet, state, err := health.BuildAWGInitiationPacket(sPub[:], nil, nil, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket failed: %v", err)
	}
	clientPub, err := curve25519.X25519(state.ClientPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("failed to derive client pub: %v", err)
	}
	peerKey := base64.StdEncoding.EncodeToString(clientPub)

	// Register the peer's static pub as a user connection (mirrors
	// TestEndpointListenerRegistrationAndDrain setup).
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.0.0.1"})
	_, _ = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "pubkey",
		PrivateKey:    "privkey",
		Endpoint:      "10.0.0.1:51820",
	})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "noise_user", Enabled: true})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: sID,
		Protocol: "awg",
		ClientID: peerKey,
	})

	serverAddr, ok := el.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("GetListenAddr returned %T, want *net.UDPAddr", el.GetListenAddr())
	}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write(packet); err != nil {
		t.Fatalf("failed to send initiation: %v", err)
	}

	respBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("no handshake response received: %v", err)
	}

	if !health.VerifyAWGResponsePacket(respBuf[:n], state, health.DefaultH2, health.DefaultS2) {
		t.Error("VerifyAWGResponsePacket rejected the listener's UDP response")
	}

	// The accept path must have created a session and stored transport keys.
	if _, ok := el.SessionManager().GetSession(peerKey); !ok {
		t.Error("expected an active session after successful handshake")
	}
	if _, ok := el.TransportKeysFor(peerKey); !ok {
		t.Error("expected transport keys to be stored for the peer")
	}

	// Unregistered peer: initiation must be silently dropped (no response).
	ghostPacket, _, err := health.BuildAWGInitiationPacket(sPub[:], nil, nil, health.DefaultH1, health.DefaultS1)
	if err != nil {
		t.Fatalf("BuildAWGInitiationPacket failed: %v", err)
	}
	if _, err := clientConn.Write(ghostPacket); err != nil {
		t.Fatalf("failed to send ghost initiation: %v", err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if n, err := clientConn.Read(respBuf); err == nil {
		t.Errorf("expected silent drop for unregistered peer, got %d-byte response", n)
	}
}
