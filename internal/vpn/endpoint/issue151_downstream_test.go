package endpoint

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"golang.org/x/crypto/chacha20poly1305"
)

// TestSocketBufferConfiguration verifies that DefaultUDPSocketBufferSize is 4 MB
// and that Listener.Start successfully binds and configures the UDP socket buffers (issue #151).
func TestSocketBufferConfiguration(t *testing.T) {
	if DefaultUDPSocketBufferSize != 4*1024*1024 {
		t.Fatalf("DefaultUDPSocketBufferSize = %d, want %d", DefaultUDPSocketBufferSize, 4*1024*1024)
	}

	db := setupTestDB(t)
	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := el.Start(ctx); err != nil {
		t.Fatalf("Listener.Start failed with socket buffer configuration: %v", err)
	}
	defer func() { _ = el.Stop() }()

	if !el.IsRunning() {
		t.Fatal("expected listener to be running")
	}
}

// TestSendToPeer_FastPathCachedUDPAddr verifies that rememberPeer caches the pre-parsed
// *net.UDPAddr, SendToPeer uses the cached address avoiding per-packet string resolution,
// and gracefully falls back if the cached pointer is missing (issue #151).
func TestSendToPeer_FastPathCachedUDPAddr(t *testing.T) {
	db := setupTestDB(t)
	listenPort := getFreeUDPPort(t)
	cfg := ListenerConfig{
		ListenPort:  listenPort,
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
		S4:          0,
		H4:          models.DegenerateHeaderRange(health.DefaultH4),
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	// Start a local UDP mock client
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP for client failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	peerKey := "test-peer-cached-addr"
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}

	tk, err := NewTransportKeys(key, key)
	if err != nil {
		t.Fatalf("NewTransportKeys failed: %v", err)
	}
	el.storeTransportKeys(peerKey, tk)

	// Step 1: rememberPeer should store cloned *net.UDPAddr
	el.rememberPeer(clientAddr, peerKey, 42)

	st, ok := el.peerByAddr(clientAddr.String())
	if !ok || st == nil {
		t.Fatalf("peerByAddr failed to find peer")
	}
	if st.udpAddr == nil {
		t.Fatal("expected cached udpAddr in activePeerState, got nil")
	}
	if st.udpAddr.String() != clientAddr.String() {
		t.Fatalf("cached udpAddr = %s, want %s", st.udpAddr.String(), clientAddr.String())
	}

	// Step 2: SendToPeer using cached *net.UDPAddr fast path
	testPayload := []byte("fast-path-payload-cached-addr")
	if err := el.SendToPeer(peerKey, testPayload); err != nil {
		t.Fatalf("SendToPeer failed with cached UDPAddr: %v", err)
	}

	buf := make([]byte, 1500)
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, from, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client failed to read packet sent via cached UDPAddr: %v", err)
	}
	if n == 0 || from == nil {
		t.Fatal("received empty datagram")
	}

	// Step 3: Fallback test: if st.udpAddr is nil, SendToPeer resolves addrStr and still succeeds
	el.mu.Lock()
	st.udpAddr = nil
	el.mu.Unlock()

	if err := el.SendToPeer(peerKey, testPayload); err != nil {
		t.Fatalf("SendToPeer fallback failed when st.udpAddr == nil: %v", err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n2, _, err := clientConn.ReadFromUDP(buf)
	if err != nil || n2 == 0 {
		t.Fatalf("client failed to read packet sent via fallback resolver: %v", err)
	}
}

// TestHandleTransportData_CachesUDPAddrIfMissing verifies that when datagram arrives
// for a peer whose udpAddr was not yet cached, handleTransportData populates st.udpAddr (issue #151).
func TestHandleTransportData_CachesUDPAddrIfMissing(t *testing.T) {
	db := setupTestDB(t)
	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
		S4:          12,
		H4:          models.DegenerateHeaderRange(health.DefaultH4),
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	sender, _ := net.ResolveUDPAddr("udp", "127.0.0.1:48888")
	peerKey := "test-peer-cache-on-recv"
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i + 10)
	}

	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: key,
		SendKey: key,
	})
	el.rememberPeer(sender, peerKey, 100)

	// Artificially clear st.udpAddr to test that handleTransportData heals and caches it
	st, ok := el.peerByAddr(sender.String())
	if !ok || st == nil {
		t.Fatal("peer not found after rememberPeer")
	}
	el.mu.Lock()
	st.udpAddr = nil
	el.mu.Unlock()

	// Build a valid transport datagram
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], health.DefaultH4)
	binary.LittleEndian.PutUint32(hdr[4:8], 100)
	binary.LittleEndian.PutUint64(hdr[8:16], 0)

	var nonce [chacha20poly1305.NonceSize]byte
	innerPacket := make([]byte, 20)
	innerPacket[0] = 0x45 // IPv4
	binary.BigEndian.PutUint16(innerPacket[2:4], 20)

	s4Junk := make([]byte, el.config.S4)
	datagram := append(s4Junk, hdr[:]...)
	datagram = aead.Seal(datagram, nonce[:], innerPacket, nil)

	var routedPacket []byte
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		routedPacket = pkt
		return nil
	})

	handled := el.handleTransportData(datagram, sender)
	if !handled {
		t.Fatal("expected handleTransportData to return true")
	}
	if !bytes.Equal(routedPacket, innerPacket) {
		t.Fatalf("routed packet mismatch: got %v, want %v", routedPacket, innerPacket)
	}

	// Verify st.udpAddr was cached
	if st.udpAddr == nil {
		t.Fatal("expected st.udpAddr to be cached by handleTransportData")
	}
	if st.udpAddr.String() != sender.String() {
		t.Fatalf("cached udpAddr = %s, want %s", st.udpAddr.String(), sender.String())
	}
}

// TestTransportKeys_PreInstantiatedAEADCiphers tests pre-instantiation, caching, and reuse
// of SendAEAD and RecvAEAD ciphers in TransportKeys (issue #151).
func TestTransportKeys_PreInstantiatedAEADCiphers(t *testing.T) {
	sendKey := make([]byte, chacha20poly1305.KeySize)
	recvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range sendKey {
		sendKey[i] = byte(i + 1)
		recvKey[i] = byte(i + 50)
	}

	// 1. NewTransportKeys initializes both ciphers
	tk, err := NewTransportKeys(sendKey, recvKey)
	if err != nil {
		t.Fatalf("NewTransportKeys failed: %v", err)
	}
	if tk.SendAEAD == nil {
		t.Fatal("SendAEAD was not pre-instantiated")
	}
	if tk.RecvAEAD == nil {
		t.Fatal("RecvAEAD was not pre-instantiated")
	}

	// 2. SendCipher() and RecvCipher() return the pre-created ciphers without re-allocating
	s1, err := tk.SendCipher()
	if err != nil || s1 != tk.SendAEAD {
		t.Fatalf("SendCipher() failed or returned different instance")
	}
	s2, err := tk.SendCipher()
	if err != nil || s2 != s1 {
		t.Fatalf("SendCipher() did not reuse pre-instantiated cipher instance")
	}

	r1, err := tk.RecvCipher()
	if err != nil || r1 != tk.RecvAEAD {
		t.Fatalf("RecvCipher() failed or returned different instance")
	}
	r2, err := tk.RecvCipher()
	if err != nil || r2 != r1 {
		t.Fatalf("RecvCipher() did not reuse pre-instantiated cipher instance")
	}

	// 3. Encrypt with SendCipher and verify decrypt with matching key
	var nonce [chacha20poly1305.NonceSize]byte
	plaintext := []byte("pre-instantiated-cipher-test-data")
	ciphertext := s1.Seal(nil, nonce[:], plaintext, nil)

	verifierAEAD, err := chacha20poly1305.New(sendKey)
	if err != nil {
		t.Fatalf("verifier cipher creation failed: %v", err)
	}
	decrypted, err := verifierAEAD.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted payload mismatch: got %s, want %s", string(decrypted), string(plaintext))
	}

	// 4. Test lazy InitCiphers on struct literal
	tkRaw := &TransportKeys{SendKey: sendKey, RecvKey: recvKey}
	if tkRaw.SendAEAD != nil || tkRaw.RecvAEAD != nil {
		t.Fatal("raw struct should have nil ciphers initially")
	}
	if err := tkRaw.InitCiphers(); err != nil {
		t.Fatalf("InitCiphers failed: %v", err)
	}
	if tkRaw.SendAEAD == nil || tkRaw.RecvAEAD == nil {
		t.Fatal("InitCiphers failed to instantiate ciphers")
	}

	// 5. Error cases
	tkBadKey := &TransportKeys{SendKey: []byte("too-short")}
	if err := tkBadKey.InitCiphers(); err == nil {
		t.Fatal("expected error on invalid key length in InitCiphers")
	}

	var tkNil *TransportKeys
	if _, err := tkNil.SendCipher(); err == nil {
		t.Fatal("expected error on nil TransportKeys")
	}
	if _, err := tkNil.RecvCipher(); err == nil {
		t.Fatal("expected error on nil TransportKeys")
	}
}

// TestSendToPeerAndHandleTransportData_CipherReuse verifies end-to-end that
// storeTransportKeys pre-instantiates ciphers, SendToPeer uses SendCipher,
// and handleTransportData uses RecvCipher without per-packet reallocations (issue #151).
func TestSendToPeerAndHandleTransportData_CipherReuse(t *testing.T) {
	db := setupTestDB(t)
	listenPort := getFreeUDPPort(t)
	cfg := ListenerConfig{
		ListenPort:  listenPort,
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
		S4:          12,
		H4:          models.DegenerateHeaderRange(health.DefaultH4),
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP for client failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	peerKey := "test-peer-roundtrip-reuse"
	serverSendKey := make([]byte, chacha20poly1305.KeySize)
	serverRecvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range serverSendKey {
		serverSendKey[i] = byte(i + 1)
		serverRecvKey[i] = byte(i + 40)
	}

	// storeTransportKeys auto-runs InitCiphers
	rawKeys := &TransportKeys{
		SendKey: serverSendKey,
		RecvKey: serverRecvKey,
	}
	el.storeTransportKeys(peerKey, rawKeys)
	if rawKeys.SendAEAD == nil || rawKeys.RecvAEAD == nil {
		t.Fatal("storeTransportKeys should have pre-instantiated ciphers")
	}

	el.rememberPeer(clientAddr, peerKey, 77)

	// Step 1: Server -> Client via SendToPeer
	serverMsg := []byte("packet-from-server-to-client")
	if err := el.SendToPeer(peerKey, serverMsg); err != nil {
		t.Fatalf("SendToPeer failed: %v", err)
	}

	readBuf := make([]byte, 1500)
	_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err := clientConn.ReadFromUDP(readBuf)
	if err != nil {
		t.Fatalf("client read failed: %v", err)
	}

	// Client decrypts using serverSendKey
	clientAEAD, err := chacha20poly1305.New(serverSendKey)
	if err != nil {
		t.Fatalf("clientAEAD failed: %v", err)
	}
	datagram := readBuf[:n]
	s4 := el.config.S4
	payload := datagram[s4:]
	counter := binary.LittleEndian.Uint64(payload[8:16])
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)

	decryptedServerMsg, err := clientAEAD.Open(nil, nonce[:], payload[transportDataHeaderLen:], nil)
	if err != nil {
		t.Fatalf("client failed to decrypt SendToPeer packet: %v", err)
	}
	if !bytes.Equal(decryptedServerMsg, serverMsg) {
		t.Fatalf("server message mismatch: got %s, want %s", string(decryptedServerMsg), string(serverMsg))
	}

	// Step 2: Client -> Server via handleTransportData
	var routedPacket []byte
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		routedPacket = append([]byte(nil), pkt...)
		return nil
	})

	clientMsg := make([]byte, 20)
	clientMsg[0] = 0x45 // IPv4
	binary.BigEndian.PutUint16(clientMsg[2:4], 20)
	copy(clientMsg[12:16], []byte{10, 100, 0, 2})
	copy(clientMsg[16:20], []byte{1, 1, 1, 1})

	clientSendAEAD, err := chacha20poly1305.New(serverRecvKey)
	if err != nil {
		t.Fatalf("clientSendAEAD creation failed: %v", err)
	}

	var clientNonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(clientNonce[4:12], 1)

	var inHdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(inHdr[0:4], health.DefaultH4)
	binary.LittleEndian.PutUint32(inHdr[4:8], 77)
	binary.LittleEndian.PutUint64(inHdr[8:16], 1)

	s4Junk := make([]byte, s4)
	inDatagram := append(s4Junk, inHdr[:]...)
	inDatagram = clientSendAEAD.Seal(inDatagram, clientNonce[:], clientMsg, nil)

	handled := el.handleTransportData(inDatagram, clientAddr)
	if !handled {
		t.Fatal("expected handleTransportData to succeed")
	}
	if !bytes.Equal(routedPacket, clientMsg) {
		t.Fatalf("routed packet mismatch: got %v, want %v", routedPacket, clientMsg)
	}
}

// BenchmarkSendToPeer_FastPath benchmarks SendToPeer with cached UDP address and pre-instantiated cipher.
func BenchmarkSendToPeer_FastPath(b *testing.B) {
	tempConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenUDP failed: %v", err)
	}
	listenPort := tempConn.LocalAddr().(*net.UDPAddr).Port
	_ = tempConn.Close()

	cfg := ListenerConfig{
		ListenPort:  listenPort,
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 1 * time.Minute,
		S4:          0,
		H4:          models.DegenerateHeaderRange(health.DefaultH4),
	}

	el, err := NewListener(cfg, nil, nil, nil, nil, nil)
	if err != nil {
		b.Fatalf("NewListener failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := el.Start(ctx); err != nil {
		b.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenUDP for client failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	peerKey := "bench-peer"
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}

	tk, _ := NewTransportKeys(key, key)
	el.storeTransportKeys(peerKey, tk)
	el.rememberPeer(clientAddr, peerKey, 1)

	packet := make([]byte, 100)
	packet[0] = 0x45

	// Drain goroutine for mock UDP client
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
				_ = clientConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				_, _, _ = clientConn.ReadFromUDP(buf)
			}
		}
	}()
	defer close(done)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := el.SendToPeer(peerKey, packet); err != nil {
			b.Fatalf("SendToPeer error: %v", err)
		}
	}
}
