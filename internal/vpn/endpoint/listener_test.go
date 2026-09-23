package endpoint

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestChannelPacketDevice(t *testing.T) {
	dev := NewChannelPacketDevice("test-tun", 1420, 10)
	if dev.Name() != "test-tun" || dev.MTU() != 1420 {
		t.Errorf("device property mismatch: name=%s, mtu=%d", dev.Name(), dev.MTU())
	}

	pkt := []byte("hello-vpn-packet")
	if err := dev.InjectPacket(pkt); err != nil {
		t.Fatalf("InjectPacket failed: %v", err)
	}

	readBuf := make([]byte, 1500)
	n, err := dev.Read(readBuf)
	if err != nil || n != len(pkt) || string(readBuf[:n]) != string(pkt) {
		t.Fatalf("Read mismatch: n=%d, err=%v, data=%s", n, err, string(readBuf[:n]))
	}

	// Test Write and ReceivePacket
	writePkt := []byte("response-vpn-packet")
	n, err = dev.Write(writePkt)
	if err != nil || n != len(writePkt) {
		t.Fatalf("Write failed: %v", err)
	}

	recvPkt, err := dev.ReceivePacket()
	if err != nil || string(recvPkt) != string(writePkt) {
		t.Fatalf("ReceivePacket mismatch: %s, err=%v", string(recvPkt), err)
	}

	// Close device
	if err := dev.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Operations after close
	if err := dev.InjectPacket(pkt); err == nil {
		t.Errorf("expected error injecting to closed device")
	}
	if _, err := dev.Write(pkt); err == nil {
		t.Errorf("expected error writing to closed device")
	}
	if _, err := dev.Read(readBuf); err == nil {
		t.Errorf("expected error reading from closed device")
	}
	if _, err := dev.ReceivePacket(); err == nil {
		t.Errorf("expected error receiving from closed device")
	}
}

func getFreeUDPPort(tb testing.TB) int {
	tb.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	tempConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		tb.Fatalf("ListenUDP failed: %v", err)
	}
	port := tempConn.LocalAddr().(*net.UDPAddr).Port
	_ = tempConn.Close()
	return port
}

func TestEndpointListenerBasic(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

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

	if el.IPAM() == nil || el.SessionManager() == nil {
		t.Errorf("expected initialized IPAM and SessionManager")
	}

	customDev := NewChannelPacketDevice("mock0", 1420, 100)
	el.SetPacketDevice(customDev)

	// Start
	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !el.IsRunning() {
		t.Errorf("expected IsRunning() to be true")
	}
	if el.GetListenAddr() == nil {
		t.Errorf("GetListenAddr() is nil")
	}

	// Double start should error
	if err := el.Start(ctx); err == nil {
		t.Errorf("expected error on double Start")
	}

	// Stop
	if err := el.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if el.IsRunning() {
		t.Errorf("expected IsRunning() to be false after Stop")
	}
	if err := el.Stop(); err != nil {
		t.Errorf("double Stop failed: %v", err)
	}
}

func TestEndpointListenerRegistrationAndDrain(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

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

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.0.0.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "pubkey",
		PrivateKey:    "privkey",
		Endpoint:      "10.0.0.1:51820",
	})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "el_user", Enabled: true})
	peerKey := "client-public-key-test"
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: sID,
		Protocol: "awg",
		ClientID: peerKey,
	})

	// Authenticate and Register Peer
	sess, err := el.AuthenticateAndRegisterPeer(ctx, peerKey, tID)
	if err != nil {
		t.Fatalf("AuthenticateAndRegisterPeer failed: %v", err)
	}
	if sess.PeerPublicKey != peerKey || sess.AssignedIP == "" {
		t.Errorf("session mismatch: %+v", sess)
	}

	// Non-registered peer
	if _, err := el.AuthenticateAndRegisterPeer(ctx, "unregistered", tID); err == nil {
		t.Errorf("expected error for unregistered peer")
	}

	// Traffic stats
	el.RecordTraffic(100, 200)
	rx, tx, active := el.GetStats()
	if rx != 100 || tx != 200 || active != 1 {
		t.Errorf("GetStats mismatch: rx=%d, tx=%d, active=%d", rx, tx, active)
	}

	// Disconnect Peer
	if err := el.DisconnectPeer(ctx, peerKey); err != nil {
		t.Fatalf("DisconnectPeer failed: %v", err)
	}
	if _, _, active := el.GetStats(); active != 0 {
		t.Errorf("expected 0 active sessions after disconnect, got %d", active)
	}
	if err := el.DisconnectPeer(ctx, "ghost"); err != ErrPeerNotFound {
		t.Errorf("expected ErrPeerNotFound on ghost peer, got %v", err)
	}

	// Reconnect and Drain
	_, _ = el.AuthenticateAndRegisterPeer(ctx, peerKey, tID)
	if err := el.Drain(ctx, 2*time.Second); err != nil {
		t.Fatalf("Drain failed: %v", err)
	}
	if !el.IsDraining() {
		t.Errorf("expected IsDraining() to be true")
	}

	// Registering while draining should reject
	if _, err := el.AuthenticateAndRegisterPeer(ctx, peerKey, tID); err == nil {
		t.Errorf("expected new registration rejected while draining")
	}
}

func TestHandleTransportData_PayloadContentPaddingTrimming(t *testing.T) {
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

	peerKey := "padding-trim-peer-key"
	clientAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:43210")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	recvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey {
		recvKey[i] = byte(i + 1)
	}
	sendKey := make([]byte, chacha20poly1305.KeySize)
	for i := range sendKey {
		sendKey[i] = byte(i + 33)
	}

	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: recvKey,
		SendKey: sendKey,
	})
	el.rememberPeer(clientAddr, peerKey, 12345)

	var routedPackets [][]byte
	var mu sync.Mutex
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		mu.Lock()
		defer mu.Unlock()
		if pk != peerKey {
			t.Errorf("expected peerKey %s, got %s", peerKey, pk)
		}
		pktCopy := make([]byte, len(pkt))
		copy(pktCopy, pkt)
		routedPackets = append(routedPackets, pktCopy)
		return nil
	})

	aead, err := chacha20poly1305.New(recvKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}

	// Case 1: IPv4 packet with 16-byte zero padding at the end.
	// IPv4 header TotalLength = 28 (20 bytes IPv4 header + 8 bytes payload).
	ipv4HeaderAndPayload := make([]byte, 28)
	ipv4HeaderAndPayload[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(ipv4HeaderAndPayload[2:4], 28)
	for i := 4; i < 28; i++ {
		ipv4HeaderAndPayload[i] = byte(0xAA)
	}
	padding := make([]byte, 16) // 16-byte zero padding
	plaintextIPv4 := append(ipv4HeaderAndPayload, padding...)

	var counter uint64 = 1
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	ciphertextIPv4 := aead.Seal(nil, nonce[:], plaintextIPv4, nil)

	s4Junk := make([]byte, cfg.S4)
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 0) // receiver index
	binary.LittleEndian.PutUint64(hdr[8:16], counter)

	datagram := append(s4Junk, hdr[:]...)
	datagram = append(datagram, ciphertextIPv4...)

	el.handleTransportData(datagram, clientAddr)

	mu.Lock()
	if len(routedPackets) != 1 {
		t.Fatalf("expected 1 routed packet, got %d", len(routedPackets))
	}
	if len(routedPackets[0]) != 28 {
		t.Errorf("expected routed IPv4 packet len 28, got %d", len(routedPackets[0]))
	}
	if !bytes.Equal(routedPackets[0], ipv4HeaderAndPayload) {
		t.Errorf("routed IPv4 packet content mismatch: got %x, want %x", routedPackets[0], ipv4HeaderAndPayload)
	}
	mu.Unlock()

	// Case 2: IPv6 packet with 16-byte zero padding at the end.
	// IPv6 header PayloadLength = 8 (total packet = 40 + 8 = 48 bytes).
	ipv6HeaderAndPayload := make([]byte, 48)
	ipv6HeaderAndPayload[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ipv6HeaderAndPayload[4:6], 8)
	for i := 6; i < 48; i++ {
		ipv6HeaderAndPayload[i] = byte(0xBB)
	}
	plaintextIPv6 := append(ipv6HeaderAndPayload, padding...)

	counter = 2
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	ciphertextIPv6 := aead.Seal(nil, nonce[:], plaintextIPv6, nil)

	binary.LittleEndian.PutUint64(hdr[8:16], counter)
	datagramIPv6 := append(s4Junk, hdr[:]...)
	datagramIPv6 = append(datagramIPv6, ciphertextIPv6...)

	el.handleTransportData(datagramIPv6, clientAddr)

	mu.Lock()
	if len(routedPackets) != 2 {
		t.Fatalf("expected 2 routed packets, got %d", len(routedPackets))
	}
	if len(routedPackets[1]) != 48 {
		t.Errorf("expected routed IPv6 packet len 48, got %d", len(routedPackets[1]))
	}
	if !bytes.Equal(routedPackets[1], ipv6HeaderAndPayload) {
		t.Errorf("routed IPv6 packet content mismatch: got %x, want %x", routedPackets[1], ipv6HeaderAndPayload)
	}
	mu.Unlock()
}

func TestConcurrentRememberAndSendToPeer(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

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

	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	peerKey := "concurrent-test-peer-key"
	key := make([]byte, chacha20poly1305.KeySize)
	el.storeTransportKeys(peerKey, &TransportKeys{SendKey: key, RecvKey: key})

	sinkConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer func() { _ = sinkConn.Close() }()
	clientAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	el.rememberPeer(clientAddr, peerKey, 1000)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Goroutines concurrently calling rememberPeer
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var idx uint32 = uint32(id * 100)
			for {
				select {
				case <-stop:
					return
				default:
					idx++
					el.rememberPeer(clientAddr, peerKey, idx)
				}
			}
		}(i)
	}

	// Goroutines concurrently calling SendToPeer
	packet := []byte("dummy-ip-payload")
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = el.SendToPeer(peerKey, packet)
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestHandleTransportData_HeaderProtection_MaskedAndFallback(t *testing.T) {
	db := setupTestDB(t)
	hpKeyBytes := make([]byte, 32)
	for i := range hpKeyBytes {
		hpKeyBytes[i] = byte(i + 42)
	}
	hpKeyB64 := base64.StdEncoding.EncodeToString(hpKeyBytes)

	cfg := ListenerConfig{
		ListenPort:          getFreeUDPPort(t),
		SubnetCIDR:          "10.100.0.0/24",
		MTU:                 1420,
		IdleTimeout:         1 * time.Minute,
		S4:                  16,
		H4:                  models.DegenerateHeaderRange(health.DefaultH4),
		HeaderProtectionKey: hpKeyB64,
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	peerKey := "hp-test-peer-key"
	clientAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:45678")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}

	recvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey {
		recvKey[i] = byte(i + 1)
	}
	sendKey := make([]byte, chacha20poly1305.KeySize)
	for i := range sendKey {
		sendKey[i] = byte(i + 33)
	}

	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: recvKey,
		SendKey: sendKey,
	})
	el.rememberPeer(clientAddr, peerKey, 54321)

	var routedPackets [][]byte
	var mu sync.Mutex
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		mu.Lock()
		defer mu.Unlock()
		if pk != peerKey {
			t.Errorf("expected peerKey %s, got %s", peerKey, pk)
		}
		pktCopy := make([]byte, len(pkt))
		copy(pktCopy, pkt)
		routedPackets = append(routedPackets, pktCopy)
		return nil
	})

	aead, err := chacha20poly1305.New(recvKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}

	// 1. Masked Transport Data Packet:
	testPayloadMasked := []byte("masked-transport-data-payload")
	var counter uint64 = 1
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	ciphertextMasked := aead.Seal(nil, nonce[:], testPayloadMasked, nil)

	s4Junk := make([]byte, cfg.S4)
	for i := range s4Junk {
		s4Junk[i] = byte(i + 7)
	}
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 54321) // receiver index
	binary.LittleEndian.PutUint64(hdr[8:16], counter)

	// Apply header protection masking on hdr
	cip := health.NewHeaderProtectionCipher(hpKeyBytes, s4Junk[:health.HeaderCipherNonceSize])
	if cip == nil {
		t.Fatal("failed to create client-side HeaderProtectionCipher")
	}
	maskedHdr := make([]byte, transportDataHeaderLen)
	cip.XORKeyStream(maskedHdr, hdr[:])

	datagramMasked := append(s4Junk, maskedHdr...)
	datagramMasked = append(datagramMasked, ciphertextMasked...)

	if ok := el.handleTransportData(datagramMasked, clientAddr); !ok {
		t.Fatal("handleTransportData rejected valid masked transport data packet")
	}

	mu.Lock()
	if len(routedPackets) != 1 || !bytes.Equal(routedPackets[0], testPayloadMasked) {
		t.Fatalf("routed packet mismatch: got %v, want %s", routedPackets, testPayloadMasked)
	}
	mu.Unlock()

	// 2. Plaintext Transport Data Packet (Dual-mode fallback):
	testPayloadPlain := []byte("plaintext-fallback-payload")
	counter = 2
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	ciphertextPlain := aead.Seal(nil, nonce[:], testPayloadPlain, nil)

	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 54321)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)

	datagramPlain := append(s4Junk, hdr[:]...)
	datagramPlain = append(datagramPlain, ciphertextPlain...)

	if ok := el.handleTransportData(datagramPlain, clientAddr); !ok {
		t.Fatal("handleTransportData rejected plaintext packet via dual-mode fallback")
	}

	mu.Lock()
	if len(routedPackets) != 2 || !bytes.Equal(routedPackets[1], testPayloadPlain) {
		t.Fatalf("routed fallback packet mismatch: got %v, want %s", routedPackets, testPayloadPlain)
	}
	mu.Unlock()

	// 3. Non-H4 Packet: neither unmasked nor plaintext matches H4.
	// Must return false so non-transport datagrams (e.g. handshake initiations)
	// are not swallowed as transport data (issue #288 Round 2).
	nonH4Datagram := make([]byte, len(datagramMasked))
	copy(nonH4Datagram, datagramMasked)
	nonH4Datagram[cfg.S4] ^= 0xFF
	nonH4Datagram[cfg.S4+1] ^= 0xFF

	if ok := el.handleTransportData(nonH4Datagram, clientAddr); ok {
		t.Fatal("handleTransportData returned true for non-H4 packet")
	}

	// 3b. Transport Decryption Failure: valid H4 header with corrupted ciphertext.
	// Since it is recognized as transport data for an established peer, handleTransportData
	// returns true (decoupled from handshake rejection counter, issue #149),
	// but the corrupt packet is dropped and never routed.
	corruptCiphertext := make([]byte, len(datagramMasked))
	copy(corruptCiphertext, datagramMasked)
	corruptCiphertext[len(corruptCiphertext)-1] ^= 0xFF

	if ok := el.handleTransportData(corruptCiphertext, clientAddr); !ok {
		t.Fatal("handleTransportData returned false for valid H4 transport packet with decryption failure")
	}
	mu.Lock()
	if len(routedPackets) != 2 {
		t.Fatalf("expected 2 routed packets (corrupt packet must be dropped), got %d", len(routedPackets))
	}
	mu.Unlock()

	// 4. Unknown Sender: not an established session, must return false.
	unknownAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:49999")
	if ok := el.handleTransportData(nonH4Datagram, unknownAddr); ok {
		t.Fatal("handleTransportData returned true for unknown sender")
	}

	// 5. Truncated Datagram: too short for transport, must return false.
	if ok := el.handleTransportData([]byte{1, 2, 3}, clientAddr); ok {
		t.Fatal("handleTransportData returned true for truncated datagram")
	}
}

func TestSendToPeer_HeaderProtection_Masked(t *testing.T) {
	db := setupTestDB(t)
	hpKeyBytes := make([]byte, 32)
	for i := range hpKeyBytes {
		hpKeyBytes[i] = byte(i + 77)
	}
	hpKeyB64 := base64.StdEncoding.EncodeToString(hpKeyBytes)

	// Bind a local UDP socket for simulated client
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("net.ListenUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)

	cfg := ListenerConfig{
		ListenPort:          getFreeUDPPort(t),
		SubnetCIDR:          "10.100.0.0/24",
		MTU:                 1420,
		IdleTimeout:         1 * time.Minute,
		S4:                  16,
		H4:                  models.DegenerateHeaderRange(health.DefaultH4),
		HeaderProtectionKey: hpKeyB64,
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	// Create listener UDP connection
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: cfg.ListenPort}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("server net.ListenUDP failed: %v", err)
	}
	defer func() { _ = serverConn.Close() }()
	el.udpConn = serverConn

	peerKey := "send-to-peer-hp-key"
	clientReceiverIdx := uint32(98765)

	recvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range recvKey {
		recvKey[i] = byte(i + 10)
	}
	sendKey := make([]byte, chacha20poly1305.KeySize)
	for i := range sendKey {
		sendKey[i] = byte(i + 50)
	}

	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: recvKey,
		SendKey: sendKey,
	})
	el.rememberPeer(clientAddr, peerKey, clientReceiverIdx)

	testPacket := []byte("outbound-vpn-payload-for-client")
	if err := el.SendToPeer(peerKey, testPacket); err != nil {
		t.Fatalf("SendToPeer failed: %v", err)
	}

	buf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("clientConn ReadFromUDP failed: %v", err)
	}

	s4 := cfg.S4
	expectedMinLen := s4 + transportDataHeaderLen + len(testPacket) + chacha20poly1305.Overhead
	if n < expectedMinLen {
		t.Fatalf("received packet too short: got %d, want >= %d", n, expectedMinLen)
	}

	datagram := buf[:n]

	// 1. Raw header bytes must NOT match plaintext H4 because it must be masked!
	rawMsgType := binary.LittleEndian.Uint32(datagram[s4 : s4+4])
	if rawMsgType == cfg.H4.Lo {
		t.Fatal("SendToPeer sent unmasked H4 header when HP key is configured")
	}

	// 2. Unmask header using upstream ChaCha20 cipher with nonce = datagram[:12]
	cip := health.NewHeaderProtectionCipher(hpKeyBytes, datagram[:health.HeaderCipherNonceSize])
	if cip == nil {
		t.Fatal("failed to create client-side HP cipher")
	}
	unmaskedHdr := make([]byte, transportDataHeaderLen)
	cip.XORKeyStream(unmaskedHdr, datagram[s4:s4+transportDataHeaderLen])

	unmaskedMsgType := binary.LittleEndian.Uint32(unmaskedHdr[0:4])
	if unmaskedMsgType != cfg.H4.Lo {
		t.Fatalf("unmasked msgType mismatch: got %d, want %d", unmaskedMsgType, cfg.H4.Lo)
	}
	unmaskedReceiverIdx := binary.LittleEndian.Uint32(unmaskedHdr[4:8])
	if unmaskedReceiverIdx != clientReceiverIdx {
		t.Fatalf("unmasked receiverIdx mismatch: got %d, want %d", unmaskedReceiverIdx, clientReceiverIdx)
	}
	counter := binary.LittleEndian.Uint64(unmaskedHdr[8:16])

	// 3. Decrypt payload using AEAD key (server's SendKey is client's RecvKey on wire)
	aead, err := chacha20poly1305.New(sendKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	decrypted, err := aead.Open(nil, nonce[:], datagram[s4+transportDataHeaderLen:], nil)
	if err != nil {
		t.Fatalf("failed to decrypt SendToPeer ciphertext: %v", err)
	}
	if !bytes.Equal(decrypted, testPacket) {
		t.Fatalf("decrypted payload mismatch: got %s, want %s", string(decrypted), string(testPacket))
	}
}

func TestTransportData_EndToEndRoundTrip_HeaderProtection(t *testing.T) {
	db := setupTestDB(t)
	hpKeyBytes := make([]byte, 32)
	for i := range hpKeyBytes {
		hpKeyBytes[i] = byte(i + 99)
	}
	hpKeyB64 := base64.StdEncoding.EncodeToString(hpKeyBytes)

	listenPort := getFreeUDPPort(t)
	cfg := ListenerConfig{
		ListenPort:          listenPort,
		SubnetCIDR:          "10.100.0.0/24",
		MTU:                 1420,
		IdleTimeout:         1 * time.Minute,
		S4:                  18,
		H4:                  models.DegenerateHeaderRange(health.DefaultH4),
		HeaderProtectionKey: hpKeyB64,
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	routedCh := make(chan []byte, 1)
	peerKey := "e2e-hp-peer-key"
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		if pk == peerKey {
			pktCopy := make([]byte, len(pkt))
			copy(pktCopy, pkt)
			routedCh <- pktCopy
		}
		return nil
	})

	if err := el.Start(ctx); err != nil {
		t.Fatalf("el.Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listenPort}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	// Establish keys: client's sendKey is server's recvKey; client's recvKey is server's sendKey
	clientSendKey := make([]byte, chacha20poly1305.KeySize)
	clientRecvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range clientSendKey {
		clientSendKey[i] = byte(i + 1)
		clientRecvKey[i] = byte(i + 101)
	}

	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: clientSendKey,
		SendKey: clientRecvKey,
	})

	clientAddr, err := net.ResolveUDPAddr("udp", clientConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	clientReceiverIdx := uint32(112233)
	el.rememberPeer(clientAddr, peerKey, clientReceiverIdx)

	// Step A: Client -> Listener (Masked Transport Data)
	clientAEAD, err := chacha20poly1305.New(clientSendKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}
	clientPayload := []byte("client-to-endpoint-ping-over-hp")
	var counter uint64 = 0
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	ciphertext := clientAEAD.Seal(nil, nonce[:], clientPayload, nil)

	s4Junk := make([]byte, cfg.S4)
	for i := range s4Junk {
		s4Junk[i] = byte(i + 13)
	}
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 0)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)

	cip := health.NewHeaderProtectionCipher(hpKeyBytes, s4Junk[:health.HeaderCipherNonceSize])
	if cip == nil {
		t.Fatal("failed to create client HP cipher")
	}
	maskedHdr := make([]byte, transportDataHeaderLen)
	cip.XORKeyStream(maskedHdr, hdr[:])

	datagram := append(s4Junk, maskedHdr...)
	datagram = append(datagram, ciphertext...)

	if _, err := clientConn.Write(datagram); err != nil {
		t.Fatalf("clientConn.Write failed: %v", err)
	}

	select {
	case routed := <-routedCh:
		if !bytes.Equal(routed, clientPayload) {
			t.Fatalf("routed packet mismatch: got %q, want %q", routed, clientPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client packet to be routed")
	}

	// Step B: Listener -> Client (Masked Transport Data via SendToPeer)
	serverReply := []byte("endpoint-to-client-pong-over-hp")
	if err := el.SendToPeer(peerKey, serverReply); err != nil {
		t.Fatalf("SendToPeer failed: %v", err)
	}

	replyBuf := make([]byte, 2048)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(replyBuf)
	if err != nil {
		t.Fatalf("failed to read reply from SendToPeer: %v", err)
	}

	s4 := cfg.S4
	expectedMinLen := s4 + transportDataHeaderLen + len(serverReply) + chacha20poly1305.Overhead
	if n < expectedMinLen {
		t.Fatalf("received packet too short: got %d, want >= %d", n, expectedMinLen)
	}

	datagramIn := replyBuf[:n]
	recvCip := health.NewHeaderProtectionCipher(hpKeyBytes, datagramIn[:health.HeaderCipherNonceSize])
	if recvCip == nil {
		t.Fatal("failed to create client unmask cipher")
	}
	unmaskedInHdr := make([]byte, transportDataHeaderLen)
	recvCip.XORKeyStream(unmaskedInHdr, datagramIn[s4:s4+transportDataHeaderLen])

	inMsgType := binary.LittleEndian.Uint32(unmaskedInHdr[0:4])
	if inMsgType != cfg.H4.Lo {
		t.Fatalf("inbound msgType mismatch: got %d, want %d", inMsgType, cfg.H4.Lo)
	}
	inReceiverIdx := binary.LittleEndian.Uint32(unmaskedInHdr[4:8])
	if inReceiverIdx != clientReceiverIdx {
		t.Fatalf("inbound receiverIdx mismatch: got %d, want %d", inReceiverIdx, clientReceiverIdx)
	}
	inCounter := binary.LittleEndian.Uint64(unmaskedInHdr[8:16])

	recvAEAD, err := chacha20poly1305.New(clientRecvKey)
	if err != nil {
		t.Fatalf("recvAEAD New failed: %v", err)
	}
	var recvNonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(recvNonce[4:12], inCounter)
	decryptedReply, err := recvAEAD.Open(nil, recvNonce[:], datagramIn[s4+transportDataHeaderLen:], nil)
	if err != nil {
		t.Fatalf("failed to decrypt reply from SendToPeer: %v", err)
	}
	if !bytes.Equal(decryptedReply, serverReply) {
		t.Fatalf("reply mismatch: got %q, want %q", decryptedReply, serverReply)
	}
}

func TestListener_ActiveTransportTrafficUpdatesLiveness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 5 * time.Second,
		S4:          16,
		H4:          models.DegenerateHeaderRange(health.DefaultH4),
	}

	ipam, err := NewIPAM(cfg.SubnetCIDR)
	if err != nil {
		t.Fatalf("NewIPAM failed: %v", err)
	}
	sm := NewSessionManager(nil, ipam)

	el, err := NewListener(cfg, nil, nil, ipam, sm, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	peerKey := "test-peer-key-liveness-1"
	sess, err := sm.CreateSession(ctx, "user-live-1", peerKey, "10.100.0.50", 1, "conn-live-1")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Artificially age session LastSeen by 3 seconds (older than touch throttle, within 5s IdleTimeout)
	initialLastSeen := time.Now().UTC().Add(-3 * time.Second)
	sm.SetSessionLastSeen(peerKey, initialLastSeen)

	// Set up transport keys and peer endpoint
	clientAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:48123")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	clientSendKey := make([]byte, chacha20poly1305.KeySize)
	clientRecvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range clientSendKey {
		clientSendKey[i] = byte(i + 1)
		clientRecvKey[i] = byte(i + 40)
	}
	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: clientSendKey,
		SendKey: clientRecvKey,
	})
	el.rememberPeer(clientAddr, peerKey, 10001)

	// Route channel to verify decrypted transport packet routing
	routedCh := make(chan []byte, 10)
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		routedCh <- pkt
		return nil
	})

	// Prepare transport packet
	clientAEAD, err := chacha20poly1305.New(clientSendKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}
	clientPayload := []byte("ping-transport-liveness-payload")
	var counter uint64 = 0
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	ciphertext := clientAEAD.Seal(nil, nonce[:], clientPayload, nil)

	s4Junk := make([]byte, cfg.S4)
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 10001)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)

	datagram := append(s4Junk, hdr[:]...)
	datagram = append(datagram, ciphertext...)

	// Send first transport datagram
	el.handleDatagram(ctx, datagram, clientAddr)

	select {
	case routed := <-routedCh:
		if !bytes.Equal(routed, clientPayload) {
			t.Fatalf("routed packet mismatch: got %q, want %q", routed, clientPayload)
		}
	default:
		t.Fatal("expected transport packet to be routed")
	}

	// Verify session LastSeen was refreshed by transport traffic
	currentSess, ok := sm.GetSession(peerKey)
	if !ok {
		t.Fatal("session not found in sessionMgr")
	}
	if !currentSess.LastSeen.After(initialLastSeen) {
		t.Fatalf("expected LastSeen to be updated after initial %v, got %v", initialLastSeen, currentSess.LastSeen)
	}

	// Verify throttle protection: rapid burst of datagrams
	st, ok := el.peerByAddr(clientAddr.String())
	if !ok {
		t.Fatal("peer not found in peersByAddr")
	}
	firstTouch := st.lastTouchSec.Load()
	if firstTouch == 0 {
		t.Fatal("expected lastTouchSec to be non-zero after packet touch")
	}

	// Update session LastSeen back to 1 second ago to observe whether second packet touches it
	markerTime := time.Now().UTC().Add(-1 * time.Second)
	sm.SetSessionLastSeen(peerKey, markerTime)

	// Send immediate second packet
	counter++
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)
	ciphertext2 := clientAEAD.Seal(nil, nonce[:], clientPayload, nil)
	datagram2 := append(s4Junk, hdr[:]...)
	datagram2 = append(datagram2, ciphertext2...)

	el.handleDatagram(ctx, datagram2, clientAddr)

	// Second packet should be throttled (within 2s window)
	currentSess2, _ := sm.GetSession(peerKey)
	if !currentSess2.LastSeen.Equal(markerTime) {
		t.Fatalf("expected LastSeen to remain markerTime due to throttling, got %v", currentSess2.LastSeen)
	}

	// Advance lastTouchSec past throttle window
	st.lastTouchSec.Store(time.Now().Unix() - 5)

	// Send third packet
	counter++
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)
	ciphertext3 := clientAEAD.Seal(nil, nonce[:], clientPayload, nil)
	datagram3 := append(s4Junk, hdr[:]...)
	datagram3 = append(datagram3, ciphertext3...)

	el.handleDatagram(ctx, datagram3, clientAddr)

	// Third packet should have refreshed LastSeen
	currentSess3, _ := sm.GetSession(peerKey)
	if !currentSess3.LastSeen.After(markerTime) {
		t.Fatalf("expected LastSeen to be refreshed after throttle window elapsed, got %v", currentSess3.LastSeen)
	}

	// Verify CheckTimeouts / SweepTimedOutSessions does NOT reap the active session
	timedOut, err := el.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) > 0 {
		t.Fatalf("expected active session to survive sweep, got %d reaped sessions", len(timedOut))
	}

	// Now cease traffic and simulate idle timeout: age LastSeen past IdleTimeout (5s)
	sm.SetSessionLastSeen(peerKey, time.Now().UTC().Add(-10*time.Second))
	timedOutAfterIdle, err := el.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOutAfterIdle) != 1 || timedOutAfterIdle[0].ID != sess.ID {
		t.Fatalf("expected idle session to be reaped after traffic ceased, got %+v", timedOutAfterIdle)
	}
}

func TestListener_ActiveTransportTrafficUpdatesLiveness_RouterErrorDoesNotDropLiveness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := ListenerConfig{
		ListenPort:  getFreeUDPPort(t),
		SubnetCIDR:  "10.100.0.0/24",
		MTU:         1420,
		IdleTimeout: 5 * time.Second,
		S4:          16,
		H4:          models.DegenerateHeaderRange(health.DefaultH4),
	}

	ipam, err := NewIPAM(cfg.SubnetCIDR)
	if err != nil {
		t.Fatalf("NewIPAM failed: %v", err)
	}
	sm := NewSessionManager(nil, ipam)

	el, err := NewListener(cfg, nil, nil, ipam, sm, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	peerKey := "test-peer-key-router-fail-1"
	sess, err := sm.CreateSession(ctx, "user-live-fail", peerKey, "10.100.0.51", 1, "conn-live-fail")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Artificially age session LastSeen by 3 seconds
	initialLastSeen := time.Now().UTC().Add(-3 * time.Second)
	sm.SetSessionLastSeen(peerKey, initialLastSeen)

	// Set up transport keys and peer endpoint
	clientAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:48124")
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	clientSendKey := make([]byte, chacha20poly1305.KeySize)
	clientRecvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range clientSendKey {
		clientSendKey[i] = byte(i + 2)
		clientRecvKey[i] = byte(i + 42)
	}
	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: clientSendKey,
		SendKey: clientRecvKey,
	})
	el.rememberPeer(clientAddr, peerKey, 10002)

	// Configure a router that deliberately returns an error (e.g. queue full, backpressure, or route error)
	routerCalled := false
	el.SetClientPacketRouter(func(pk string, pkt []byte) error {
		routerCalled = true
		return errors.New("simulated forwarding failure")
	})

	// Prepare transport packet
	clientAEAD, err := chacha20poly1305.New(clientSendKey)
	if err != nil {
		t.Fatalf("chacha20poly1305.New failed: %v", err)
	}
	clientPayload := []byte("ping-transport-router-error-payload")
	var counter uint64 = 0
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	ciphertext := clientAEAD.Seal(nil, nonce[:], clientPayload, nil)

	s4Junk := make([]byte, cfg.S4)
	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], cfg.H4.Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 10002)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)

	datagram := append(s4Junk, hdr[:]...)
	datagram = append(datagram, ciphertext...)

	// Send datagram into listener
	el.handleDatagram(ctx, datagram, clientAddr)

	if !routerCalled {
		t.Fatal("expected router to be invoked")
	}

	// Verify session LastSeen was refreshed despite the router error
	currentSess, ok := sm.GetSession(peerKey)
	if !ok {
		t.Fatal("session not found in sessionMgr")
	}
	if !currentSess.LastSeen.After(initialLastSeen) {
		t.Fatalf("expected LastSeen to be updated after packet, got %v (initial was %v)", currentSess.LastSeen, initialLastSeen)
	}

	// Verify SweepTimedOutSessions does NOT reap the session while packets arrive
	timedOut, err := el.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) > 0 {
		t.Fatalf("expected active session to survive sweep despite router error, got %d reaped sessions", len(timedOut))
	}

	// When genuine idleness occurs past IdleTimeout (5s), session must be reaped
	sm.SetSessionLastSeen(peerKey, time.Now().UTC().Add(-10*time.Second))
	timedOutAfterIdle, err := el.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOutAfterIdle) != 1 || timedOutAfterIdle[0].ID != sess.ID {
		t.Fatalf("expected idle session to be reaped after traffic ceased, got %+v", timedOutAfterIdle)
	}
}

func TestListener_PostSweepHook_CalledOncePerSweepCycle(t *testing.T) {
	cfg := ListenerConfig{
		ListenPort:        testFreePort(t),
		IdleTimeout:       10 * time.Millisecond,
		HeartbeatInterval: 25 * time.Millisecond,
	}
	sm := NewSessionManager(nil, nil)
	el, err := NewListener(cfg, nil, nil, nil, sm, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Seed 3 sessions and age them past IdleTimeout
	reapedSessions := make(chan string, 10)
	el.SetSessionReaperHook(func(ctx context.Context, sess *models.VPNSession) {
		reapedSessions <- sess.PeerPublicKey
	})

	var mu sync.Mutex
	postSweepCount := 0
	el.SetPostSweepHook(func(ctx context.Context) {
		mu.Lock()
		defer mu.Unlock()
		postSweepCount++
	})

	for i := 1; i <= 3; i++ {
		pKey := fmt.Sprintf("peer-post-sweep-%d", i)
		sID := fmt.Sprintf("sess-post-sweep-%d", i)
		sess, err := sm.CreateSession(ctx, "user-sweep", pKey, fmt.Sprintf("10.88.0.%d", i), 1, sID)
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		sess.LastSeen = time.Now().UTC().Add(-1 * time.Minute)
	}

	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	// Wait for the heartbeat sweep to process the timed out sessions
	deadline := time.Now().Add(2 * time.Second)
	reapedCount := 0
	for time.Now().Before(deadline) {
		select {
		case <-reapedSessions:
			reapedCount++
		default:
		}
		if reapedCount >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if reapedCount < 3 {
		t.Fatalf("expected 3 reaped sessions from reaperHook, got %d", reapedCount)
	}

	// Verify postSweepHook was called
	mu.Lock()
	count := postSweepCount
	mu.Unlock()

	if count < 1 {
		t.Fatalf("expected postSweepHook to be called at least once, got %d", count)
	}

	// Also verify that panic in postSweepHook does not crash heartbeatLoop
	el.SetPostSweepHook(func(ctx context.Context) {
		panic("post sweep hook test panic")
	})
	// Trigger invokePostSweepHook directly and ensure it recovers safely
	el.invokePostSweepHook(ctx)
}
