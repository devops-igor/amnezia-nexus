package endpoint

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"golang.org/x/crypto/chacha20poly1305"
)

func buildTestTransportDatagram(tb testing.TB, clientSendKey []byte, hpKey []byte, s4 int, h4Lo uint32, counter uint64, payload []byte) []byte {
	tb.Helper()
	if h4Lo == 0 {
		h4Lo = health.DefaultH4
	}
	clientAEAD, err := chacha20poly1305.New(clientSendKey)
	if err != nil {
		tb.Fatalf("chacha20poly1305.New failed: %v", err)
	}

	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	ciphertext := clientAEAD.Seal(nil, nonce[:], payload, nil)

	s4Junk := make([]byte, s4)
	for i := range s4Junk {
		s4Junk[i] = byte(i + 7)
	}

	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], h4Lo)
	binary.LittleEndian.PutUint32(hdr[4:8], 0)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)

	if len(hpKey) == 32 && s4 >= health.HeaderCipherNonceSize {
		cip := health.NewHeaderProtectionCipher(hpKey, s4Junk[:health.HeaderCipherNonceSize])
		if cip == nil {
			tb.Fatal("failed to create client HP cipher")
		}
		maskedHdr := make([]byte, transportDataHeaderLen)
		cip.XORKeyStream(maskedHdr, hdr[:])
		copy(hdr[:], maskedHdr)
	}

	datagram := append(s4Junk, hdr[:]...)
	datagram = append(datagram, ciphertext...)
	return datagram
}

func TestListener_WorkerPoolDecoupling(t *testing.T) {
	db := setupTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenPort := getFreeUDPPort(t)
	cfg := ListenerConfig{
		ListenPort:      listenPort,
		SubnetCIDR:      "10.100.0.0/24",
		MTU:             1420,
		IdleTimeout:     1 * time.Minute,
		S4:              16,
		NumWorkers:      4,
		WorkerQueueSize: 512,
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	workers, _, qCap := el.WorkerPoolStats()
	if workers != 4 || qCap != 512 {
		t.Fatalf("expected 4 workers and 512 queue capacity, got %d workers and %d capacity", workers, qCap)
	}

	routedCh := make(chan []byte, 100)
	el.SetClientPacketRouter(func(peerKey string, packet []byte) error {
		pktCopy := make([]byte, len(packet))
		copy(pktCopy, packet)
		routedCh <- pktCopy
		return nil
	})

	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listenPort}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	peerKey := "worker-pool-test-peer-key"
	clientSendKey := make([]byte, chacha20poly1305.KeySize)
	clientRecvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range clientSendKey {
		clientSendKey[i] = byte(i + 1)
		clientRecvKey[i] = byte(i + 50)
	}

	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: clientSendKey,
		SendKey: clientRecvKey,
	})

	clientAddr, err := net.ResolveUDPAddr("udp", clientConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %v", err)
	}
	el.rememberPeer(clientAddr, peerKey, 42)

	// Send 40 packets concurrently from 4 goroutines
	const goroutines = 4
	const packetsPerGoroutine = 10
	const totalPackets = goroutines * packetsPerGoroutine

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for p := 0; p < packetsPerGoroutine; p++ {
				seq := uint64(gid*1000 + p)
				payload := []byte(fmt.Sprintf("pkt-g%d-p%d", gid, p))
				dgram := buildTestTransportDatagram(t, clientSendKey, nil, cfg.S4, cfg.H4.Lo, seq, payload)
				if _, err := clientConn.Write(dgram); err != nil {
					t.Errorf("clientConn.Write failed: %v", err)
					return
				}
			}
		}(g)
	}

	wg.Wait()

	received := make(map[string]bool)
	timeout := time.After(5 * time.Second)

	for i := 0; i < totalPackets; i++ {
		select {
		case pkt := <-routedCh:
			received[string(pkt)] = true
		case <-timeout:
			t.Fatalf("timed out waiting for routed packets: received %d of %d", len(received), totalPackets)
		}
	}

	if len(received) != totalPackets {
		t.Fatalf("expected %d unique routed packets, got %d", totalPackets, len(received))
	}
	if drops := el.PacketQueueDrops(); drops != 0 {
		t.Errorf("expected 0 packet queue drops, got %d", drops)
	}
}

func TestListener_PacketQueueDropAccounting(t *testing.T) {
	db := setupTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenPort := getFreeUDPPort(t)
	cfg := ListenerConfig{
		ListenPort:      listenPort,
		SubnetCIDR:      "10.100.0.0/24",
		MTU:             1420,
		IdleTimeout:     1 * time.Minute,
		S4:              16,
		NumWorkers:      1,
		WorkerQueueSize: 2,
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	workerEntered := make(chan struct{})
	gateCh := make(chan struct{})
	var once sync.Once
	var gateOnce sync.Once
	defer gateOnce.Do(func() { close(gateCh) })

	el.SetClientPacketRouter(func(peerKey string, packet []byte) error {
		once.Do(func() {
			close(workerEntered)
		})
		<-gateCh
		return nil
	})

	if err := el.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listenPort}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	peerKey := "drop-test-peer"
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	el.storeTransportKeys(peerKey, &TransportKeys{RecvKey: key, SendKey: key})
	clientAddr, _ := net.ResolveUDPAddr("udp", clientConn.LocalAddr().String())
	el.rememberPeer(clientAddr, peerKey, 1)

	// Packet 1: worker picks it up and blocks on gateCh
	dgram1 := buildTestTransportDatagram(t, key, nil, cfg.S4, cfg.H4.Lo, 1, []byte("blocker"))
	if _, err := clientConn.Write(dgram1); err != nil {
		t.Fatalf("Write 1 failed: %v", err)
	}

	// Wait for worker to enter router and block
	select {
	case <-workerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker to enter router")
	}

	// Packets 2, 3 fill queue (capacity 2)
	// Packets 4, 5, 6, 7, 8 must be dropped by the select default branch
	for i := 2; i <= 10; i++ {
		dgram := buildTestTransportDatagram(t, key, nil, cfg.S4, cfg.H4.Lo, uint64(i), []byte("queued-or-dropped"))
		_, _ = clientConn.Write(dgram)
		time.Sleep(2 * time.Millisecond)
	}

	// Verify drops were registered
	drops := el.PacketQueueDrops()
	if drops == 0 {
		t.Errorf("expected packet queue drops > 0, got %d", drops)
	}

	// Unblock worker
	gateOnce.Do(func() { close(gateCh) })
}

func TestListener_CleanShutdownUnblocksReadFrom(t *testing.T) {
	db := setupTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenPort := getFreeUDPPort(t)
	cfg := ListenerConfig{
		ListenPort:  listenPort,
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

	if !el.IsRunning() {
		t.Fatal("expected listener to be running")
	}

	stopDone := make(chan struct{})
	startStop := time.Now()

	go func() {
		_ = el.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		dur := time.Since(startStop)
		if dur > time.Second {
			t.Errorf("Stop took too long (%v), ReadFrom may not have been unblocked immediately", dur)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop timed out; goroutines deadlocked or ReadFrom failed to unblock")
	}

	if el.IsRunning() {
		t.Error("expected IsRunning to be false after Stop")
	}
}

func TestListener_WorkerPoolConfigDefaults(t *testing.T) {
	cfg := ListenerConfig{
		ListenPort:      51820,
		SubnetCIDR:      "10.100.0.0/24",
		NumWorkers:      0,
		WorkerQueueSize: 0,
	}

	el, err := NewListener(cfg, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewListener failed: %v", err)
	}

	workers, _, qCap := el.WorkerPoolStats()
	if workers < 4 {
		t.Errorf("expected NumWorkers >= 4 default, got %d", workers)
	}
	if qCap != 2048 {
		t.Errorf("expected WorkerQueueSize 2048 default, got %d", qCap)
	}
}

func BenchmarkListener_WorkerPoolDispatch(b *testing.B) {
	db := setupTestDB(b)
	ctx := context.Background()

	listenPort := getFreeUDPPort(b)
	cfg := ListenerConfig{
		ListenPort:      listenPort,
		SubnetCIDR:      "10.100.0.0/24",
		MTU:             1420,
		IdleTimeout:     1 * time.Minute,
		S4:              16,
		NumWorkers:      4,
		WorkerQueueSize: 4096,
	}

	el, err := NewListener(cfg, db, nil, nil, nil, nil)
	if err != nil {
		b.Fatalf("NewListener failed: %v", err)
	}

	routed := make(chan struct{}, 4096)
	el.SetClientPacketRouter(func(peerKey string, packet []byte) error {
		select {
		case routed <- struct{}{}:
		default:
		}
		return nil
	})

	if err := el.Start(ctx); err != nil {
		b.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = el.Stop() }()

	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listenPort}
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		b.Fatalf("DialUDP failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	peerKey := "bench-peer-key"
	clientSendKey := make([]byte, chacha20poly1305.KeySize)
	clientRecvKey := make([]byte, chacha20poly1305.KeySize)
	for i := range clientSendKey {
		clientSendKey[i] = byte(i + 1)
		clientRecvKey[i] = byte(i + 50)
	}
	el.storeTransportKeys(peerKey, &TransportKeys{
		RecvKey: clientSendKey,
		SendKey: clientRecvKey,
	})

	clientAddr, _ := net.ResolveUDPAddr("udp", clientConn.LocalAddr().String())
	el.rememberPeer(clientAddr, peerKey, 1)

	payload := []byte("bench-packet-payload-for-upstream-pipeline")
	dgram := buildTestTransportDatagram(b, clientSendKey, nil, cfg.S4, cfg.H4.Lo, 1, payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = clientConn.Write(dgram)
		<-routed
	}
	b.StopTimer()
}
