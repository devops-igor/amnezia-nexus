package vpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// The client is the upstream implementation, including its timers, Noise
// handshake, header protection, and TUN packet handling.
func upstreamRekeyClient(t *testing.T, privateKey, portalPublicKey, endpoint string, cfg *models.VPNConfig, hpKey []byte) (*device.Device, *tuntest.ChannelTUN, *device.Peer) {
	t.Helper()
	priv, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(portalPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	virtual := tuntest.NewChannelTUN()
	dev := device.NewDevice(virtual.TUN(), tunnel.NewTunedBind(conn.NewDefaultBind(), tunnel.DefaultUDPSocketBufferSize), device.NewLogger(device.LogLevelSilent, "upstream-rekey"))
	t.Cleanup(dev.Close)
	config := fmt.Sprintf("private_key=%s\nlisten_port=0\ns1=%d\ns2=%d\ns3=%d\ns4=%d\nh1=%s\nh2=%s\nh3=%s\nh4=%s\nheader_protection_key=%s\nrekey_timeout=1\nrekey_after_time=120\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\n",
		hex.EncodeToString(priv), cfg.S1, cfg.S2, cfg.S3, cfg.S4, cfg.H1, cfg.H2, cfg.H3, cfg.H4, hex.EncodeToString(hpKey), hex.EncodeToString(pub), endpoint)
	if err := dev.IpcSet(config); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	var key device.NoisePublicKey
	copy(key[:], pub)
	peer := dev.LookupPeer(key)
	if peer == nil {
		t.Fatal("upstream peer was not configured")
	}
	return dev, virtual, peer
}

func rekeyTestUDPPacket(src, dst net.IP, sequence uint32) []byte {
	pkt := make([]byte, 32)
	pkt[0], pkt[8], pkt[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[20:22], 40000)
	binary.BigEndian.PutUint16(pkt[22:24], 40001)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(len(pkt)-20))
	binary.BigEndian.PutUint32(pkt[28:], sequence)
	return pkt
}

// The backend consumes packets from the actual forwarder backend pump and
// returns them through its normal client queue, preserving packet bytes.
type rekeyEchoBackend struct {
	forwarder *forwarder.Forwarder
	backendID int64
	received  atomic.Uint64
}

func (b *rekeyEchoBackend) Write(pkt []byte) (int, error) {
	if len(pkt) < 32 {
		return 0, fmt.Errorf("short backend packet")
	}
	b.received.Add(1)
	reply := append([]byte(nil), pkt...)
	copy(reply[12:16], pkt[16:20])
	copy(reply[16:20], pkt[12:16])
	if err := b.forwarder.RouteBackendToClient(b.backendID, reply, net.IP(reply[16:20]).String()); err != nil {
		return 0, err
	}
	return len(pkt), nil
}
func (*rekeyEchoBackend) Read([]byte) (int, error) { return 0, nil }
func (*rekeyEchoBackend) Close() error             { return nil }

// The UDP proxy drops only an upstream responder handshake response; K1
// transport packets continue along the same path in both directions.
type rekeyResponseProxy struct {
	conn     *net.UDPConn
	dropNext atomic.Bool
	dropped  chan struct{}
}

func startRekeyResponseProxy(t *testing.T, server *net.UDPAddr, hpKey []byte, cfg *models.VPNConfig) *rekeyResponseProxy {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &rekeyResponseProxy{conn: c, dropped: make(chan struct{}, 1)}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 4096)
		var client *net.UDPAddr
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			if from.Port != server.Port {
				client = from
				_, _ = c.WriteToUDP(packet, server)
				continue
			}
			if client == nil {
				continue
			}
			if p.dropNext.Load() && cfg.S2 >= health.HeaderCipherNonceSize && n >= cfg.S2+4 {
				cipher := health.NewHeaderProtectionCipher(hpKey, packet[:health.HeaderCipherNonceSize])
				var header [4]byte
				cipher.XORKeyStream(header[:], packet[cfg.S2:cfg.S2+4])
				if cfg.H2.Contains(binary.LittleEndian.Uint32(header[:])) && p.dropNext.CompareAndSwap(true, false) {
					select {
					case p.dropped <- struct{}{}:
					default:
					}
					continue
				}
			}
			_, _ = c.WriteToUDP(packet, client)
		}
	}()
	return p
}

func TestIssue331UpstreamClientNexusBackendLostResponseAndRekeys(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	db := setupTestDB(t)
	svc, _, _, userID, _ := setupTestVPNService(t, db)
	serverPub, _, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "echo-backend", Host: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := svc.pool.AddTunnel(ctx, serverID, "127.0.0.1:1", serverPub)
	if err != nil {
		t.Fatal(err)
	}
	echo := &rekeyEchoBackend{forwarder: svc.forwarder, backendID: backend.ID}
	svc.forwarder.AttachBackendDevice(backend.ID, echo)
	svc.forwarder.Start(ctx)
	svc.forwarder.StartPumps(ctx)
	t.Cleanup(func() { _ = svc.forwarder.Stop() })

	clientPub, clientPriv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{UserID: userID, Protocol: "awg", ClientID: clientPub,
		ClientParams: map[string]any{"assigned_ip": "10.100.0.2"}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.endpoint.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.endpoint.Stop() })
	listen := svc.endpoint.GetListenAddr().(*net.UDPAddr)
	hpKey, err := health.DecodeKey(svc.cfg.HeaderProtectionKey)
	if err != nil {
		t.Fatal(err)
	}
	proxy := startRekeyResponseProxy(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listen.Port}, hpKey, svc.cfg)
	_, clientTUN, peer := upstreamRekeyClient(t, clientPriv, svc.portalPubKey, proxy.conn.LocalAddr().String(), svc.cfg, hpKey)
	clientIP, backendIP := net.IPv4(10, 100, 0, 2), net.IPv4(10, 200, 0, 1)

	roundTrip := func(seq uint32, budget time.Duration) {
		t.Helper()
		pkt := rekeyTestUDPPacket(clientIP, backendIP, seq)
		deadline := time.Now().Add(budget)
		for time.Now().Before(deadline) {
			select {
			case clientTUN.Outbound <- pkt:
			case <-time.After(time.Second):
				t.Fatal("upstream TUN write stalled")
			}
			select {
			case reply := <-clientTUN.Inbound:
				if len(reply) == len(pkt) && bytes.Equal(reply[12:16], pkt[16:20]) && bytes.Equal(reply[16:20], pkt[12:16]) && bytes.Equal(reply[28:], pkt[28:]) {
					return
				}
				t.Fatalf("unexpected backend reply for seq=%d: %x", seq, reply)
			case <-time.After(200 * time.Millisecond):
			}
		}
		_, current, next := svc.endpoint.PeerKeypairStateForTest(clientPub)
		rx, tx, routes := svc.forwarder.GetStats()
		t.Fatalf("no upstream/backend roundtrip seq=%d current=%v next=%v routes=%d rx=%d tx=%d decrypt_failures=%d", seq, current != nil, next != nil, routes, rx, tx, svc.endpoint.TransportDecryptionFailures())
	}

	// The first TUN packet can trigger K1 and precede its confirmation; retry
	// only during initial admission. Once K1 is confirmed, all sends are exact.
	roundTrip(1, 5*time.Second)
	initial, ok := svc.sessionMgr.GetSessionSnapshotByPeer(clientPub)
	if !ok || initial.AssignedIP != clientIP.String() || initial.BackendTunnelID != backend.ID {
		t.Fatalf("wrong admission: %+v", initial)
	}
	registration := svc.forwarder.PeerRegistration(clientPub)
	oldCurrent, _ := svc.endpoint.PeerKeypairsForTest(clientPub)
	if oldCurrent == nil {
		t.Fatal("K1 was not confirmed by upstream transport")
	}

	// A real upstream rekey response is lost. K1 must carry both directions.
	time.Sleep(1100 * time.Millisecond)
	proxy.dropNext.Store(true)
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proxy.dropped:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream rekey response was not observed")
	}
	_, current, next := svc.endpoint.PeerKeypairStateForTest(clientPub)
	if current == nil || next == nil || current.Generation != oldCurrent.Generation {
		t.Fatalf("lost response changed K1: current_present=%v next_present=%v", current != nil, next != nil)
	}
	for i := uint32(2); i < 7; i++ {
		roundTrip(i, time.Second)
	}

	// Retry from the upstream client, and continue VoIP-sized UDP traffic
	// throughout promotion. Each response traverses the real front socket.
	time.Sleep(1100 * time.Millisecond)
	if err := peer.SendHandshakeInitiation(true); err != nil {
		t.Fatal(err)
	}
	for i := uint32(7); i < 17; i++ {
		roundTrip(i, time.Second)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		_, current, next = svc.endpoint.PeerKeypairStateForTest(clientPub)
		if current != nil && current.Generation > oldCurrent.Generation && next == nil {
			break
		}
		roundTrip(17, time.Second)
	}
	_, current, next = svc.endpoint.PeerKeypairStateForTest(clientPub)
	if current == nil || current.Generation <= oldCurrent.Generation || next != nil {
		t.Fatalf("upstream retry did not confirm K2: current_present=%v next_present=%v", current != nil, next != nil)
	}
	for i := uint32(18); i < 23; i++ {
		roundTrip(i, time.Second)
	}
	confirmedGeneration := current.Generation
	time.Sleep(1100 * time.Millisecond)
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatal(err)
	}
	for i := uint32(23); i < 33; i++ {
		roundTrip(i, time.Second)
	}
	for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		_, current, next = svc.endpoint.PeerKeypairStateForTest(clientPub)
		if current != nil && current.Generation > confirmedGeneration && next == nil {
			break
		}
		roundTrip(33, time.Second)
		_ = peer.SendHandshakeInitiation(true)
	}
	_, current, next = svc.endpoint.PeerKeypairStateForTest(clientPub)
	if current == nil || current.Generation <= confirmedGeneration || next != nil {
		t.Fatalf("second upstream rekey did not confirm: current_generation=%d next_present=%v", func() uint64 {
			if current != nil {
				return current.Generation
			}
			return 0
		}(), next != nil)
	}
	after, ok := svc.sessionMgr.GetSessionSnapshotByPeer(clientPub)
	if !ok || after.ID != initial.ID || after.BackendTunnelID != backend.ID || after.AssignedIP != initial.AssignedIP ||
		svc.forwarder.RouteSessionID(clientPub) != initial.ID || svc.forwarder.PeerRegistration(clientPub) != registration {
		t.Fatalf("rekey changed logical route/session: before=%+v after=%+v", initial, after)
	}
	if echo.received.Load() < 31 {
		t.Fatalf("backend received only %d packets", echo.received.Load())
	}
	if now, err := svc.pool.GetTunnelByID(backend.ID); err != nil || now.ActiveConnections != 1 {
		t.Fatalf("backend counter drift: %+v %v", now, err)
	}
}
