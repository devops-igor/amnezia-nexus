package endpoint

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestStalledHandshakeDoesNotStarveEstablishedTransport(t *testing.T) {
	ctx := context.Background()
	keysMgr := NewServerKeysManager(nil)
	_, serverPub, err := keysMgr.EnsureKeypair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port := getFreeUDPPort(t)
	el, err := NewListener(ListenerConfig{
		ListenPort: port, SubnetCIDR: "10.100.0.0/24", NumWorkers: 1,
		WorkerQueueSize: 2, HandshakeWorkers: 1, HandshakeQueueSize: 2,
	}, nil, nil, nil, nil, keysMgr)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	el.SetIncomingPeerHandler(func(context.Context, string) (*models.VPNSession, *models.BackendTunnel, error) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release // Simulate a stalled session database write.
		return nil, nil, errors.New("session write failed")
	})
	routed := make(chan string, 1)
	el.SetClientPacketRouter(func(_ string, packet []byte) error {
		routed <- string(packet)
		return nil
	})
	if err := el.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(release)
		_ = el.Stop()
	}()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	handshakeConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer handshakeConn.Close()
	initiation, _, err := health.BuildAWGInitiationPacket(serverPub[:], nil, nil, el.config.H1, el.config.S1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handshakeConn.Write(initiation); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not enter the stalled session callback")
	}
	for i := 0; i < 12; i++ {
		if _, err := handshakeConn.Write(initiation); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.After(3 * time.Second)
	for el.HandshakeQueueDrops() == 0 {
		select {
		case <-deadline:
			t.Fatal("handshake queue did not report overflow")
		case <-time.After(time.Millisecond):
		}
	}

	transportConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer transportConn.Close()
	key := make([]byte, chacha20poly1305.KeySize)
	peerKey := "existing-peer"
	const localIndex = 7342
	el.storeTransportKeys(peerKey, &TransportKeys{RecvKey: key, SendKey: key, LocalIndex: localIndex})
	pkt := buildTestTransportDatagram(t, key, nil, el.config.S4, el.config.H4.Lo, 1, []byte("established traffic"))
	binary.LittleEndian.PutUint32(pkt[el.config.S4+4:el.config.S4+8], localIndex)
	if _, err := transportConn.Write(pkt); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-routed:
		if got != "established traffic" {
			t.Fatalf("routed %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("transport stalled behind the blocked handshake")
	}
	if drops := el.PacketQueueDrops(); drops != 0 {
		t.Fatalf("transport queue dropped %d packets", drops)
	}
}
