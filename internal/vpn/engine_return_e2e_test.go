package vpn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

func returnEchoServers(t *testing.T, stack *netstack.Net, addr netip.Addr, backendMarker byte) {
	t.Helper()
	tcpListener, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(addr, 40001))
	if err != nil {
		t.Fatal(err)
	}
	udpListener, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(addr, 40001))
	if err != nil {
		t.Fatal(err)
	}
	doneTCP, doneUDP := make(chan struct{}), make(chan struct{})
	var activeMu sync.Mutex
	var active net.Conn
	closing := false
	go func() {
		defer close(doneTCP)
		c, err := tcpListener.Accept()
		if err != nil {
			return
		}
		activeMu.Lock()
		if closing {
			activeMu.Unlock()
			_ = c.Close()
			return
		}
		active = c
		activeMu.Unlock()
		defer c.Close()
		if _, err := c.Write([]byte{backendMarker}); err != nil {
			return
		}
		_, _ = io.Copy(c, c)
	}()
	go func() {
		defer close(doneUDP)
		buf := make([]byte, 2048)
		for {
			n, remote, err := udpListener.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err = udpListener.WriteTo(append([]byte{backendMarker}, buf[:n]...), remote); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = tcpListener.Close()
		_ = udpListener.Close()
		activeMu.Lock()
		closing = true
		if active != nil {
			_ = active.Close()
		}
		activeMu.Unlock()
		<-doneTCP
		<-doneUDP
	})
}

type returnStreamClient struct {
	peer      enginePeer
	dev       *device.Device
	stack     *netstack.Net
	tcp       net.Conn
	udp       net.Conn
	session   models.VPNSession
	handshake time.Time
	rekeys    int
	endpoint  string
}

// LastHandshakeTime returns the timestamp of the last successful handshake recorded by the client device.
func (c *returnStreamClient) LastHandshakeTime() time.Time {
	raw, err := c.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && k == "last_handshake_time_sec" {
			sec, _ := strconv.ParseInt(v, 10, 64)
			if sec > 0 {
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}

func newReturnStreamClient(t *testing.T, peer enginePeer, saved string, destination netip.Addr, backendMarker byte) *returnStreamClient {
	t.Helper()
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(peer.assignedIP)}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "return-client"))
	t.Cleanup(dev.Close)
	// Test-only supported upstream timing configuration. Every subsequent
	// handshake is initiated naturally by upstream while application traffic
	// continues; no forced handshake, device restart or crypto-state access.
	uapi := configToUAPI(t, saved)
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal("client configuration rejected")
	}
	if err := dev.IpcSet("rekey_after_time=2\nrekey_timeout=1\n"); err != nil {
		t.Fatal("test timing configuration rejected")
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), engineHandshakeTimeout)
	defer cancel()
	tcpConn, err := stack.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(destination, 40001))
	if err != nil {
		t.Fatalf("TCP over upstream return path: %v", err)
	}
	t.Cleanup(func() { _ = tcpConn.Close() })
	_ = tcpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	marker := make([]byte, 1)
	if _, err := io.ReadFull(tcpConn, marker); err != nil || marker[0] != backendMarker {
		t.Fatalf("TCP reached wrong backend: marker=%v err=%v", marker, err)
	}
	udpConn, err := stack.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(destination, 40001))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	return &returnStreamClient{peer: peer, dev: dev, stack: stack, tcp: tcpConn, udp: udpConn}
}

func returnExchange(t *testing.T, c net.Conn, payload []byte, datagram bool, backendMarker byte) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := c.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("application write: n=%d err=%v", n, err)
	}
	want := payload
	if datagram {
		want = append([]byte{backendMarker}, payload...)
	}
	buf := make([]byte, len(want))
	if datagram {
		n, err = c.Read(buf)
	} else {
		n, err = io.ReadFull(c, buf)
	}
	if err != nil || n != len(want) || !bytes.Equal(buf, want) {
		t.Fatalf("application reply: n=%d err=%v identical=%v", n, err, bytes.Equal(buf, want))
	}
}

// TestUpstreamReturnTCPUDPRekeysAndRoaming keeps the SAME TCP connections
// alive and exchanges sustained UDP on two peers assigned to separate
// backends. It observes two natural rekeys for EACH peer plus an outer UDP
// socket/endpoint change, without changing any Nexus routing session.
func TestUpstreamReturnTCPUDPRekeysAndRoaming(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peerA, savedA := newEnginePeer(t, svc, db, "return-a")
	peerB, savedB := newEnginePeer(t, svc, db, "return-b")
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	backends := svc.pool.ListTunnels()
	sort.Slice(backends, func(i, j int) bool { return backends[i].ID < backends[j].ID })
	if len(backends) != 2 {
		t.Fatalf("backends=%d", len(backends))
	}
	destination := netip.MustParseAddr("198.51.100.99")
	for i, backend := range backends {
		vt, stack, err := netstack.CreateNetTUN([]netip.Addr{destination}, nil, 1280)
		if err != nil {
			t.Fatal(err)
		}
		adapter := &returnStackDevice{tun: vt}
		done := make(chan struct{})
		svc.forwarder.AttachBackendDevice(backend.ID, adapter)
		go func() { defer close(done); svc.pumpBackendReturns(backend.ID, backend.ServerID, adapter) }()
		t.Cleanup(func() { _ = adapter.Close(); <-done })
		returnEchoServers(t, stack, destination, byte(i))
		peer := peerA
		if i == 1 {
			peer = peerB
		}
		svc.stickyMgr.AssignPeerAffinity(peer.publicKey, backend.ID)
	}
	svc.forwarder.StartPumps(t.Context())
	t.Cleanup(svc.forwarder.StopPumps)
	engine, err := svc.NewIngressEngine(t.Context(), "return-portal", []clientawg.Peer{
		{PublicKey: peerA.publicKey, AllowedIP: netip.PrefixFrom(netip.MustParseAddr(peerA.assignedIP), 32)},
		{PublicKey: peerB.publicKey, AllowedIP: netip.PrefixFrom(netip.MustParseAddr(peerB.assignedIP), 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	clients := []*returnStreamClient{
		newReturnStreamClient(t, peerA, savedA, destination, 0),
		newReturnStreamClient(t, peerB, savedB, destination, 1),
	}
	for i, c := range clients {
		var ok bool
		c.session, ok = svc.sessionMgr.GetSessionSnapshotByPeer(c.peer.publicKey)
		if !ok || c.session.BackendTunnelID != backends[i].ID {
			t.Fatal("unexpected initial session/backend")
		}
	}
	registrations := svc.freshSessionRegistrations.Load()
	deadline := time.Now().Add(30 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	roamed, observedRoam := false, false
	for iteration := 0; ; iteration++ {
		for i, c := range clients {
			payload := []byte(fmt.Sprintf("peer-%d-sequence-%08d", i, iteration))
			returnExchange(t, c.tcp, payload, false, byte(i))
			returnExchange(t, c.udp, payload, true, byte(i))
		}
		status, err := engine.Portal().Status()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range clients {
			for _, p := range status.Peers {
				if p.PublicKey != c.peer.publicKey {
					continue
				}
				if !c.handshake.IsZero() && p.LastHandshake.After(c.handshake) {
					c.rekeys++
				}
				c.handshake = p.LastHandshake
				if c.endpoint == "" {
					c.endpoint = p.Endpoint
				}
				if c == clients[0] && roamed && p.Endpoint != c.endpoint {
					observedRoam = true
				}
			}
			current, ok := svc.sessionMgr.GetSessionSnapshotByPeer(c.peer.publicKey)
			if !ok || current.ID != c.session.ID || current.BackendTunnelID != c.session.BackendTunnelID || svc.forwarder.RouteSessionID(c.peer.publicKey) != c.session.ID {
				t.Fatal("Nexus routing session changed across active rekeys/roaming")
			}
		}
		if !roamed && clients[0].rekeys >= 1 {
			// Rebinding only the client's UDP socket simulates a NAT mapping
			// change while retaining its device, TCP connection and transport keys.
			if err := clients[0].dev.IpcSet("listen_port=0\n"); err != nil {
				t.Fatal(err)
			}
			roamed = true
		}
		if observedRoam && clients[0].rekeys >= 2 && clients[1].rekeys >= 2 {
			if svc.freshSessionRegistrations.Load() != registrations {
				t.Fatal("rekey recreated a backend session")
			}
			for _, backend := range svc.pool.ListTunnels() {
				if backend.ActiveConnections != 1 {
					t.Fatalf("backend count=%d, want 1", backend.ActiveConnections)
				}
			}
			t.Logf("same TCP connections and UDP flows survived %d/%d natural rekeys and endpoint roaming (%d exchanges per flow)", clients[0].rekeys, clients[1].rekeys, iteration+1)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("natural rekeys/roam not observed: rekeys=%d/%d roam=%v", clients[0].rekeys, clients[1].rekeys, observedRoam)
		}
		select {
		case <-ticker.C:
		case <-t.Context().Done():
			t.Fatal("test canceled")
		}
	}
}
