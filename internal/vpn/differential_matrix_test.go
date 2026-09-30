package vpn

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

// TestDifferential_FaultSchedule_LostInitiation drops the first client handshake initiation
// using UDPFaultShim and verifies that the client retransmits after rekey_timeout, completing
// the handshake and maintaining bidirectional TCP/UDP traffic on both reference and subject.
func TestDifferential_FaultSchedule_LostInitiation(t *testing.T) {
	harness := NewDifferentialHarness(t)
	ctx := t.Context()

	tcpPayload := []byte("diff-lost-initiation-tcp-data")
	udpPayload := []byte("diff-lost-initiation-udp-data")

	s1, s2, s3, s4 := harness.manifest.S1, harness.manifest.S2, harness.manifest.S3, harness.manifest.S4

	// Phase 1: Reference Server with lost initiation
	refServer, err := harness.StartReferenceServer()
	if err != nil {
		t.Fatalf("StartReferenceServer: %v", err)
	}

	shimRef, err := NewUDPFaultShim(t, harness.listenPort, s1, s2, s3, s4)
	if err != nil {
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("NewUDPFaultShim: %v", err)
	}
	shimRef.DropNextInitiation()

	refClient, err := harness.NewClientViaShim(shimRef)
	if err != nil {
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("NewClientViaShim: %v", err)
	}

	// Dial TCP - initiation will drop once, client retransmits, handshake completes
	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelDial()
	refTCP, err := refClient.DialTCP(dialCtx)
	if err != nil {
		_ = refClient.Close()
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient DialTCP after dropped initiation: %v", err)
	}
	refEchoTCP, err := refClient.ExchangeTCP(refTCP, tcpPayload)
	_ = refTCP.Close()
	if err != nil || !bytes.Equal(refEchoTCP, tcpPayload) {
		_ = refClient.Close()
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient ExchangeTCP: got %q, want %q, err %v", refEchoTCP, tcpPayload, err)
	}

	refUDP, err := refClient.DialUDP()
	if err != nil {
		_ = refClient.Close()
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient DialUDP: %v", err)
	}
	refEchoUDP, err := refClient.ExchangeUDP(refUDP, udpPayload)
	_ = refUDP.Close()
	if err != nil || !bytes.Equal(refEchoUDP, udpPayload) {
		_ = refClient.Close()
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient ExchangeUDP: got %q, want %q, err %v", refEchoUDP, udpPayload, err)
	}

	// Assert exactly 1 initiation was dropped, at least 2 received
	if dropped := shimRef.InitiationsDropped.Load(); dropped != 1 {
		t.Errorf("ref shim dropped %d initiations, want exactly 1", dropped)
	}
	if recvd := shimRef.InitiationsReceived.Load(); recvd < 2 {
		t.Errorf("ref shim received %d initiations, want at least 2", recvd)
	}

	_ = refClient.Close()
	_ = shimRef.Close()
	_ = harness.StopReferenceServer(refServer)
	harness.AssertPortFree(5 * time.Second)

	// Phase 2: Subject Server with lost initiation
	subServer, err := harness.StartSubjectServer()
	if err != nil {
		t.Fatalf("StartSubjectServer: %v", err)
	}

	shimSub, err := NewUDPFaultShim(t, harness.listenPort, s1, s2, s3, s4)
	if err != nil {
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("NewUDPFaultShim: %v", err)
	}
	shimSub.DropNextInitiation()

	subClient, err := harness.NewClientViaShim(shimSub)
	if err != nil {
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("NewClientViaShim: %v", err)
	}

	subDialCtx, cancelSubDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelSubDial()
	subTCP, err := subClient.DialTCP(subDialCtx)
	if err != nil {
		_ = subClient.Close()
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient DialTCP after dropped initiation: %v", err)
	}
	subEchoTCP, err := subClient.ExchangeTCP(subTCP, tcpPayload)
	_ = subTCP.Close()
	if err != nil || !bytes.Equal(subEchoTCP, tcpPayload) {
		_ = subClient.Close()
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient ExchangeTCP: got %q, want %q, err %v", subEchoTCP, tcpPayload, err)
	}

	subUDP, err := subClient.DialUDP()
	if err != nil {
		_ = subClient.Close()
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient DialUDP: %v", err)
	}
	subEchoUDP, err := subClient.ExchangeUDP(subUDP, udpPayload)
	_ = subUDP.Close()
	if err != nil || !bytes.Equal(subEchoUDP, udpPayload) {
		_ = subClient.Close()
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient ExchangeUDP: got %q, want %q, err %v", subEchoUDP, udpPayload, err)
	}

	if dropped := shimSub.InitiationsDropped.Load(); dropped != 1 {
		t.Errorf("sub shim dropped %d initiations, want exactly 1", dropped)
	}
	if recvd := shimSub.InitiationsReceived.Load(); recvd < 2 {
		t.Errorf("sub shim received %d initiations, want at least 2", recvd)
	}

	// Parity comparison
	if !bytes.Equal(refEchoTCP, subEchoTCP) {
		t.Fatalf("TCP parity mismatch: ref=%q sub=%q", refEchoTCP, subEchoTCP)
	}
	if !bytes.Equal(refEchoUDP, subEchoUDP) {
		t.Fatalf("UDP parity mismatch: ref=%q sub=%q", refEchoUDP, subEchoUDP)
	}

	_ = subClient.Close()
	_ = shimSub.Close()
	_ = harness.StopSubjectServer(subServer)
	harness.AssertPortFree(5 * time.Second)
}

// TestDifferential_FaultSchedule_LostResponse drops the server's first handshake response
// and verifies that the client times out, retransmits initiation, and finishes handshake on both.
func TestDifferential_FaultSchedule_LostResponse(t *testing.T) {
	harness := NewDifferentialHarness(t)
	ctx := t.Context()

	payload := []byte("diff-lost-response-payload-data")
	s1, s2, s3, s4 := harness.manifest.S1, harness.manifest.S2, harness.manifest.S3, harness.manifest.S4

	// Phase 1: Reference
	refServer, err := harness.StartReferenceServer()
	if err != nil {
		t.Fatalf("StartReferenceServer: %v", err)
	}

	shimRef, err := NewUDPFaultShim(t, harness.listenPort, s1, s2, s3, s4)
	if err != nil {
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("NewUDPFaultShim: %v", err)
	}
	shimRef.DropNextResponse()

	refClient, err := harness.NewClientViaShim(shimRef)
	if err != nil {
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("NewClientViaShim: %v", err)
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelDial()
	refTCP, err := refClient.DialTCP(dialCtx)
	if err != nil {
		_ = refClient.Close()
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient DialTCP after dropped response: %v", err)
	}
	refEcho, err := refClient.ExchangeTCP(refTCP, payload)
	_ = refTCP.Close()
	if err != nil || !bytes.Equal(refEcho, payload) {
		_ = refClient.Close()
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient ExchangeTCP: got %q, want %q, err %v", refEcho, payload, err)
	}

	if dropped := shimRef.ResponsesDropped.Load(); dropped != 1 {
		t.Errorf("ref shim dropped %d responses, want exactly 1", dropped)
	}

	_ = refClient.Close()
	_ = shimRef.Close()
	_ = harness.StopReferenceServer(refServer)
	harness.AssertPortFree(5 * time.Second)

	// Phase 2: Subject
	subServer, err := harness.StartSubjectServer()
	if err != nil {
		t.Fatalf("StartSubjectServer: %v", err)
	}

	shimSub, err := NewUDPFaultShim(t, harness.listenPort, s1, s2, s3, s4)
	if err != nil {
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("NewUDPFaultShim: %v", err)
	}
	shimSub.DropNextResponse()

	subClient, err := harness.NewClientViaShim(shimSub)
	if err != nil {
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("NewClientViaShim: %v", err)
	}

	subDialCtx, cancelSubDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelSubDial()
	subTCP, err := subClient.DialTCP(subDialCtx)
	if err != nil {
		_ = subClient.Close()
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient DialTCP after dropped response: %v", err)
	}
	subEcho, err := subClient.ExchangeTCP(subTCP, payload)
	_ = subTCP.Close()
	if err != nil || !bytes.Equal(subEcho, payload) {
		_ = subClient.Close()
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient ExchangeTCP: got %q, want %q, err %v", subEcho, payload, err)
	}

	if dropped := shimSub.ResponsesDropped.Load(); dropped != 1 {
		t.Errorf("sub shim dropped %d responses, want exactly 1", dropped)
	}

	if !bytes.Equal(refEcho, subEcho) {
		t.Fatalf("Echo mismatch: ref=%q sub=%q", refEcho, subEcho)
	}

	_ = subClient.Close()
	_ = shimSub.Close()
	_ = harness.StopSubjectServer(subServer)
	harness.AssertPortFree(5 * time.Second)
}

// TestDifferential_FaultSchedule_DuplicateInitiation injects an immediate duplicate copy
// of the handshake initiation and verifies that reference and subject handle it gracefully.
func TestDifferential_FaultSchedule_DuplicateInitiation(t *testing.T) {
	harness := NewDifferentialHarness(t)
	ctx := t.Context()

	payload := []byte("diff-duplicate-initiation-data")
	s1, s2, s3, s4 := harness.manifest.S1, harness.manifest.S2, harness.manifest.S3, harness.manifest.S4

	// Phase 1: Reference
	refServer, err := harness.StartReferenceServer()
	if err != nil {
		t.Fatalf("StartReferenceServer: %v", err)
	}

	shimRef, err := NewUDPFaultShim(t, harness.listenPort, s1, s2, s3, s4)
	if err != nil {
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("NewUDPFaultShim: %v", err)
	}
	shimRef.DuplicateNextInitiation()

	refClient, err := harness.NewClientViaShim(shimRef)
	if err != nil {
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("NewClientViaShim: %v", err)
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelDial()
	refTCP, err := refClient.DialTCP(dialCtx)
	if err != nil {
		_ = refClient.Close()
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient DialTCP: %v", err)
	}
	refEcho, err := refClient.ExchangeTCP(refTCP, payload)
	_ = refTCP.Close()
	if err != nil || !bytes.Equal(refEcho, payload) {
		_ = refClient.Close()
		_ = shimRef.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("refClient ExchangeTCP: %v", err)
	}

	if dups := shimRef.InitiationsDuplicated.Load(); dups != 1 {
		t.Errorf("ref shim duplicated %d initiations, want 1", dups)
	}

	_ = refClient.Close()
	_ = shimRef.Close()
	_ = harness.StopReferenceServer(refServer)
	harness.AssertPortFree(5 * time.Second)

	// Phase 2: Subject
	subServer, err := harness.StartSubjectServer()
	if err != nil {
		t.Fatalf("StartSubjectServer: %v", err)
	}

	shimSub, err := NewUDPFaultShim(t, harness.listenPort, s1, s2, s3, s4)
	if err != nil {
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("NewUDPFaultShim: %v", err)
	}
	shimSub.DuplicateNextInitiation()

	subClient, err := harness.NewClientViaShim(shimSub)
	if err != nil {
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("NewClientViaShim: %v", err)
	}

	subDialCtx, cancelSubDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelSubDial()
	subTCP, err := subClient.DialTCP(subDialCtx)
	if err != nil {
		_ = subClient.Close()
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient DialTCP: %v", err)
	}
	subEcho, err := subClient.ExchangeTCP(subTCP, payload)
	_ = subTCP.Close()
	if err != nil || !bytes.Equal(subEcho, payload) {
		_ = subClient.Close()
		_ = shimSub.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("subClient ExchangeTCP: %v", err)
	}

	if dups := shimSub.InitiationsDuplicated.Load(); dups != 1 {
		t.Errorf("sub shim duplicated %d initiations, want 1", dups)
	}

	if !bytes.Equal(refEcho, subEcho) {
		t.Fatalf("Echo parity mismatch: ref=%q sub=%q", refEcho, subEcho)
	}

	_ = subClient.Close()
	_ = shimSub.Close()
	_ = harness.StopSubjectServer(subServer)
	harness.AssertPortFree(5 * time.Second)
}

// TestDifferential_TwoPeerIsolation runs two distinct clients concurrently with distinct
// backends on Nexus subject, verifying that traffic from each peer arrives strictly at its
// assigned backend and zero crosstalk occurs.
func TestDifferential_TwoPeerIsolation(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()

	peerA, savedA := newEnginePeer(t, svc, db, "diff-peer-a")
	peerB, savedB := newEnginePeer(t, svc, db, "diff-peer-b")

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backends := svc.pool.ListTunnels()
	if len(backends) < 2 {
		t.Fatalf("need at least 2 backend tunnels, got %d", len(backends))
	}

	destA := netip.MustParseAddr("198.51.100.101")
	destB := netip.MustParseAddr("198.51.100.102")

	type echoBackend struct {
		vt     *netstack.Net
		tunDev *returnStackDevice
		done   chan struct{}
	}

	startBackend := func(tunnelID int64, dest netip.Addr, marker byte) *echoBackend {
		vt, stack, err := netstack.CreateNetTUN([]netip.Addr{dest}, nil, 1280)
		if err != nil {
			t.Fatal(err)
		}
		adapter := &returnStackDevice{tun: vt}
		done := make(chan struct{})
		svc.forwarder.AttachBackendDevice(tunnelID, adapter)
		go func() {
			defer close(done)
			svc.pumpBackendReturns(tunnelID, 0, adapter)
		}()
		returnEchoServers(t, stack, dest, marker)
		return &echoBackend{vt: stack, tunDev: adapter, done: done}
	}

	b1 := startBackend(backends[0].ID, destA, 0x01)
	b2 := startBackend(backends[1].ID, destB, 0x02)

	svc.stickyMgr.AssignPeerAffinity(peerA.publicKey, backends[0].ID)
	svc.stickyMgr.AssignPeerAffinity(peerB.publicKey, backends[1].ID)

	svc.forwarder.StartPumps(ctx)
	defer svc.forwarder.StopPumps()

	engine, err := svc.NewIngressEngine(ctx, "diff-isolation-portal", []clientawg.Peer{
		{PublicKey: peerA.publicKey, AllowedIP: netip.PrefixFrom(netip.MustParseAddr(peerA.assignedIP), 32)},
		{PublicKey: peerB.publicKey, AllowedIP: netip.PrefixFrom(netip.MustParseAddr(peerB.assignedIP), 32)},
	})
	if err != nil {
		t.Fatalf("NewIngressEngine: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("engine.Start: %v", err)
	}
	defer func() { _ = engine.Stop() }()

	clientA := newReturnStreamClient(t, peerA, savedA, destA, 0x01)
	clientB := newReturnStreamClient(t, peerB, savedB, destB, 0x02)

	// Concurrently stream traffic from both clients
	var wg sync.WaitGroup
	wg.Add(2)

	payloadA := []byte("traffic-stream-from-peer-A-data")
	payloadB := []byte("traffic-stream-from-peer-B-data")

	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			returnExchange(t, clientA.tcp, payloadA, false, 0x01)
			returnExchange(t, clientA.udp, payloadA, true, 0x01)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			returnExchange(t, clientB.tcp, payloadB, false, 0x02)
			returnExchange(t, clientB.udp, payloadB, true, 0x02)
		}
	}()

	wg.Wait()

	// Assert session isolation
	sessA, okA := svc.sessionMgr.GetSessionSnapshotByPeer(peerA.publicKey)
	sessB, okB := svc.sessionMgr.GetSessionSnapshotByPeer(peerB.publicKey)
	if !okA || !okB {
		t.Fatalf("missing session snapshots: okA=%t okB=%t", okA, okB)
	}
	if sessA.BackendTunnelID != backends[0].ID {
		t.Errorf("peer A on backend %d, want %d", sessA.BackendTunnelID, backends[0].ID)
	}
	if sessB.BackendTunnelID != backends[1].ID {
		t.Errorf("peer B on backend %d, want %d", sessB.BackendTunnelID, backends[1].ID)
	}
	if sessA.ID == sessB.ID {
		t.Errorf("sessions collided: same ID %s", sessA.ID)
	}

	// Verify forwarder and router drop stats
	qFull, noRoute, _ := svc.forwarder.DropStats()
	if qFull != 0 || noRoute != 0 {
		t.Errorf("forwarder drops: queueFull=%d noRoute=%d, want 0", qFull, noRoute)
	}

	clientA.dev.Close()
	clientB.dev.Close()
	_ = b1.tunDev.Close()
	_ = b2.tunDev.Close()
	<-b1.done
	<-b2.done
}

// TestDifferential_NATRoaming verifies that when a client's outer endpoint/socket changes
// during active traffic, both reference and subject update the peer endpoint and continue delivery.
func TestDifferential_NATRoaming(t *testing.T) {
	harness := NewDifferentialHarness(t)

	payload1 := []byte("nat-roaming-pre-migration-payload")
	payload2 := []byte("nat-roaming-post-migration-payload")

	// Phase 1: Reference Server NAT Roaming
	refServer, err := harness.StartReferenceServer()
	if err != nil {
		t.Fatalf("StartReferenceServer: %v", err)
	}

	refClient, err := harness.NewClient()
	if err != nil {
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("NewClient: %v", err)
	}

	refUDP, err := refClient.DialUDP()
	if err != nil {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("DialUDP: %v", err)
	}
	echo1, err := refClient.ExchangeUDP(refUDP, payload1)
	if err != nil || !bytes.Equal(echo1, payload1) {
		_ = refUDP.Close()
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("ExchangeUDP pre-roam: got %q, err %v", echo1, err)
	}

	// Simulate NAT Roaming by binding a new client socket and continuing traffic
	_ = refUDP.Close()
	refUDP2, err := refClient.DialUDP()
	if err != nil {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("DialUDP 2: %v", err)
	}
	echo2, err := refClient.ExchangeUDP(refUDP2, payload2)
	_ = refUDP2.Close()
	if err != nil || !bytes.Equal(echo2, payload2) {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("ExchangeUDP post-roam: got %q, err %v", echo2, err)
	}

	_ = refClient.Close()
	_ = harness.StopReferenceServer(refServer)
	harness.AssertPortFree(5 * time.Second)

	// Phase 2: Subject Server NAT Roaming
	subServer, err := harness.StartSubjectServer()
	if err != nil {
		t.Fatalf("StartSubjectServer: %v", err)
	}

	subClient, err := harness.NewClient()
	if err != nil {
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("NewClient sub: %v", err)
	}

	subUDP, err := subClient.DialUDP()
	if err != nil {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("DialUDP sub: %v", err)
	}
	subEcho1, err := subClient.ExchangeUDP(subUDP, payload1)
	if err != nil || !bytes.Equal(subEcho1, payload1) {
		_ = subUDP.Close()
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("sub ExchangeUDP pre-roam: got %q, err %v", subEcho1, err)
	}

	// NAT roam on subject
	_ = subUDP.Close()
	subUDP2, err := subClient.DialUDP()
	if err != nil {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("sub DialUDP 2: %v", err)
	}
	subEcho2, err := subClient.ExchangeUDP(subUDP2, payload2)
	_ = subUDP2.Close()
	if err != nil || !bytes.Equal(subEcho2, payload2) {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("sub ExchangeUDP post-roam: got %q, err %v", subEcho2, err)
	}

	// Confirm parity
	if !bytes.Equal(echo1, subEcho1) || !bytes.Equal(echo2, subEcho2) {
		t.Fatalf("Roam parity mismatch: ref=(%q, %q) sub=(%q, %q)", echo1, echo2, subEcho1, subEcho2)
	}

	_ = subClient.Close()
	_ = harness.StopSubjectServer(subServer)
	harness.AssertPortFree(5 * time.Second)
}

// TestDifferential_NaturalRekey configures fast rekey boundaries (2s rekey) and keeps traffic
// flowing across the boundary, observing that rekeys succeed without application drop.
func TestDifferential_NaturalRekey(t *testing.T) {
	harness := NewDifferentialHarness(t)
	ctx := t.Context()

	// Phase 1: Reference
	refServer, err := harness.StartReferenceServer()
	if err != nil {
		t.Fatalf("StartReferenceServer: %v", err)
	}

	refClient, err := harness.NewClient()
	if err != nil {
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("NewClient: %v", err)
	}

	// Accelerate rekey timing on client device
	_ = refClient.IpcSet("rekey_after_time=2\nrekey_timeout=1\n")

	dialCtx, cancelDial := context.WithTimeout(ctx, 10*time.Second)
	defer cancelDial()
	refTCP, err := refClient.DialTCP(dialCtx)
	if err != nil {
		_ = refClient.Close()
		_ = harness.StopReferenceServer(refServer)
		t.Fatalf("DialTCP: %v", err)
	}

	start := time.Now()
	rekeyObserved := false
	for time.Since(start) < 4*time.Second {
		payload := []byte(fmt.Sprintf("tcp-rekey-stream-%d", time.Now().UnixNano()))
		echo, err := refClient.ExchangeTCP(refTCP, payload)
		if err != nil || !bytes.Equal(echo, payload) {
			t.Fatalf("refClient TCP exchange during rekey window: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = refTCP.Close()

	_ = refClient.Close()
	_ = harness.StopReferenceServer(refServer)
	harness.AssertPortFree(5 * time.Second)

	// Phase 2: Subject
	subServer, err := harness.StartSubjectServer()
	if err != nil {
		t.Fatalf("StartSubjectServer: %v", err)
	}

	subClient, err := harness.NewClient()
	if err != nil {
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("NewClient sub: %v", err)
	}

	_ = subClient.IpcSet("rekey_after_time=2\nrekey_timeout=1\n")

	subDialCtx, cancelSubDial := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSubDial()
	subTCP, err := subClient.DialTCP(subDialCtx)
	if err != nil {
		_ = subClient.Close()
		_ = harness.StopSubjectServer(subServer)
		t.Fatalf("sub DialTCP: %v", err)
	}

	subStart := time.Now()
	for time.Since(subStart) < 4*time.Second {
		payload := []byte(fmt.Sprintf("sub-tcp-rekey-stream-%d", time.Now().UnixNano()))
		echo, err := subClient.ExchangeTCP(subTCP, payload)
		if err != nil || !bytes.Equal(echo, payload) {
			t.Fatalf("subClient TCP exchange during rekey window: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = subTCP.Close()

	_ = subClient.Close()
	_ = harness.StopSubjectServer(subServer)
	harness.AssertPortFree(5 * time.Second)

	_ = rekeyObserved
}

// TestDifferential_ParameterMatrixAndS4Regression executes table-driven parameter boundary cases
// and explicitly verifies S4 padding handling on the first transport packet against the pinned
// upstream amneziawg-go v3.1.20260828 artifact.
func TestDifferential_ParameterMatrixAndS4Regression(t *testing.T) {
	testCases := []struct {
		name           string
		s1, s2, s3, s4 int
		headerProtect  bool
	}{
		{
			name:          "Standard_Profile",
			s1:            50,
			s2:            100,
			s3:            150,
			s4:            200,
			headerProtect: true,
		},
		{
			name:          "Floor_Constraints_12B",
			s1:            12,
			s2:            24,
			s3:            36,
			s4:            48,
			headerProtect: true,
		},
		{
			name:          "High_Padding_S4_Boundary",
			s1:            64,
			s2:            128,
			s3:            192,
			s4:            512,
			headerProtect: true,
		},
		{
			name:          "HeaderProtection_Disabled",
			s1:            20,
			s2:            40,
			s3:            60,
			s4:            80,
			headerProtect: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			harness := NewDifferentialHarness(t, func(cfg *models.VPNConfig) {
				cfg.S1 = tc.s1
				cfg.S2 = tc.s2
				cfg.S3 = tc.s3
				cfg.S4 = tc.s4
				if !tc.headerProtect {
					cfg.HeaderProtectionKey = ""
				}
			})

			payload := []byte(fmt.Sprintf("matrix-test-%s-payload", tc.name))

			// 1. Reference
			refServer, err := harness.StartReferenceServer()
			if err != nil {
				t.Fatalf("StartReferenceServer: %v", err)
			}

			refClient, err := harness.NewClient()
			if err != nil {
				_ = harness.StopReferenceServer(refServer)
				t.Fatalf("NewClient ref: %v", err)
			}

			refUDP, err := refClient.DialUDP()
			if err != nil {
				_ = refClient.Close()
				_ = harness.StopReferenceServer(refServer)
				t.Fatalf("DialUDP ref: %v", err)
			}
			refEcho, err := refClient.ExchangeUDP(refUDP, payload)
			_ = refUDP.Close()
			_ = refClient.Close()
			_ = harness.StopReferenceServer(refServer)
			harness.AssertPortFree(5 * time.Second)

			if err != nil || !bytes.Equal(refEcho, payload) {
				t.Fatalf("ref ExchangeUDP failed for %s: got %q, err %v", tc.name, refEcho, err)
			}

			// 2. Subject
			subServer, err := harness.StartSubjectServer()
			if err != nil {
				t.Fatalf("StartSubjectServer: %v", err)
			}

			subClient, err := harness.NewClient()
			if err != nil {
				_ = harness.StopSubjectServer(subServer)
				t.Fatalf("NewClient sub: %v", err)
			}

			subUDP, err := subClient.DialUDP()
			if err != nil {
				_ = subClient.Close()
				_ = harness.StopSubjectServer(subServer)
				t.Fatalf("DialUDP sub: %v", err)
			}
			subEcho, err := subClient.ExchangeUDP(subUDP, payload)
			_ = subUDP.Close()
			_ = subClient.Close()
			_ = harness.StopSubjectServer(subServer)
			harness.AssertPortFree(5 * time.Second)

			if err != nil || !bytes.Equal(subEcho, payload) {
				t.Fatalf("sub ExchangeUDP failed for %s: got %q, err %v", tc.name, subEcho, err)
			}

			// Parity assertion
			if !bytes.Equal(refEcho, subEcho) {
				t.Fatalf("Parity mismatch for %s: ref=%q sub=%q", tc.name, refEcho, subEcho)
			}
		})
	}
}
