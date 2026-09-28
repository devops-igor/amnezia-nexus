package ingress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// fakeSession / fakeBackend implement the handle seams.
type fakeSession struct {
	id         string
	assignedIP string
}

func (s *fakeSession) SessionID() string  { return s.id }
func (s *fakeSession) AssignedIP() string { return s.assignedIP }

type fakeBackend struct {
	id int64
}

func (b *fakeBackend) TunnelID() int64 { return b.id }

// nopDevice is a no-op packet device for backend queue attachment.
type nopDevice struct{}

func (nopDevice) Read(p []byte) (int, error)  { return 0, nil }
func (nopDevice) Write(p []byte) (int, error) { return len(p), nil }
func (nopDevice) Close() error                { return nil }

// admissionCounter is a fake Admission recording every call. Sessions are
// created with the peer's durable assigned IP (seeded via assignIP), the way
// a real admission resolves the lease.
type admissionCounter struct {
	mu          sync.Mutex
	byCalls     map[string]int
	sessions    map[string]*fakeSession
	backends    map[string]*fakeBackend
	errFor      map[string]error
	nilFor      map[string]bool
	assignedIPs map[string]string
}

func newAdmissionCounter() *admissionCounter {
	return &admissionCounter{
		byCalls:     make(map[string]int),
		sessions:    make(map[string]*fakeSession),
		backends:    make(map[string]*fakeBackend),
		errFor:      make(map[string]error),
		nilFor:      make(map[string]bool),
		assignedIPs: make(map[string]string),
	}
}

// assignIP seeds the durable IP a created session will report.
func (a *admissionCounter) assignIP(peerPublicKey, ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.assignedIPs[peerPublicKey] = ip
}

func (a *admissionCounter) EnsureSession(peerPublicKey string) (SessionHandle, BackendHandle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.byCalls[peerPublicKey]++
	if a.nilFor[peerPublicKey] {
		return nil, nil, nil
	}
	if err, ok := a.errFor[peerPublicKey]; ok {
		return nil, nil, err
	}
	sess, ok := a.sessions[peerPublicKey]
	if !ok {
		sess = &fakeSession{id: fmt.Sprintf("sess-%s", peerPublicKey[:6]), assignedIP: a.assignedIPs[peerPublicKey]}
		a.sessions[peerPublicKey] = sess
	}
	be, ok := a.backends[peerPublicKey]
	if !ok {
		be = &fakeBackend{id: 42}
		a.backends[peerPublicKey] = be
	}
	return sess, be, nil
}

func (a *admissionCounter) calls(peerPublicKey string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.byCalls[peerPublicKey]
}

func (a *admissionCounter) totalCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, c := range a.byCalls {
		n += c
	}
	return n
}

// fixture wires a resolver with one owned IP, an admission counter whose
// created sessions report the peer's durable IP, and a real forwarder with
// the backend queue attached (mirroring production AttachBackendDevice).
func fixture(t *testing.T, peerKey, assignedIP string) (*Router, *Resolver, *admissionCounter, *forwarder.Forwarder) {
	t.Helper()
	r := NewResolver()
	if err := r.Update(PeerOwnership{PeerPublicKey: peerKey, ConnectionID: "conn-1", UserID: "user-1", IP: netip.MustParseAddr(assignedIP)}); err != nil {
		t.Fatalf("seed resolver: %v", err)
	}
	admission := newAdmissionCounter()
	admission.assignIP(peerKey, assignedIP)
	fwd := forwarder.NewForwarder(nil, "10.40.0.0/24")
	fwd.AttachBackendDevice(42, nopDevice{})
	router := NewRouter(r, admission, fwd)
	return router, r, admission, fwd
}

func TestRouterDropsAndCounters(t *testing.T) {
	const peer = testPeer1
	router, resolver, admission, fwd := fixture(t, peer, "10.40.0.2")

	// Malformed: short, non-IPv4, zero length.
	for _, pkt := range [][]byte{make([]byte, 19), make([]byte, 20), nil} {
		if err := router.HandlePacket(pkt); !errors.Is(err, ErrDropMalformed) {
			t.Fatalf("HandlePacket(% x) = %v, want malformed drop", pkt, err)
		}
	}

	// Unmapped source: well-formed packet from an unowned address.
	unmapped := buildPacket(t, netip.MustParseAddr("10.40.0.250"), 40)
	if err := router.HandlePacket(unmapped); !errors.Is(err, ErrDropUnmapped) {
		t.Fatalf("unmapped packet = %v, want unmapped drop", err)
	}

	// Remove the peer's lease: its now-former address becomes unmapped.
	if _, ok := resolver.Remove(peer); !ok {
		t.Fatal("Remove failed")
	}
	removed := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	if err := router.HandlePacket(removed); !errors.Is(err, ErrDropUnmapped) {
		t.Fatalf("removed-owner packet = %v, want unmapped drop", err)
	}

	stats := router.StatsSnapshot()
	if stats.MalformedPacketDrops != 3 || stats.UnmappedSourceIPDrops != 2 {
		t.Fatalf("drop counters = %+v, want malformed 3 / unmapped 2", stats)
	}
	if admission.totalCalls() != 0 {
		t.Fatalf("admission ran %d times for dropped packets, want 0", admission.totalCalls())
	}
	if _, _, routes := fwd.GetStats(); routes != 0 {
		t.Fatalf("forwarder holds %d routes after pure drops, want 0", routes)
	}
}

func TestRouterAdmissionErrorPropagation(t *testing.T) {
	const peer = testPeer1
	router, _, admission, _ := fixture(t, peer, "10.40.0.2")
	admission.errFor[peer] = errors.New("no healthy backends")

	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	err := router.HandlePacket(pkt)
	if !errors.Is(err, ErrAdmissionRejected) || !strings.Contains(err.Error(), "no healthy backends") {
		t.Fatalf("admission error not propagated: %v", err)
	}
	if got := admission.calls(peer); got != 1 {
		t.Fatalf("admission called %d times, want 1", got)
	}
	stats := router.StatsSnapshot()
	if stats.AdmissionRejectedDrops != 1 || stats.AdmittedSessions != 0 {
		t.Fatalf("stats after rejection = %+v", stats)
	}

	// Admission returning nil handles with nil error is a contract
	// violation, not a crash.
	admission.nilFor[peer] = true
	if err := router.HandlePacket(pkt); !errors.Is(err, ErrAdmissionContract) {
		t.Fatalf("nil-handle admission = %v, want contract violation", err)
	}
	stats = router.StatsSnapshot()
	if stats.AdmissionRejectedDrops != 2 {
		t.Fatalf("stats after contract violation = %+v", stats)
	}
}

func TestRouterOwnershipMismatchDropsWithoutRouting(t *testing.T) {
	const peer = testPeer1
	const victim = testPeer2
	router, resolver, admission, fwd := fixture(t, peer, "10.40.0.2")
	if err := resolver.Update(PeerOwnership{PeerPublicKey: victim, ConnectionID: "conn-2", UserID: "user-2", IP: netip.MustParseAddr("10.40.0.9")}); err != nil {
		t.Fatalf("seed victim lease: %v", err)
	}

	// Admission authenticates the resolved owner (peer), but the session's
	// assigned IP disagrees with the resolver's durable record: divergence
	// is dropped and counted, and the forwarder is never touched.
	admission.sessions[peer] = &fakeSession{id: "sess-divergent", assignedIP: "10.40.0.99"}

	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	if err := router.HandlePacket(pkt); !errors.Is(err, ErrDropMismatch) {
		t.Fatalf("divergent packet = %v, want mismatch drop", err)
	}
	stats := router.StatsSnapshot()
	if stats.OwnershipMismatchDrops != 1 || stats.AdmittedSessions != 0 {
		t.Fatalf("stats after mismatch = %+v", stats)
	}
	if _, _, routes := fwd.GetStats(); routes != 0 {
		t.Fatalf("forwarder holds %d routes after mismatch drop, want 0", routes)
	}
}

func TestRouterHappyPathThroughRealForwarder(t *testing.T) {
	const peer = testPeer1
	const backendID = int64(42)
	router, _, admission, fwd := fixture(t, peer, "10.40.0.2")

	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)

	// First packet: admission runs, route registers, packet reaches the
	// backend queue.
	if err := router.HandlePacket(pkt); err != nil {
		t.Fatalf("first packet: %v", err)
	}
	beQueue, ok := fwd.GetBackendPacketChannel(backendID)
	if !ok {
		t.Fatal("backend queue missing after first packet")
	}
	got := <-beQueue
	if string(got) != string(pkt) {
		t.Fatalf("backend received % x, want % x", got, pkt)
	}
	if got := admission.calls(peer); got != 1 {
		t.Fatalf("admission called %d times after first packet, want 1", got)
	}
	if _, ok := fwd.RouteQueueStats(peer); !ok {
		t.Fatal("client route missing after first packet")
	}

	// Burst of follow-up packets: admission must NOT re-run; the live route
	// is reused.
	for range 32 {
		if err := router.HandlePacket(pkt); err != nil {
			t.Fatalf("burst packet: %v", err)
		}
	}
	if got := admission.calls(peer); got != 1 {
		t.Fatalf("admission called %d times after burst, want 1 (lazy admission is once per live route)", got)
	}
	stats := router.StatsSnapshot()
	if stats.AdmittedSessions != 1 {
		t.Fatalf("AdmittedSessions = %d, want 1", stats.AdmittedSessions)
	}

	// Drain the burst from the backend queue.
	for range 32 {
		select {
		case <-beQueue:
		default:
			t.Fatal("burst packets missing from backend queue")
		}
	}
}

func TestRouterRekeyKeepsSessionStable(t *testing.T) {
	const peer = testPeer1
	router, _, admission, fwd := fixture(t, peer, "10.40.0.2")
	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	if err := router.HandlePacket(pkt); err != nil {
		t.Fatalf("first packet: %v", err)
	}
	firstSessionID := admission.sessions[peer].id

	// Upstream rekey: the transport session is replaced, Nexus sees only
	// continued plaintext from the same assigned IP. The memoized route is
	// still live, so admission must NOT run again — Nexus keeps the FIRST
	// session and its backend. The deliberate fake replacement below models
	// what a broken implementation would do; the router must never ask.
	for range 8 {
		if err := router.HandlePacket(pkt); err != nil {
			t.Fatalf("post-rekey packet: %v", err)
		}
	}
	if got := admission.calls(peer); got != 1 {
		t.Fatalf("admission ran %d times across a rekey, want 1", got)
	}
	if admission.sessions[peer].id != firstSessionID {
		t.Fatal("test fixture replaced the session during the rekey window")
	}
	// The live route still belongs to the FIRST session: rekeys did not
	// touch Nexus routing state.
	if got := fwd.RouteSessionID(peer); got != firstSessionID {
		t.Fatalf("route session ID = %q, want the pre-rekey %q", got, firstSessionID)
	}
}

func TestRouterAdmissionExactlyOncePerBurst(t *testing.T) {
	const peer = testPeer1
	router, _, admission, _ := fixture(t, peer, "10.40.0.2")

	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	const burst = 64
	var wg sync.WaitGroup
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := router.HandlePacket(pkt); err != nil {
				t.Errorf("burst packet: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := admission.calls(peer); got != 1 {
		t.Fatalf("admission ran %d times for a %d-packet first burst, want 1", got, burst)
	}
}

func TestRouterStaleMemoForcesReadmission(t *testing.T) {
	const peer = testPeer1
	router, _, admission, fwd := fixture(t, peer, "10.40.0.2")

	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	if err := router.HandlePacket(pkt); err != nil {
		t.Fatalf("first packet: %v", err)
	}

	// Simulate backend death: the forwarder route is unregistered by the
	// lifecycle path. The next packet must re-admit (fresh backend select).
	fwd.UnregisterSession(peer)
	if err := router.HandlePacket(pkt); err != nil {
		t.Fatalf("post-teardown packet: %v", err)
	}
	if got := admission.calls(peer); got != 2 {
		t.Fatalf("admission ran %d times after route teardown, want 2", got)
	}

	// A durable lease revocation (resolver Remove) also forces re-admission
	// — and, once removed, the source IP no longer resolves at all.
	router2, resolver2, admission2, _ := fixture(t, testPeer3, "10.40.0.7")
	pkt3 := buildPacket(t, netip.MustParseAddr("10.40.0.7"), 40)
	if err := router2.HandlePacket(pkt3); err != nil {
		t.Fatalf("router2 first packet: %v", err)
	}
	if _, ok := resolver2.Remove(testPeer3); !ok {
		t.Fatal("resolver2 Remove failed")
	}
	if err := router2.HandlePacket(pkt3); !errors.Is(err, ErrDropUnmapped) {
		t.Fatalf("post-revocation packet = %v, want unmapped drop", err)
	}
	if got := admission2.calls(testPeer3); got != 1 {
		t.Fatalf("admission2 ran %d times, want 1 (revoked peers never re-admit)", got)
	}
}

func TestRouterConcurrentMixedLoad(t *testing.T) {
	resolver := NewResolver()
	const workers = 6
	const perWorker = 50

	// Six owned peers, each with its own IP and admission identity.
	peers := make([]string, workers)
	for i := range peers {
		peers[i] = fmt.Sprintf("wwwwwwww-%02d-peer", i)
		ip := netip.AddrFrom4([4]byte{10, 40, 2, byte(i + 1)})
		if err := resolver.Update(PeerOwnership{PeerPublicKey: peers[i], ConnectionID: fmt.Sprintf("conn-%02d", i), UserID: "u", IP: ip}); err != nil {
			t.Fatalf("seed peer %d: %v", i, err)
		}
	}
	admission := newAdmissionCounter()
	for i := range peers {
		ip := netip.AddrFrom4([4]byte{10, 40, 2, byte(i + 1)})
		admission.assignIP(peers[i], ip.String())
	}
	fwd := forwarder.NewForwarder(nil, "10.40.0.0/24")
	router := NewRouter(resolver, admission, fwd)

	packets := make([][]byte, workers)
	for i := range packets {
		packets[i] = buildPacket(t, netip.AddrFrom4([4]byte{10, 40, 2, byte(i + 1)}), 40)
	}

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for range perWorker {
				if err := router.HandlePacket(packets[worker]); err != nil {
					t.Errorf("worker %d: %v", worker, err)
					return
				}
			}
		}(w)
	}
	// Concurrent non-member noise: malformed + unmapped traffic racing the
	// admitted packets.
	wg.Add(1)
	go func() {
		defer wg.Done()
		noise := buildPacket(t, netip.MustParseAddr("10.40.9.9"), 40)
		for range perWorker {
			_ = router.HandlePacket(make([]byte, 12))
			_ = router.HandlePacket(noise)
		}
	}()
	wg.Wait()

	stats := router.StatsSnapshot()
	if stats.AdmittedSessions != workers {
		t.Fatalf("AdmittedSessions = %d, want %d", stats.AdmittedSessions, workers)
	}
	for i, peer := range peers {
		if got := admission.calls(peer); got != 1 {
			t.Fatalf("peer %d admitted %d times, want 1", i, got)
		}
	}
	if stats.MalformedPacketDrops != perWorker || stats.UnmappedSourceIPDrops != perWorker {
		t.Fatalf("noise counters = %+v", stats)
	}
}

func TestRouterRejectsImpossibleTotalLength(t *testing.T) {
	// The strict parse treats a self-declared total length that cannot be
	// true (0xFFFF bytes received in a 40-byte datagram) as malformed: the
	// packet is dropped and counted, never routed or admitted.
	const peer = testPeer1
	router, _, admission, fwd := fixture(t, peer, "10.40.0.2")

	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	binary.BigEndian.PutUint16(pkt[2:4], 0xFFFF) // impossible total length
	if err := router.HandlePacket(pkt); !errors.Is(err, ErrDropMalformed) {
		t.Fatalf("packet with impossible total length = %v, want malformed drop", err)
	}
	if stats := router.StatsSnapshot(); stats.MalformedPacketDrops != 1 {
		t.Fatalf("MalformedPacketDrops = %d, want 1", stats.MalformedPacketDrops)
	}
	if got := admission.calls(peer); got != 0 {
		t.Fatalf("admission ran %d times, want 0 (packet dropped before admission)", got)
	}
	beQueue, ok := fwd.GetBackendPacketChannel(42)
	if !ok {
		t.Fatal("backend queue missing")
	}
	select {
	case got := <-beQueue:
		t.Fatalf("malformed packet reached the backend queue: % x", got)
	default:
	}
}
