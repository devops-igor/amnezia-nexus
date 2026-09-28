package ingress

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// countingLiveness records every refresh; the atomic guards cross-goroutine
// reads from the router's submission path.
type countingLiveness struct {
	touches atomic.Int64
}

func (l *countingLiveness) Touch(peerPublicKey string) { l.touches.Add(1) }
func (l *countingLiveness) TouchThrottled(peer string) { l.Touch(peer) }

// TestRouterAcceptedTrafficRefreshesLiveness is the finding-3 regression:
// an old LastSeen plus a valid plaintext packet must produce a liveness
// refresh; drops must not.
func TestRouterAcceptedTrafficRefreshesLiveness(t *testing.T) {
	const peer = testPeer1
	r := NewResolver()
	if err := r.Update(PeerOwnership{PeerPublicKey: peer, ConnectionID: "conn-1", UserID: "user-1", IP: netip.MustParseAddr("10.40.0.2")}); err != nil {
		t.Fatalf("seed resolver: %v", err)
	}
	admission := newAdmissionCounter()
	admission.assignIP(peer, "10.40.0.2")
	fwd := forwarder.NewForwarder(nil, "10.40.0.0/24")
	fwd.AttachBackendDevice(42, nopDevice{})
	live := &countingLiveness{}
	router := NewRouter(r, admission, fwd, live)

	// Simulate a stale session: the reaper's idle window has long passed.
	// (The production LastSeen lives in the SessionManager; this contract
	// test pins the ROUTER side: accepted traffic calls the refresher.)
	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	if err := router.HandlePacket(pkt); err != nil {
		t.Fatalf("first packet: %v", err)
	}
	if got := live.touches.Load(); got != 1 {
		t.Fatalf("accepted first packet produced %d liveness refreshes, want 1", got)
	}

	// Burst: every accepted packet refreshes (the throttle lives in
	// SessionLiveness; a bare Liveness sees one call per packet).
	for range 9 {
		if err := router.HandlePacket(pkt); err != nil {
			t.Fatalf("burst packet: %v", err)
		}
	}
	if got := live.touches.Load(); got != 10 {
		t.Fatalf("accepted burst produced %d refreshes, want 10", got)
	}

	// Drops never refresh: malformed, unmapped, admission-rejected.
	if err := router.HandlePacket(make([]byte, 12)); !errors.Is(err, ErrDropMalformed) {
		t.Fatalf("malformed packet = %v", err)
	}
	if err := router.HandlePacket(buildPacket(t, netip.MustParseAddr("10.40.9.9"), 40)); !errors.Is(err, ErrDropUnmapped) {
		t.Fatalf("unmapped packet = %v", err)
	}
	admission.errFor[peer] = errors.New("no backends")
	fwd.UnregisterSession(peer) // force re-admission so the rejection path runs
	if err := router.HandlePacket(pkt); !errors.Is(err, ErrAdmissionRejected) {
		t.Fatalf("rejected packet = %v", err)
	}
	if got := live.touches.Load(); got != 10 {
		t.Fatalf("drops refreshed liveness (%d refreshes after 3 drops), want 10", got)
	}
}

// TestRouterNilLivenessStillRoutes pins the optional-liveness contract: a
// router constructed without a refresher routes traffic (the parameter is a
// production no-op, not a required dependency).
func TestRouterNilLivenessStillRoutes(t *testing.T) {
	const peer = testPeer1
	router, _, admission, _ := fixture(t, peer, "10.40.0.2")
	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	if err := router.HandlePacket(pkt); err != nil {
		t.Fatalf("packet with nil liveness: %v", err)
	}
	if got := admission.calls(peer); got != 1 {
		t.Fatalf("admission ran %d times, want 1", got)
	}
}

// TestRouterLivenessSurvivesReaperSweep is the end-to-end shape of finding 3:
// an admitted peer whose LastSeen had gone stale (as the idle reaper would
// see it) ends up live again because accepted plaintext refreshed it through
// the production-shaped throttled refresher.
func TestRouterLivenessSurvivesReaperSweep(t *testing.T) {
	const peer = testPeer1
	resolver := NewResolver()
	if err := resolver.Update(PeerOwnership{PeerPublicKey: peer, ConnectionID: "conn-1", UserID: "user-1", IP: netip.MustParseAddr("10.40.0.2")}); err != nil {
		t.Fatalf("seed resolver: %v", err)
	}
	admission := newAdmissionCounter()
	admission.assignIP(peer, "10.40.0.2")
	fwd := forwarder.NewForwarder(nil, "10.40.0.0/24")
	fwd.AttachBackendDevice(42, nopDevice{})

	// Production-shaped liveness: throttled, backed by a store with the
	// reaper's rule (now - LastSeen > idleTimeout => reap).
	type session struct{ lastSeen time.Time }
	var mu sync.Mutex
	store := make(map[string]*session)
	live := NewSessionLiveness(func(peerPublicKey string) {
		mu.Lock()
		store[peerPublicKey] = &session{lastSeen: time.Now()}
		mu.Unlock()
	})
	router := NewRouter(resolver, admission, fwd, live)

	const idleTimeout = 3 * time.Second
	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	if err := router.HandlePacket(pkt); err != nil {
		t.Fatalf("accepted packet: %v", err)
	}
	mu.Lock()
	sess, ok := store[peer]
	mu.Unlock()
	if !ok {
		t.Fatal("accepted traffic never refreshed session liveness")
	}
	// The refresh moved LastSeen inside the reaper's window: the session
	// survives a sweep that runs right now.
	if time.Since(sess.lastSeen) > idleTimeout {
		t.Fatalf("refreshed LastSeen %s still looks idle to a %s reaper", sess.lastSeen, idleTimeout)
	}
}

// TestSessionLivenessThrottlesBurst is the finding-3 throttle test: 100
// rapid packets produce few refreshes (at most a handful within one window,
// never one per packet).
func TestSessionLivenessThrottlesBurst(t *testing.T) {
	var touches atomic.Int64
	live := NewSessionLiveness(func(string) { touches.Add(1) })

	const packets = 100
	var wg sync.WaitGroup
	for range packets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			live.TouchThrottled(testPeer1)
		}()
	}
	wg.Wait()

	got := touches.Load()
	if got == 0 {
		t.Fatal("throttled refresher never refreshed")
	}
	if got > 5 {
		t.Fatalf("%d rapid refresh calls produced %d refreshes, want <= 5", packets, got)
	}
}

// TestSessionLivenessRefreshesAcrossWindows pins the liveness property that
// matters for the reaper: after the throttle window elapses, the next packet
// refreshes again — sustained traffic keeps advancing LastSeen.
func TestSessionLivenessRefreshesAcrossWindows(t *testing.T) {
	var touches atomic.Int64
	live := NewSessionLiveness(func(string) { touches.Add(1) })

	live.TouchThrottled(testPeer1)
	live.TouchThrottled(testPeer1)
	if got := touches.Load(); got != 1 {
		t.Fatalf("same-window refreshes = %d, want 1", got)
	}
	// Sleep-free boundary proof is impossible against the wall clock, so
	// spread 100 packets at 25ms over 2.5s: several 2s windows elapse,
	// proving sustained traffic keeps refreshing while staying throttled.
	for range 100 {
		live.TouchThrottled(testPeer1)
		time.Sleep(25 * time.Millisecond)
	}
	got := touches.Load()
	if got < 2 {
		t.Fatalf("sustained traffic over 2.5s produced %d refreshes, want >= 2 (window crossings)", got)
	}
	if got > 10 {
		t.Fatalf("sustained traffic over 2.5s produced %d refreshes, want <= 10 (throttled)", got)
	}
}

// TestSessionLivenessForgetStopsStateRetention pins the per-peer state
// cleanup: Forget removes the throttle entry so the map never retains dead
// peers; a subsequent touch starts a fresh window.
func TestSessionLivenessForgetStopsStateRetention(t *testing.T) {
	var touches atomic.Int64
	live := NewSessionLiveness(func(string) { touches.Add(1) })
	live.TouchThrottled(testPeer1)
	if got := touches.Load(); got != 1 {
		t.Fatalf("first refresh = %d, want 1", got)
	}
	live.Forget(testPeer1)
	live.TouchThrottled(testPeer1)
	if got := touches.Load(); got != 2 {
		t.Fatalf("post-Forget refreshes = %d, want 2 (fresh window after state removal)", got)
	}
}

// TestSessionLivenessNilTouchPanics pins the constructor contract.
func TestSessionLivenessNilTouchPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewSessionLiveness(nil) did not panic")
		}
	}()
	NewSessionLiveness(nil)
}

// TestRouterRegistersRoutesWithCheckedAPI pins the router's use of the
// CHECKED registration: a forwarder at route capacity yields a counted
// RouteRegistrationErrors and an error wrapping
// forwarder.ErrRouteCapacityExhausted, and the router never memorizes a
// route that does not exist.
func TestRouterRegistersRoutesWithCheckedAPI(t *testing.T) {
	const peer = testPeer1
	resolver := NewResolver()
	if err := resolver.Update(PeerOwnership{PeerPublicKey: peer, ConnectionID: "conn-1", UserID: "user-1", IP: netip.MustParseAddr("10.40.0.2")}); err != nil {
		t.Fatalf("seed resolver: %v", err)
	}
	admission := newAdmissionCounter()
	admission.assignIP(peer, "10.40.0.2")

	// A real forwarder already holding maxActiveRoutes routes: the next
	// NEW peer's registration must fail with the checked error.
	fwd, err := forwarder.NewForwarderWithLimits(nil, "10.40.0.0/24", forwarder.DefaultClientQueueSize, 1)
	if err != nil {
		t.Fatalf("forwarder with limits: %v", err)
	}
	fwd.AttachBackendDevice(42, nopDevice{})
	// Fill the single route slot with a different peer.
	fwd.RegisterSession("sess-full", "conn-other", "other-peer-key", "10.40.0.250", 42)

	router := NewRouter(resolver, admission, fwd, nil)
	pkt := buildPacket(t, netip.MustParseAddr("10.40.0.2"), 40)
	err = router.HandlePacket(pkt)
	if err == nil {
		t.Fatal("route registration at capacity succeeded; want checked error")
	}
	if !errors.Is(err, forwarder.ErrRouteCapacityExhausted) {
		t.Fatalf("capacity error not propagated as ErrRouteCapacityExhausted: %v", err)
	}
	stats := router.StatsSnapshot()
	if stats.RouteRegistrationErrors != 1 {
		t.Fatalf("RouteRegistrationErrors = %d, want 1", stats.RouteRegistrationErrors)
	}
	if stats.AdmittedSessions != 0 {
		t.Fatalf("AdmittedSessions = %d, want 0 (registration failed)", stats.AdmittedSessions)
	}
	if got := fwd.RouteSessionID(peer); got != "" {
		t.Fatalf("failed admission left route %q behind", got)
	}
}


