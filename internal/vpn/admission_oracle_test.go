package vpn

// Readiness-oracle coverage for the ingress admission publish/register split
// (issue #703 follow-up). Admission publishes the routing session as
// "connected" under the session-manager lock and registers the forwarder route
// LAST under Service.mu, so a reader that accepts "connected" alone can sample
// the forwarder route before it exists and observe "".
//
// These tests pin the oracle, not the CI interleave:
//   - awaitSettledAdmission is the readiness condition the engine-based rekey
//     test now uses; it accepts only a session/route pair that already agrees.
//   - TestEngineAdmissionOracleRequiresSettledRoute blocks real engine-driven
//     admission in the existing pre-route-registration hook and shows, in the
//     window, that the old connected-only condition is satisfied while the
//     route is absent — the CI failure — and that the repaired condition
//     refuses to settle until registration lands.
//   - TestEngineAdmissionOracleRejectsWrongRoute proves the repair cannot pass
//     by accepting any non-empty route: a route owned by another session ID
//     must not settle the wait.

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// awaitSettledAdmission polls for a routing session that is "connected" AND
// whose forwarder route already names that same session. It returns the last
// observed pair so callers can report the exact mismatch, and settled=false
// when the deadline elapses. The previous oracle accepted "connected" alone and
// then sampled the route once; that is the sampling bug this replaces.
func awaitSettledAdmission(svc *Service, peerPublicKey string, deadline time.Time, reinject func()) (sess models.VPNSession, lastRoute string, settled bool) {
	for time.Now().Before(deadline) {
		if s, found := svc.sessionMgr.GetSessionSnapshotByPeer(peerPublicKey); found && s.Status == "connected" {
			sess = s
			lastRoute = svc.forwarder.RouteSessionID(peerPublicKey)
			if lastRoute == s.ID {
				return sess, lastRoute, true
			}
		}
		time.Sleep(50 * time.Millisecond)
		if reinject != nil {
			reinject()
		}
	}
	return sess, lastRoute, false
}

// TestEngineAdmissionOracleRequiresSettledRoute drives a REAL upstream engine
// against the ingress engine exactly as the rekey test does, but holds
// admission inside the existing pre-route-registration hook. Inside that window
// the session is already "connected" and the route is still "" — the pair the
// CI failure sampled. The repaired readiness condition must not settle there,
// and must settle immediately after the gate is released.
func TestEngineAdmissionOracleRequiresSettledRoute(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tun := range svc.pool.ListTunnels() {
		svc.forwarder.AttachBackendDevice(tun.ID, nil)
	}

	peer, saved := newEnginePeer(t, svc, db, "oracle-engine-user")

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	released := func() { releaseOnce.Do(func() { close(release) }) }
	// The hook runs under Service.mu, so it must not call back into Service:
	// signal, then block on the gate with a bounded fallback so a failed
	// assertion can never wedge admission for the rest of the run.
	svc.SetPreIngressRouteRegistrationHookForTest(func() {
		select {
		case <-entered:
		default:
			close(entered)
		}
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	})

	e, err := svc.NewIngressEngine(ctx, "sync-oracle-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	// Registered AFTER the Stop cleanup so it runs BEFORE it (cleanups are LIFO):
	// a failing assertion inside the window must not leave engine Stop waiting
	// for the gate's fallback timeout.
	t.Cleanup(func() {
		released()
		svc.SetPreIngressRouteRegistrationHookForTest(nil)
	})
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}

	uc := startEngineUpstreamClient(t, saved, "sync-oracle-client")
	firstPkt := engineUDPPacket(netip.MustParseAddr(peer.assignedIP), netip.MustParseAddr("10.0.0.1"), 1)
	uc.inject(t, firstPkt)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("engine admission never reached the pre-route-registration hook")
	}

	// Inside the window: session published as connected, route not registered.
	live, found := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
	if !found || live.Status != "connected" {
		t.Fatalf("in-window session snapshot = %+v (found=%v), want a connected session", live, found)
	}
	route := svc.forwarder.RouteSessionID(peer.publicKey)
	if route != "" {
		t.Fatalf("in-window route = %q, want empty before registration", route)
	}
	// RED witness: the pre-fix condition ("connected" alone) accepts here, and
	// the very next route read is exactly the CI failure line.
	t.Logf("RED witness (pre-fix connected-only oracle): route session mismatch: got %q, want %q", route, live.ID)

	// GREEN: the repaired condition refuses to call this settled, so the rekey
	// test keeps waiting instead of failing on a mid-admission sample.
	if _, _, settled := awaitSettledAdmission(svc, peer.publicKey, time.Now().Add(300*time.Millisecond), nil); settled {
		t.Fatal("settled-admission oracle accepted a connected session whose route was not registered")
	}

	// Releasing the gate must let registration finish; the same oracle then
	// settles on the matching pair, so the repair is not just a permanent wait.
	released()
	settledSess, settledRoute, settled := awaitSettledAdmission(svc, peer.publicKey, time.Now().Add(5*time.Second), func() {
		_ = uc.vt.InjectInbound(firstPkt)
	})
	if !settled {
		t.Fatalf("admission did not settle after release: last session %q, last route %q", settledSess.ID, settledRoute)
	}
	if settledSess.ID == "" || settledRoute != settledSess.ID {
		t.Fatalf("settled pair = (%q, %q), want a matching session/route pair", settledSess.ID, settledRoute)
	}
}

// TestEngineAdmissionOracleRejectsNeverRegisteredPeer is the never-registered
// negative control: admission is held in the window for the whole probe, so
// registration never lands and the repaired condition must report "not settled".
// Without this, a repair that simply waits could be mistaken for a repair that
// detects route loss.
func TestEngineAdmissionOracleRejectsNeverRegisteredPeer(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	peer := seedIngressPeer(t, db, "oracle-never", "oracle-peer-bbbbbbbb2", "10.100.7.3")

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	released := func() { releaseOnce.Do(func() { close(release) }) }
	svc.SetPreIngressRouteRegistrationHookForTest(func() {
		select {
		case <-entered:
		default:
			close(entered)
		}
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	})
	t.Cleanup(func() {
		released()
		svc.SetPreIngressRouteRegistrationHookForTest(nil)
	})

	done := make(chan error, 1)
	go func() {
		_, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
		done <- err
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("admission never reached the pre-route-registration hook")
	}

	// Bounded probe while registration is deliberately blocked: this never
	// depends on losing a race.
	sess, route, settled := awaitSettledAdmission(svc, peer.peerKey, time.Now().Add(250*time.Millisecond), nil)
	if settled {
		t.Fatalf("repaired oracle settled while registration never happened: session %q route %q", sess.ID, route)
	}
	if sess.ID == "" {
		t.Fatal("control is vacuous: no connected session was observed, so the never-registered case was not exercised")
	}
	if route != "" {
		t.Fatalf("control is vacuous: route = %q, want empty (registration was blocked)", route)
	}

	released()
	if err := <-done; err != nil {
		t.Fatalf("admission after release: %v", err)
	}
	if got := svc.forwarder.RouteSessionID(peer.peerKey); got != sess.ID {
		t.Fatalf("route after release = %q, want %q", got, sess.ID)
	}
}

// TestEngineAdmissionOracleRejectsWrongRoute is the wrong-route negative
// control: the peer has a connected session, but the forwarder route belongs to
// a different session ID, so the repaired condition must not settle. This is
// what stops an "any non-empty route passes" repair from going green while
// hiding a real route-loss defect.
func TestEngineAdmissionOracleRejectsWrongRoute(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	peer := seedIngressPeer(t, db, "oracle-wrong", "oracle-peer-cccccccc3", "10.100.7.4")

	admitted, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	t.Cleanup(func() { svc.forwarder.UnregisterSession(peer.peerKey) })

	const staleSessionID = "stale-route-session"
	svc.forwarder.RegisterSession(staleSessionID, peer.connID, peer.peerKey, peer.ip.String(), admitted.BackendTunnelID)
	if got := svc.forwarder.RouteSessionID(peer.peerKey); got != staleSessionID {
		t.Fatalf("stale route session = %q, want %q", got, staleSessionID)
	}

	sess, route, settled := awaitSettledAdmission(svc, peer.peerKey, time.Now().Add(300*time.Millisecond), nil)
	if settled {
		t.Fatalf("repaired oracle settled on a wrong-session route: session %q route %q", sess.ID, route)
	}
	if sess.ID != admitted.ID {
		t.Fatalf("observed session %q, want the admitted session %q", sess.ID, admitted.ID)
	}
	if route != staleSessionID {
		t.Fatalf("last observed route = %q, want the stale route %q", route, staleSessionID)
	}
}
