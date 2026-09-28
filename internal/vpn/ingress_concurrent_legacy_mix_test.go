package vpn

// Regression test for issue #388 rework D: the ingress admission must act on
// the ReplacementPoolDelta ITS OWN CreateSession call returned, never a
// foreign call's. The legacy custom-listener path
// (endpoint/listener.go AuthenticateAndRegisterPeer -> SessionManager
// .CreateSession) does NOT take the VPN Service's s.mu, so nothing serializes
// a legacy CreateSession against the ingress admission sequence. Under the
// rework-C shared field (SessionManager.lastReplacementDelta, read by
// LastReplacementPoolDelta without sm.mu) such an interleaving was both a
// data race and a wrong-accounting hazard: the ingress could read the legacy
// call's zero delta, suppress its own increment, and — under the #384
// dual-engine canary, where both paths are alive concurrently — leave the
// new backend's gauge short by one, or double-count when the foreign delta
// arrives between the ingress's CreateSession and its read.
//
// Per iteration, with X = the ingress peer's current backend and Y the
// other: X is made administratively ineligible so the ingress admission must
// replace the peer's session onto Y (deterministic selection), while a
// legacy-shaped CreateSession replaces the second peer's session on ITS home
// backend in parallel (a same-backend replacement, so the hook's delta is
// {Replaced, HasInc: false} — a nonzero foreign delta), followed by the
// legacy path's own unconditional pool increment. Whatever the interleaving,
// the backend gauges must end exactly right: the legacy peer's home keeps
// exactly its one count, and the ingress peer's new backend gains exactly
// its one count — a stolen/suppressed delta shows up as 0 or 2.
//
// The loop count plus runtime.Gosched before each call force the
// interleavings; under the old shared-field mechanism this test failed via
// the wrong-count assertion and/or the -race report on the unsynchronized
// field read (see DEV_HANDOVER.md "## Rework D", mutation check).

import (
	"runtime"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestIngressCountersWithConcurrentLegacyCreateSession(t *testing.T) {
	db := setupTestDB(t)
	svc, serverA, serverB, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backendA := serverTunnelID(t, svc, serverA)
	backendB := serverTunnelID(t, svc, serverB)

	peer := seedIngressPeer(t, db, "ingress-repl-dave", "ingress-peer-bbbbbbbbbb4", "10.100.4.5")

	const (
		legacyPeerKey = "ingress-legacy-mix-peer"
		legacyIP      = "10.100.4.250"
		iterations    = 40
	)

	legacyUserID, err := db.CreateUser(ctx, &models.User{Username: "ingress-legacy-mix-user", Role: "user", Enabled: true})
	if err != nil {
		t.Fatalf("create legacy user: %v", err)
	}

	// Initial state: the ingress peer admitted onto backend A (deterministic
	// first pick), the legacy peer registered directly on A the way the
	// custom-listener path does (CreateSession + the path's own increment).
	if _, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer)); err != nil {
		t.Fatalf("initial ingress admission: %v", err)
	}
	if _, err := svc.sessionMgr.CreateSession(ctx, legacyUserID, legacyPeerKey, legacyIP, backendA, "legacy-mix-device", 1); err != nil {
		t.Fatalf("initial legacy registration: %v", err)
	}
	svc.pool.IncrementConnections(backendA)

	for it := 0; it < iterations; it++ {
		live, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey)
		if !ok {
			t.Fatalf("iter %d: ingress peer lost its session", it)
		}
		legacyLive, ok := svc.sessionMgr.GetSessionSnapshotByPeer(legacyPeerKey)
		if !ok {
			t.Fatalf("iter %d: legacy peer lost its session", it)
		}
		homeBackend := live.BackendTunnelID // X: about to be made ineligible
		legacyHome := legacyLive.BackendTunnelID
		homeServer := serverA
		if homeBackend == backendB {
			homeServer = serverB
		}
		otherBackend := backendB
		if homeBackend == backendB {
			otherBackend = backendA
		}

		// X ineligible: the next ingress admission must replace onto Y.
		adminDisableBackend(t, svc, homeServer)

		type mixOutcome struct {
			legacyErr      error
			ingressErr     error
			ingressSess    *models.VPNSession
			ingressBackend *models.BackendTunnel
		}
		var outcome mixOutcome // each goroutine writes distinct fields
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			runtime.Gosched() // invite the interleaving under test
			// Legacy custom-listener shape (AuthenticateAndRegisterPeer):
			// CreateSession directly on the manager — no Service.mu —
			// replacing the legacy peer's session on ITS home backend
			// (same-backend: the hook fires Dec only, a nonzero foreign
			// delta), then the path's own unconditional increment.
			if _, err := svc.sessionMgr.CreateSession(ctx, legacyUserID, legacyPeerKey, legacyIP, legacyHome, "legacy-mix-device", uint64(it)+2); err != nil {
				outcome.legacyErr = err
				return
			}
			svc.pool.IncrementConnections(legacyHome)
		}()
		go func() {
			defer wg.Done()
			runtime.Gosched()
			sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
			outcome.ingressErr = err
			outcome.ingressSess = sess
			outcome.ingressBackend = backend
		}()
		wg.Wait()

		if outcome.legacyErr != nil {
			t.Fatalf("iter %d: legacy CreateSession: %v", it, outcome.legacyErr)
		}
		if outcome.ingressErr != nil {
			t.Fatalf("iter %d: ingress admission: %v", it, outcome.ingressErr)
		}
		if outcome.ingressBackend == nil || outcome.ingressBackend.ID != otherBackend {
			t.Fatalf("iter %d: ingress landed on %+v, want the surviving backend %d", it, outcome.ingressBackend, otherBackend)
		}
		if outcome.ingressSess == nil || outcome.ingressSess.ID == live.ID {
			t.Fatalf("iter %d: expected a replaced session, got %+v", it, outcome.ingressSess)
		}

		// The accounting contract itself: each backend holds EXACTLY the one
		// count of the session that lives on it. The ingress peer's new
		// backend must not lose its increment to a foreign zero delta (want
		// 0) nor gain a duplicate (want 2).
		wantHome, wantOther := 0, 1
		if legacyHome == homeBackend {
			wantHome = 1
		} else {
			wantOther = 2 // legacy peer already lives on the ingress peer's new backend
		}
		counts := backendCounts(t, svc)
		if counts[homeBackend] != wantHome {
			t.Fatalf("iter %d: backend %d count = %d, want %d", it, homeBackend, counts[homeBackend], wantHome)
		}
		if counts[otherBackend] != wantOther {
			t.Fatalf("iter %d: backend %d count = %d, want %d (a foreign legacy delta stole this admission's increment decision)", it, otherBackend, counts[otherBackend], wantOther)
		}

		active := 0
		peerBackend, legacyBackend := int64(0), int64(0)
		for _, s := range svc.sessionMgr.ListActiveSessions() {
			switch s.PeerPublicKey {
			case peer.peerKey:
				active++
				peerBackend = s.BackendTunnelID
			case legacyPeerKey:
				active++
				legacyBackend = s.BackendTunnelID
			}
		}
		if active != 2 {
			t.Fatalf("iter %d: %d active sessions, want 2", it, active)
		}
		if peerBackend != otherBackend || legacyBackend != legacyHome {
			t.Fatalf("iter %d: session backends (ingress=%d, legacy=%d), want (ingress=%d, legacy=%d)", it, peerBackend, legacyBackend, otherBackend, legacyHome)
		}

		// Restore X; roles swap next iteration (the ingress peer now lives
		// on Y).
		if err := svc.pool.SetTunnelEnabled(ctx, homeServer, true, models.DisableReasonNone); err != nil {
			t.Fatalf("iter %d: re-enable backend %d: %v", it, homeServer, err)
		}
	}
}
