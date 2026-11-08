package vpn

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestHealthDisableEligible covers the suppression matrix that keeps the
// automatic failover from overriding administrative intent or acting on a
// superseded commit.
func TestHealthDisableEligible(t *testing.T) {
	disabledHealth := func() models.BackendTunnel {
		return models.BackendTunnel{
			ID:            7,
			ServerID:      3,
			Enabled:       true,
			Status:        models.TunnelStatusDisabled,
			DisableReason: models.DisableReasonHealth,
			StateVersion:  11,
		}
	}

	cases := []struct {
		name      string
		mutate    func(*models.BackendTunnel)
		committed func(*models.BackendTunnel)
		want      bool
	}{
		{name: "exact live health disable", want: true},
		{name: "committed version unknown (0) still eligible", want: true,
			committed: func(b *models.BackendTunnel) { b.StateVersion = 0 }},
		{name: "administratively re-enabled", want: false,
			mutate: func(b *models.BackendTunnel) { b.Enabled = false }},
		{name: "recovered to active", want: false,
			mutate: func(b *models.BackendTunnel) {
				b.Status = models.TunnelStatusActive
				b.DisableReason = models.DisableReasonNone
			}},
		{name: "administrative disable reason", want: false,
			mutate: func(b *models.BackendTunnel) { b.DisableReason = models.DisableReasonAdmin }},
		{name: "handshake_blocked again", want: false,
			mutate: func(b *models.BackendTunnel) { b.Status = models.TunnelStatusHandshakeBlocked }},
		{name: "newer state version supersedes commit", want: false,
			committed: func(b *models.BackendTunnel) { b.StateVersion = 10 }},
		{name: "uppercase status still matches", want: true,
			mutate: func(b *models.BackendTunnel) { b.Status = "DISABLED" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			live := disabledHealth()
			if tc.mutate != nil {
				tc.mutate(&live)
			}
			committed := disabledHealth()
			if tc.committed != nil {
				tc.committed(&committed)
			}
			if got := healthDisableEligible(&live, &committed); got != tc.want {
				t.Fatalf("healthDisableEligible = %t, want %t", got, tc.want)
			}
		})
	}

	if healthDisableEligible(nil, &models.BackendTunnel{}) {
		t.Fatal("nil live tunnel must not be eligible")
	}
	live := disabledHealth()
	if healthDisableEligible(&live, nil) {
		t.Fatal("nil committed snapshot must not be eligible")
	}
}

// TestBackendHealthDisabled_Rejections covers the defensive branches: no pool,
// no identity, a deleted backend, and a backend that no longer matches the
// committed disable.
func TestBackendHealthDisabled_Rejections(t *testing.T) {
	ctx := t.Context()

	var nilSvc *Service
	if err := nilSvc.BackendHealthDisabled(ctx, &models.BackendTunnel{ID: 1}); err == nil {
		t.Fatal("expected an error for a nil service")
	}

	db := setupTestDB(t)
	svc, sourceServerID, _, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	source, err := svc.pool.GetTunnel(sourceServerID)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.BackendHealthDisabled(ctx, nil); err == nil {
		t.Fatal("expected an error for a nil tunnel")
	}
	if err := svc.BackendHealthDisabled(ctx, &models.BackendTunnel{}); err == nil {
		t.Fatal("expected an error for a tunnel without identity")
	}
	// Unknown tunnel ID: deleted between commit and notification, a no-op.
	if err := svc.BackendHealthDisabled(ctx, &models.BackendTunnel{ID: source.ID + 9999, ServerID: source.ServerID}); err != nil {
		t.Fatalf("deleted backend must be a no-op, got %v", err)
	}
	// Live tunnel is not in a health-disabled state: nothing to do.
	if err := svc.BackendHealthDisabled(ctx, &models.BackendTunnel{
		ID:            source.ID,
		ServerID:      source.ServerID,
		StateVersion:  source.StateVersion,
		Status:        models.TunnelStatusDisabled,
		DisableReason: models.DisableReasonHealth,
	}); err != nil {
		t.Fatalf("non-health-disabled live tunnel must be a no-op, got %v", err)
	}
}

// TestBackendHealthDisabled_NoHealthyTarget verifies that a health disable with
// no eligible alternative leaves the session in place and reports no error, so
// the probe cycle is never turned into a data-plane error.
func TestBackendHealthDisabled_NoHealthyTarget(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sourceServerID, targetServerID, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	source, _ := svc.pool.GetTunnel(sourceServerID)
	target, _ := svc.pool.GetTunnel(targetServerID)
	svc.SetBackendDeviceForTest(source.ID, &testCanaryDevice{})
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})

	peer := seedIngressPeer(t, db, "r21-notarget-user", "r21-notarget-peer", "10.100.4.31")
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	if backend.ID != source.ID {
		t.Fatalf("precondition: admitted to %d, want %d", backend.ID, source.ID)
	}

	// Make the only alternative ineligible: administratively disabled, so it is
	// not in the active set the failover may use.
	if err := svc.pool.SetTunnelEnabled(ctx, targetServerID, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}
	// Drive the source into the committed terminal health-disable state.
	if err := svc.pool.SetTunnelStatusWithReason(ctx, sourceServerID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatal(err)
	}
	committed, err := svc.pool.GetTunnel(sourceServerID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.BackendHealthDisabled(ctx, committed); err != nil {
		t.Fatalf("no healthy target must not be an error, got %v", err)
	}

	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.BackendTunnelID != source.ID {
		t.Fatalf("session moved with no healthy target available: %+v", row)
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatal("route changed with no healthy target available")
	}
}

// TestBackendHealthDisabled_PartialFailureDoesNotStrandOthers covers the durable
// fallback and the per-session error isolation: a connected vpn_sessions row with
// no live in-memory session cannot be migrated (its session is gone), but the
// real live session on the same backend still moves.
func TestBackendHealthDisabled_PartialFailureDoesNotStrandOthers(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sourceServerID, targetServerID, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	source, _ := svc.pool.GetTunnel(sourceServerID)
	target, _ := svc.pool.GetTunnel(targetServerID)
	svc.SetBackendDeviceForTest(source.ID, &testCanaryDevice{})
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})

	peer := seedIngressPeer(t, db, "r21-partial-user", "r21-partial-peer", "10.100.4.41")
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	if backend.ID != source.ID {
		t.Fatalf("precondition: admitted to %d, want %d", backend.ID, source.ID)
	}
	// A durable-only row on the same backend: connected per the DB, unknown to
	// the session manager, so MigrateSession reports ErrSessionNotFound.
	phantom := &models.VPNSession{
		UserID:          peer.userID,
		BackendTunnelID: source.ID,
		PeerPublicKey:   "r21-phantom-peer",
		AssignedIP:      "10.100.4.42",
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, phantom); err != nil {
		t.Fatal(err)
	}

	if err := svc.pool.SetTunnelStatusWithReason(ctx, sourceServerID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatal(err)
	}
	committed, err := svc.pool.GetTunnel(sourceServerID)
	if err != nil {
		t.Fatal(err)
	}
	// The whole notification must succeed even though one session cannot move.
	if err := svc.BackendHealthDisabled(ctx, committed); err != nil {
		t.Fatalf("partial session failure must not surface as a notification error: %v", err)
	}

	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.BackendTunnelID != target.ID {
		t.Fatalf("live session was stranded behind an unmigratable durable row: %+v", row)
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), target.ID) {
		t.Fatal("live session route was not redirected")
	}
	// The phantom row is still where it was: nothing invents a session.
	phantomRow, err := db.GetVPNSessionByID(ctx, phantom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if phantomRow == nil || phantomRow.BackendTunnelID != source.ID {
		t.Fatalf("unmigratable durable row was mutated: %+v", phantomRow)
	}
}

// TestHealthDisableTargets pins the candidate-selection contract: same protocol
// family, never the disabled backend, least-loaded first, deterministic.
func TestHealthDisableTargets(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sourceServerID, targetServerID, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	source, _ := svc.pool.GetTunnel(sourceServerID)
	target, _ := svc.pool.GetTunnel(targetServerID)

	if got := svc.healthDisableTargets(nil); got != nil {
		t.Fatalf("nil disabled tunnel must yield no targets, got %d", len(got))
	}
	if got := svc.healthDisableTargets(source); len(got) != 1 || got[0].ID != target.ID {
		t.Fatalf("expected only the other active tunnel as a candidate, got %d targets", len(got))
	}

	// A non-AWG candidate must be excluded from an AWG failover.
	otherFamily := *target
	otherFamily.Protocol = models.ProtocolNaive
	if got := models.NormalizeTunnelProtocol(otherFamily.Protocol); got == models.ProtocolAWG {
		t.Fatalf("fixture error: %q normalizes to AWG", otherFamily.Protocol)
	}

	// Load ordering: the least loaded candidate comes first. A third AWG
	// backend is added so the ordering is actually observable.
	thirdServerID, err := db.CreateServer(ctx, &models.Server{Name: "AP South", Host: "198.51.100.3", Protocols: map[string]any{
		"awg": map[string]any{"public_key": "ap-south-pubkey", "port": 51820},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      thirdServerID,
		InterfaceName: "awg-be-3",
		PublicKey:     "ap-south-pubkey",
		PrivateKey:    "ap-south-privkey",
		Endpoint:      "198.51.100.3:51820",
		Status:        models.TunnelStatusActive,
		LatencyMS:     40,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	third, err := svc.pool.GetTunnel(thirdServerID)
	if err != nil {
		t.Fatal(err)
	}
	// Load the second candidate so the idle third tunnel must come first.
	svc.pool.IncrementConnections(target.ID)

	targets := svc.healthDisableTargets(source)
	if len(targets) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(targets))
	}
	for i := 1; i < len(targets); i++ {
		if targets[i-1].ActiveConnections > targets[i].ActiveConnections {
			t.Fatalf("candidates are not least-loaded-first: %d then %d",
				targets[i-1].ActiveConnections, targets[i].ActiveConnections)
		}
	}
	if targets[0].ID != third.ID {
		t.Fatalf("least-loaded candidate = %d, want the idle tunnel %d", targets[0].ID, third.ID)
	}
	for _, cand := range targets {
		if cand.ID == source.ID {
			t.Fatal("the disabled backend was offered as its own migration target")
		}
	}
}
