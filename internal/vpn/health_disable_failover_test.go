package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// forcedDisableOuter returns an outer probe that always fails for the given
// endpoint and succeeds elsewhere, so exactly one backend looks handshake
// blocked while its replacement stays healthy.
func forcedDisableOuter(blockedEndpoint string) func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
	return func(_ context.Context, endpoint, _, _, _, _ string, _, _ any, _, _ int, _ time.Duration) (time.Duration, error) {
		if endpoint == blockedEndpoint {
			return 0, errors.New("outer handshake blocked by DPI")
		}
		return time.Millisecond, nil
	}
}

// TestHealthDisableAutomaticallyMigratesEstablishedSession is the round21
// regression for the human-reported blocker: a terminal health auto-disable
// (both tiers failing) must move an already-established session to a healthy
// backend by itself.
//
// The oracle deliberately does NOT go through EnsureBackendSessionForIngress
// after the disable. That path only proves forced ingress re-admission: it
// creates a new session on a fresh backend and re-registers a route, which
// would look like a "migration" even if nothing had moved the original
// session. Here the ONLY action after the initial admission is driving the
// ordinary HealthProber loop, then reading durable state, the live forwarder
// route, the pool accounting and the sticky affinity.
func TestHealthDisableAutomaticallyMigratesEstablishedSession(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sourceServerID, targetServerID, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	source, err := svc.pool.GetTunnel(sourceServerID)
	if err != nil {
		t.Fatal(err)
	}
	target, err := svc.pool.GetTunnel(targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if source.ID == target.ID {
		t.Fatal("fixture requires two distinct backend tunnels")
	}

	// Real devices so the inner canary has a data plane to fail against.
	dev := &historyCanaryDevice{}
	svc.SetBackendDeviceForTest(source.ID, dev)
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})

	peer := seedIngressPeer(t, db, "r21-user", "r21-peer", "10.100.4.21")
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	if backend.ID != source.ID {
		t.Fatalf("precondition: session admitted to backend %d, want source %d", backend.ID, source.ID)
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatal("precondition: admitted session has no live route on the source backend")
	}
	// `source`/`target` above are snapshots taken before admission; re-read.
	source, err = svc.pool.GetTunnel(sourceServerID)
	if err != nil {
		t.Fatal(err)
	}
	target, err = svc.pool.GetTunnel(targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if source.ActiveConnections != 1 || target.ActiveConnections != 0 {
		t.Fatalf("precondition: counters source=%d target=%d, want 1/0", source.ActiveConnections, target.ActiveConnections)
	}

	svc.SetProbeFunc(forcedDisableOuter(source.Endpoint))
	defer svc.SetProbeFunc(nil)
	// Service.SetProbeFunc installs a default *successful* canary when none is
	// configured, so the real device probe must be restored afterwards.
	svc.SetCanaryProbeFunc(nil)

	threshold := svc.prober.Config().FailureThreshold
	if threshold <= 0 {
		threshold = 3
	}
	// Sustained inner loss: the outer handshake is blocked AND the data plane
	// is dead, so both tiers fail and the terminal state is disabled/health.
	dev.fail.Store(true)

	for i := 1; i <= threshold; i++ {
		cur, getErr := svc.pool.GetTunnel(sourceServerID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if _, probeErr := svc.prober.ProbeTunnel(ctx, cur); probeErr == nil {
			t.Fatalf("cycle %d: injected outer failure was not observed", i)
		}
		if i < threshold {
			// Below the inner threshold the session must stay exactly put
			// (issue #713: bounded established-session preservation).
			assertRound21SessionPinned(t, svc, db, peer, sess, source, "cycle "+itoa(i))
		}
	}

	// --- Terminal state: health auto-disable, still administratively enabled.
	final, err := svc.pool.GetTunnel(sourceServerID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != models.TunnelStatusDisabled {
		t.Fatalf("sustained two-tier loss left status %q, want %q", final.Status, models.TunnelStatusDisabled)
	}
	if final.DisableReason != models.DisableReasonHealth {
		t.Fatalf("disable reason %q, want %q", final.DisableReason, models.DisableReasonHealth)
	}
	if !final.Enabled {
		t.Fatal("health auto-disable must not clear administrative eligibility (self-healing must be able to recover it)")
	}

	// --- The actual blocker: the established session moved BY ITSELF.
	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row == nil {
		t.Fatal("established session row disappeared during automatic health-disable failover")
	}
	if row.BackendTunnelID != target.ID {
		t.Fatalf("durable session %s still pinned to backend %d, want automatic migration to %d",
			sess.ID, row.BackendTunnelID, target.ID)
	}
	if row.Status != "connected" {
		t.Fatalf("migrated session status %q, want connected (the client is still live)", row.Status)
	}

	live, ok := svc.sessionMgr.GetSessionSnapshotByID(sess.ID)
	if !ok {
		t.Fatal("in-memory session vanished during automatic health-disable failover")
	}
	if live.BackendTunnelID != target.ID {
		t.Fatalf("in-memory session backend %d, want %d", live.BackendTunnelID, target.ID)
	}

	// Route ownership: the old route must be REDIRECTED, not merely absent.
	if svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatal("live forwarder route still points at the disabled backend")
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), target.ID) {
		t.Fatal("live forwarder route was not redirected to the healthy backend")
	}

	// Accounting: the same single session, on the new backend.
	afterSource, err := svc.pool.GetTunnel(sourceServerID)
	if err != nil {
		t.Fatal(err)
	}
	afterTarget, err := svc.pool.GetTunnel(targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if afterSource.ActiveConnections != 0 {
		t.Fatalf("disabled backend still reports %d active connections", afterSource.ActiveConnections)
	}
	if afterTarget.ActiveConnections != 1 {
		t.Fatalf("healthy backend reports %d active connections, want exactly 1", afterTarget.ActiveConnections)
	}

	// Sticky affinity moved with the session, so a rekey of the same peer is
	// not re-pinned onto the disabled backend.
	if aff, ok := svc.stickyMgr.GetPeerAffinity(peer.peerKey); !ok || aff != target.ID {
		t.Fatalf("sticky affinity after automatic failover = %d (present=%t), want %d", aff, ok, target.ID)
	}

	// Idempotency: the prober may notify again (another worker, a
	// reconciliation) without double-counting the already-migrated session.
	if err := svc.BackendHealthDisabled(ctx, final); err != nil {
		t.Fatalf("repeated health-disable notification failed: %v", err)
	}
	again, err := svc.pool.GetTunnel(targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if again.ActiveConnections != 1 {
		t.Fatalf("repeated notification changed target accounting to %d, want 1", again.ActiveConnections)
	}
}

// TestHealthDisableNotificationSurvivesPreFixWiring documents the exact defect
// this round fixes, using the production probe path with the notifier cleared —
// the pre-round21 composition. Without it the established session is stranded
// on a disabled backend and only a later ingress admission rescues the peer.
func TestHealthDisableNotificationSurvivesPreFixWiring(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sourceServerID, targetServerID, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	// Pre-round21 wiring: the prober commits the status change and nothing
	// else. Equivalent to the production binary before this change.
	svc.SetHealthDisabledNotifier(nil)

	source, _ := svc.pool.GetTunnel(sourceServerID)
	target, _ := svc.pool.GetTunnel(targetServerID)
	dev := &historyCanaryDevice{}
	svc.SetBackendDeviceForTest(source.ID, dev)
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})
	svc.SetCanaryProbeFunc(nil)

	peer := seedIngressPeer(t, db, "r21-prefix-user", "r21-prefix-peer", "10.100.4.22")
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	if backend.ID != source.ID {
		t.Fatalf("precondition: admitted to %d, want %d", backend.ID, source.ID)
	}

	svc.SetProbeFunc(forcedDisableOuter(source.Endpoint))
	defer svc.SetProbeFunc(nil)
	svc.SetCanaryProbeFunc(nil)
	dev.fail.Store(true)

	threshold := svc.prober.Config().FailureThreshold
	for i := 0; i < threshold; i++ {
		cur, getErr := svc.pool.GetTunnel(sourceServerID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		_, _ = svc.prober.ProbeTunnel(ctx, cur)
	}

	final, _ := svc.pool.GetTunnel(sourceServerID)
	if final.Status != models.TunnelStatusDisabled || final.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected terminal disabled/health, got %q/%q", final.Status, final.DisableReason)
	}
	// This is the reported defect, asserted directly: the durable session is
	// still on the disabled backend and its live route was never redirected.
	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row != nil && row.BackendTunnelID == target.ID {
		t.Fatal("pre-fix wiring unexpectedly migrated the session; the regression oracle is not discriminating")
	}
	if row == nil || row.BackendTunnelID != source.ID {
		t.Fatalf("pre-fix expectation was a stranded session on %d, got row=%+v", source.ID, row)
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatal("pre-fix expectation was a live route on the disabled backend")
	}
}

// TestHealthDisablePreservesAdministrativeIntent verifies the new notification
// cannot override an administrative decision: if the backend was re-enabled (or
// re-decided) between the probe's commit and the notification, no migration or
// status change happens.
func TestHealthDisablePreservesAdministrativeIntent(t *testing.T) {
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

	peer := seedIngressPeer(t, db, "r21-admin-user", "r21-admin-peer", "10.100.4.23")
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	if backend.ID != source.ID {
		t.Fatalf("precondition: admitted to %d, want %d", backend.ID, source.ID)
	}

	// Simulate an administrative re-enable that landed between the prober's
	// disable commit and the notification: the tunnel is enabled again and its
	// status is no longer the health-disabled one the prober committed.
	if err := svc.pool.SetTunnelStatus(ctx, sourceServerID, models.TunnelStatusActive, 0); err != nil {
		t.Fatal(err)
	}
	stale := *source
	stale.Status = models.TunnelStatusDisabled
	stale.DisableReason = models.DisableReasonHealth
	stale.StateVersion = 0 // unknown commit version must not force a migration

	if err := svc.BackendHealthDisabled(ctx, &stale); err != nil {
		t.Fatal(err)
	}

	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row == nil || row.BackendTunnelID != source.ID {
		t.Fatalf("stale health-disable notification moved a session the administrator put back in service: %+v", row)
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatal("stale health-disable notification redirected a route the administrator put back in service")
	}
	after, _ := svc.pool.GetTunnel(sourceServerID)
	if after.Status != models.TunnelStatusActive {
		t.Fatalf("stale notification changed status to %q, want active", after.Status)
	}
}

// assertRound21SessionPinned asserts the established session, its durable row,
// its route, the pool counters and the sticky affinity are untouched.
func assertRound21SessionPinned(t *testing.T, svc *Service, db interface {
	GetVPNSessionByID(context.Context, string) (*models.VPNSession, error)
}, peer ingressTestPeer, sess *models.VPNSession, source *models.BackendTunnel, when string) {
	t.Helper()
	ctx := context.Background()
	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("%s: %v", when, err)
	}
	if row == nil || row.BackendTunnelID != source.ID {
		t.Fatalf("%s: session moved before the inner threshold: %+v", when, row)
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatalf("%s: route left the preserved backend", when)
	}
	cur, err := svc.pool.GetTunnel(source.ServerID)
	if err != nil {
		t.Fatalf("%s: %v", when, err)
	}
	if cur.ActiveConnections != 1 {
		t.Fatalf("%s: source accounting changed to %d, want 1", when, cur.ActiveConnections)
	}
	if aff, ok := svc.stickyMgr.GetPeerAffinity(peer.peerKey); !ok || aff != source.ID {
		t.Fatalf("%s: sticky affinity changed to %d (present=%t), want %d", when, aff, ok, source.ID)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
