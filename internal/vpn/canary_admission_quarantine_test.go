package vpn

// Paired enrollment-quarantine controls for issue #731.
//
// A backend under durable enrollment quarantine is enabled and may already carry
// fresh, device-bound inner canary evidence, but it has NOT been qualified or
// promoted yet. Fresh canary evidence proves the data path; it does not release
// quarantine. Only the explicit qualification/promotion transaction does.
//
// The fixture and helpers live in canary_admission_e2e_test.go, so every
// subtest below runs the real upstream engine, the real ingress router, the
// real backend device (which answers the genuine matched ICMP canary), the real
// Service admission (selection, session creation, accounting, route
// registration), the real SQLite session table and the real forwarder. The only
// difference between the admitted and refused arms is the enrollment fact.

import (
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// requireEnrollmentState pins the enrollment fact in BOTH authorities: the
// durable SQLite marker (authoritative across restarts) and the prober's
// in-memory mirror the admission path reads.
func (e *canaryAdmissionEnv) requireEnrollmentState(t *testing.T, want bool) {
	t.Helper()
	ctx := t.Context()
	durable, err := e.svc.db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatalf("read durable enrollment quarantine: %v", err)
	}
	if durable[e.blocked.ServerID] != want {
		t.Fatalf("durable enrollment quarantine for server %d = %v, want %v",
			e.blocked.ServerID, durable[e.blocked.ServerID], want)
	}
	if got := e.svc.prober.IsPendingEnrollment(e.blocked.ServerID); got != want {
		t.Fatalf("in-memory enrollment quarantine for server %d = %v, want %v",
			e.blocked.ServerID, got, want)
	}
	// A prober constructed over the same database restores the durable marker on
	// startup. Asserting it here keeps the refusal bound to the persisted fact,
	// not to whatever this process happens to remember.
	restored := tunnel.NewHealthProber(e.svc.pool, e.svc.db, e.svc.prober.Config())
	if got := restored.IsPendingEnrollment(e.blocked.ServerID); got != want {
		t.Fatalf("restored enrollment quarantine for server %d = %v, want %v",
			e.blocked.ServerID, got, want)
	}
}

// requireNoAdmissionLeftBehind asserts a refused new admission created NO
// session row, route, affinity or connection-count increment.
func (e *canaryAdmissionEnv) requireNoAdmissionLeftBehind(t *testing.T, peerKey string, wantGauge int) {
	t.Helper()
	ctx := t.Context()
	sess, err := e.svc.db.GetVPNSessionByPeerKey(ctx, peerKey)
	if err != nil {
		t.Fatalf("read session row for refused peer: %v", err)
	}
	if sess != nil {
		t.Fatalf("refused admission left a session row for the peer: id=%s backend=%d status=%s",
			sess.ID, sess.BackendTunnelID, sess.Status)
	}
	if route := e.svc.forwarder.RouteSessionID(peerKey); route != "" {
		t.Fatalf("refused admission left a forwarder route owned by %q", route)
	}
	if e.svc.stickyMgr != nil {
		if backendID, ok := e.svc.stickyMgr.GetPeerAffinity(peerKey); ok {
			t.Fatalf("refused admission left a sticky affinity to backend %d", backendID)
		}
	}
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("re-read tunnel: %v", err)
	}
	if cur.ActiveConnections != wantGauge {
		t.Fatalf("refused admission changed the backend gauge to %d, want %d", cur.ActiveConnections, wantGauge)
	}
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("refused admission changed the backend status to %q", cur.Status)
	}
}

// ownershipForPeer builds the resolver-shaped ownership record for a real
// enrolled portal client from its durable connection row — the same identity,
// connection ID, user ID and leased IP the ingress resolver carries, so the
// production admission seam can be exercised without a live handshake.
func (e *canaryAdmissionEnv) ownershipForPeer(t *testing.T, peer enginePeer) ingress.PeerOwnership {
	t.Helper()
	ctx := t.Context()
	conn, err := e.svc.db.GetConnectionByClientID(ctx, peer.publicKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("read durable connection for %s: conn=%v err=%v", ingress.RedactKey(peer.publicKey), conn, err)
	}
	if conn.UserID == "" {
		t.Fatalf("durable connection for %s has no owner", ingress.RedactKey(peer.publicKey))
	}
	return ingress.PeerOwnership{
		PeerPublicKey: peer.publicKey,
		ConnectionID:  conn.ID,
		UserID:        conn.UserID,
		IP:            netip.MustParseAddr(peer.assignedIP),
	}
}

// TestCanaryAdmission_QualifiedControlThroughSameBranch is the positive control
// of the pair: with quarantine released the identical backend, device, canary
// verdict and blocked label admit a first-time client, including the SQLite
// session row and the sticky affinity.
func TestCanaryAdmission_QualifiedControlThroughSameBranch(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	e.requireEnrollmentState(t, false)
	if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: status = %q, want handshake_blocked", cur.Status)
	}
	if c, err := e.dial(t, e.fresh, e.freshSaved, 10*time.Second, "quarantine-qualified"); err != nil {
		t.Fatalf("qualified backend refused a new client: %v", err)
	} else if c != nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	e.requireAdmittedOnBlockedBackend(t, e.fresh.publicKey, 1)

	o := e.ownership(t, e.fresh.publicKey)
	sess, err := e.svc.db.GetVPNSessionByPeerKey(t.Context(), e.fresh.publicKey)
	if err != nil {
		t.Fatalf("read admitted session row: %v", err)
	}
	if sess == nil || sess.ID != o.sessionID || sess.BackendTunnelID != e.blocked.ID {
		t.Fatalf("SQLite session row does not match the admitted session: %+v (want id=%s backend=%d)", sess, o.sessionID, e.blocked.ID)
	}
	if backendID, ok := e.svc.stickyMgr.GetPeerAffinity(e.fresh.publicKey); !ok || backendID != e.blocked.ID {
		t.Fatalf("qualified admission affinity = %d/%v, want backend %d", backendID, ok, e.blocked.ID)
	}
}

// TestCanaryAdmission_PendingEnrollmentRefusesNewAdmission is the negative arm of
// the pair: the same backend, device, canary verdict and blocked label, with
// enrollment quarantine still set, must refuse a first-time client and leave no
// session row, route, affinity or count increment — while the client already
// admitted before the quarantine keeps its payload.
func TestCanaryAdmission_PendingEnrollmentRefusesNewAdmission(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	// Establish one client while the backend is still qualified. This is the
	// established route that quarantine must not disturb.
	c, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "quarantine-established")
	if err != nil {
		t.Fatalf("initial qualified admission: %v", err)
	}
	e.svc.SetPendingEnrollment(e.blocked.ServerID, true)
	e.requireEnrollmentState(t, true)
	if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: status = %q, want handshake_blocked", cur.Status)
	}
	before, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if before.ActiveConnections != 1 {
		t.Fatalf("fixture: gauge = %d, want the established session to count 1", before.ActiveConnections)
	}

	// Refusal through the production admission seam the router itself uses
	// (EnsureSessionForIngress). A dialling client engine retries its handshake,
	// so refusal is asserted on the seam to keep the refusal exactly one attempt.
	_, _, admitErr := e.svc.EnsureSessionForIngress(t.Context(), e.ownershipForPeer(t, e.fresh))
	t.Logf("pending=true durable=true status=handshake_blocked admitErr=%v", admitErr)
	if admitErr == nil {
		t.Fatal("a brand-new client was admitted onto a backend still under enrollment quarantine")
	}
	e.requireNoAdmissionLeftBehind(t, e.fresh.publicKey, 1)
	// The refusal is a refusal to admit, not a change of the enrollment fact.
	e.requireEnrollmentState(t, true)

	// Preservation: the client admitted before the quarantine still forwards.
	if err := echo(c, "canary-admission-quarantine-established", 5*time.Second); err != nil {
		t.Fatalf("enrollment quarantine disturbed the established route: %v", err)
	}
}

// TestCanaryAdmission_PromotionIsTheReleasePoint proves the release boundary:
// a successful canary does NOT release quarantine (step 3 refuses), the explicit
// qualification/promotion transaction does (durably, surviving a fresh prober),
// and the same backend then admits through the very same blocked branch.
func TestCanaryAdmission_PromotionIsTheReleasePoint(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	e.svc.SetPendingEnrollment(e.blocked.ServerID, true)
	e.requireEnrollmentState(t, true)
	if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: status = %q, want handshake_blocked", cur.Status)
	}

	// Fresh matched-device canary success on a quarantined backend is not
	// qualification: the new client is refused.
	_, _, beforeReleaseErr := e.svc.EnsureSessionForIngress(t.Context(), e.ownershipForPeer(t, e.fresh))
	t.Logf("pending=true durable=true status=handshake_blocked admitErr=%v", beforeReleaseErr)
	if beforeReleaseErr == nil {
		t.Fatal("fresh canary success released enrollment quarantine without qualification")
	}
	e.requireNoAdmissionLeftBehind(t, e.fresh.publicKey, 0)
	e.requireEnrollmentState(t, true)

	// The legitimate release: the production promotion transaction commits the
	// qualification verdict and removes the durable marker together.
	if err := e.svc.PromoteQualifiedTunnel(t.Context(), e.blocked, 20); err != nil {
		t.Fatalf("promote qualified backend: %v", err)
	}
	e.requireEnrollmentState(t, false)
	if cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID); err != nil || cur.Status != models.TunnelStatusActive {
		t.Fatalf("after promotion status = %v/%v, want active", cur, err)
	}

	// Outside quarantine the identical blocked-with-fresh-evidence state admits.
	if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: status after release = %q, want handshake_blocked", cur.Status)
	}
	if _, _, admitErr := e.svc.EnsureSessionForIngress(t.Context(), e.ownershipForPeer(t, e.fresh)); admitErr != nil {
		t.Fatalf("released backend refused a new client: %v", admitErr)
	}
	e.requireAdmittedOnBlockedBackend(t, e.fresh.publicKey, 1)
	sess, err := e.svc.db.GetVPNSessionByPeerKey(t.Context(), e.fresh.publicKey)
	if err != nil || sess == nil || sess.BackendTunnelID != e.blocked.ID {
		t.Fatalf("SQLite session row after release = %+v/%v, want backend %d", sess, err, e.blocked.ID)
	}
}
