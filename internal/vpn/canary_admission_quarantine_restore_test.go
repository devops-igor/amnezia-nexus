package vpn

// Persisted-restoration challenge for issue #731.
//
// The admission guard must be driven by the DURABLE enrollment fact, not by
// whatever the running prober happens to remember. A real restart reconstructs
// the prober from SQLite (internal/vpn/tunnel/health.go, prober construction),
// so this control re-creates the prober from the same database through the same
// wiring the production composition root installs, while the tunnel row keeps
// its persisted handshake_blocked status and its attached device. Admission must
// still refuse, and the refusal must not be attributable to missing canary
// evidence: the fresh matched-device canary runs on the restored prober first.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// restoreProberFromDatabase rebuilds the health consumer from the durable state
// exactly as NewVPNService does: a prober constructed over the existing pool and
// database (which restores `backend_pending_enrollment:*`), the service as its
// device provider, and the real production probe/canary paths.
func (e *canaryAdmissionEnv) restoreProberFromDatabase(t *testing.T) *tunnel.HealthProber {
	t.Helper()
	restored := tunnel.NewHealthProber(e.svc.pool, e.svc.db, e.svc.prober.Config())
	restored.SetMultiProtocolEnabled(true)
	restored.SetDeviceProvider(e.svc)
	// Outer handshakes keep failing, so the re-established label is
	// handshake_blocked; the inner canary is NOT overridden, so it is decided by
	// the real attached device.
	restored.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, errors.New("controlled fresh outer handshake timeout")
	})
	restored.SetCanaryProbeFunc(nil)
	e.svc.SetHealthProber(restored)
	if got := e.svc.prober.GetCanaryProbeFunc(); got != nil {
		t.Fatal("restored prober: a canary override is installed")
	}
	return restored
}

// TestCanaryAdmission_RestoredQuarantineRefusesNewAdmission proves that the
// durable marker restored at startup keeps refusing new admissions after the
// blocked label and fresh device-bound canary evidence are re-established by a
// reconstructed prober.
func TestCanaryAdmission_RestoredQuarantineRefusesNewAdmission(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	// Primary writer path (handler/deploy): the durable marker is set through the
	// prober, which persists it in SQLite.
	e.svc.SetPendingEnrollment(e.blocked.ServerID, true)
	if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: status = %q, want handshake_blocked", cur.Status)
	}

	restored := e.restoreProberFromDatabase(t)
	if !restored.IsPendingEnrollment(e.blocked.ServerID) {
		t.Fatal("the reconstructed prober did not restore the durable enrollment marker")
	}
	// Re-establish a fresh, device-bound inner success on the reconstructed
	// prober: the guard under test must not be excused by absent evidence.
	if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: status after restore = %q, want handshake_blocked", cur.Status)
	}
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	dev := e.svc.backendDevices[cur.ID]
	if dev == nil {
		t.Fatal("fixture: no attached device after restore")
	}
	if !restored.CanaryAdmissible(cur, dev.CreatedAt()) {
		t.Fatal("fixture: the restored prober holds no admissible canary evidence, so a refusal would prove nothing")
	}

	_, _, admitErr := e.svc.EnsureSessionForIngress(t.Context(), e.ownershipForPeer(t, e.fresh))
	t.Logf("restored pending=true durable=true status=handshake_blocked canaryAdmissible=true admitErr=%v", admitErr)
	if admitErr == nil {
		t.Fatal("a brand-new client was admitted while the durable enrollment marker stood restored")
	}
	e.requireNoAdmissionLeftBehind(t, e.fresh.publicKey, 0)
	durable, err := e.svc.db.GetBackendPendingEnrollments(t.Context())
	if err != nil {
		t.Fatalf("read durable marker: %v", err)
	}
	if !durable[e.blocked.ServerID] {
		t.Fatal("refusal cleared the durable enrollment marker")
	}

	// The release point is still explicit promotion, and it admits through the
	// same branch on the same restored prober.
	if err := e.svc.PromoteQualifiedTunnel(t.Context(), e.blocked, 20); err != nil {
		t.Fatalf("promote qualified backend: %v", err)
	}
	if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: status after release = %q, want handshake_blocked", cur.Status)
	}
	if _, _, admitErr := e.svc.EnsureSessionForIngress(t.Context(), e.ownershipForPeer(t, e.existing)); admitErr != nil {
		t.Fatalf("released backend refused a new client after restore: %v", admitErr)
	}
	e.requireAdmittedOnBlockedBackend(t, e.existing.publicKey, 1)
}
