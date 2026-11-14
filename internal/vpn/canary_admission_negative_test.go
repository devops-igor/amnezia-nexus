package vpn

// Negative and guard cases for issue #731: a blocked backend whose inner data
// path is not freshly proven, or whose attached device changed, must still
// refuse a first admission, and the non-health guards keep their authority.
// The fixture and helpers live in canary_admission_e2e_test.go.

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// canaryTestClock is the freshness clock the stale-evidence case steps. The
// prober reads it from the ingress engine goroutine, not the test goroutine that
// advances it, so a plain time.Time there is a data race. Nanoseconds since the
// epoch make each step one atomic store, so a reader sees a coherent instant.
type canaryTestClock struct{ nanos atomic.Int64 }

func (c *canaryTestClock) now() time.Time          { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *canaryTestClock) set(t time.Time)         { c.nanos.Store(t.UnixNano()) }
func (c *canaryTestClock) advance(d time.Duration) { c.set(c.now().Add(d)) }

// TestCanaryAdmission_RefusesWithoutFreshEvidence is the label-only negative
// control: every blocked-but-unproven backend must still refuse a first
// admission, which is what stops "admit anything blocked" from shipping.
func TestCanaryAdmission_RefusesWithoutFreshEvidence(t *testing.T) {
	t.Run("never probed inner path", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		// Blocked by label only: no sweep ran, so no canary evidence exists.
		if err := e.svc.pool.SetTunnelStatus(t.Context(), e.blocked.ServerID, models.TunnelStatusHandshakeBlocked, 0); err != nil {
			t.Fatalf("set blocked status: %v", err)
		}
		e.requireRefusedNewAdmission(t, "never-probed")
		if n := e.engine.Router().StatsSnapshot().NoActiveBackendDrops; n == 0 {
			t.Fatal("refusal was not accounted as a no-active-backend drop")
		}
	})

	t.Run("transient suspicion keeps routes but refuses new clients", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		c, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-transient")
		if err != nil {
			t.Fatalf("initial admission: %v", err)
		}
		e.sweepFailingOuter(t)
		// One inner failure: below the confirmation threshold, and the
		// established session keeps the blocked label.
		e.dev.state.Store(canaryDevCanaryOnly)
		cur := e.sweepFailingOuter(t)
		if cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q, want handshake_blocked preserved for one inner failure", cur.Status)
		}
		if fails := e.svc.prober.GetCanaryFailCount(e.blocked.ServerID); fails != 1 {
			t.Fatalf("fixture: inner failure count = %d, want 1", fails)
		}
		e.requireRefusedNewAdmission(t, "transient")
		// The established client must keep its route through transient suspicion.
		e.dev.state.Store(canaryDevAlive)
		if err := echo(c, "canary-admission-existing-survives", 5*time.Second); err != nil {
			t.Fatalf("transient inner suspicion disturbed the established route: %v", err)
		}
	})

	t.Run("dead inner path", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		if _, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-dead-seed"); err != nil {
			t.Fatalf("initial admission: %v", err)
		}
		e.sweepFailingOuter(t)
		e.dev.state.Store(canaryDevDead)
		e.sweepFailingOuter(t)
		e.requireRefusedNewAdmission(t, "dead-inner")
	})

	t.Run("stale evidence", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		// Atomic hand-off: the prober reads the clock from the ingress engine
		// goroutine. The threshold below is unchanged.
		clock := &canaryTestClock{}
		clock.set(time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC))
		e.svc.prober.SetNowFuncForTest(clock.now)
		t.Cleanup(func() { e.svc.prober.SetNowFuncForTest(nil) })
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		// Step past the freshness bound derived from the probe cadence.
		cfg := e.svc.prober.Config()
		clock.advance(cfg.Interval*2 + cfg.Timeout)
		e.requireRefusedNewAdmission(t, "stale-evidence")
	})

	t.Run("replaced device on the same tunnel", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		// Same tunnel row and ID, different device object: a credential
		// replacement or a detach/re-attach.
		replacement := &canaryBackendDevice{
			inner:   e.dev.inner,
			created: e.dev.created.Add(time.Hour),
			hooks:   map[uint64]tunnel.CanaryResponseHook{},
		}
		e.svc.mu.Lock()
		e.svc.backendDevices[e.blocked.ID] = replacement
		e.svc.mu.Unlock()
		e.svc.forwarder.AttachBackendDevice(e.blocked.ID, replacement)

		e.requireRefusedNewAdmission(t, "replaced-device")
	})

	t.Run("detached device", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		e.svc.mu.Lock()
		delete(e.svc.backendDevices, e.blocked.ID)
		e.svc.mu.Unlock()
		e.requireRefusedNewAdmission(t, "detached-device")
	})
}

// TestCanaryAdmission_GuardsStillRefuse proves the non-health guards keep their
// authority for evidence-carrying blocked backends.
func TestCanaryAdmission_GuardsStillRefuse(t *testing.T) {
	t.Run("administrative disable", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		if err := e.svc.pool.SetTunnelEnabled(t.Context(), e.blocked.ServerID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("disable backend: %v", err)
		}
		e.requireRefusedNewAdmission(t, "admin-disabled")
	})

	t.Run("per-backend capacity", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t, func(cfg *models.VPNConfig) { cfg.MaxPeersPerBackend = 1 })
		if _, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-capacity-seed"); err != nil {
			t.Fatalf("initial admission: %v", err)
		}
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		before := e.ownership(t, e.existing.publicKey)
		if before.activeConns != 1 {
			t.Fatalf("fixture: gauge = %d, want 1 (capacity limit is 1)", before.activeConns)
		}
		// The blocked backend is at capacity, so it must be refused even with
		// fresh evidence; the only other backend is disabled.
		e.requireRefusedNewAdmission(t, "capacity")
		after := e.ownership(t, e.existing.publicKey)
		if after.activeConns != before.activeConns {
			t.Fatalf("capacity refusal changed the gauge: %d -> %d", before.activeConns, after.activeConns)
		}
		if after.routeSessionID != before.routeSessionID {
			t.Fatalf("capacity refusal disturbed the established route: %q -> %q", before.routeSessionID, after.routeSessionID)
		}
	})
}
