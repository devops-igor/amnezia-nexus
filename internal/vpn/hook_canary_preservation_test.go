package vpn

// Group A completion (issue #794): an attachment-hook failure must not withdraw a
// backend whose EXISTING attached device still answers fresh matched in-tunnel
// canary replies.
//
// Reachability established before writing this (see the checkpoint's evidence
// section): the hook returns nil whenever a usable device is already attached, so
// a hook FAILURE always means the attachment attempt itself failed. It is still
// unsafe, because the attempt can fail on the remote/credential/forwarder side
// while the previously attached device keeps forwarding payload, and because the
// counter it advances is an attachment-failure streak that may already be primed
// from earlier failures. Both are exercised below through the real prober, the
// real pool CAS and the real canary oracle.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// hookPreservationEnv is the shared #731 fixture with helpers for driving the
// attachment hook and observing whether fresh canary evidence is admissible.
type hookPreservationEnv struct {
	*canaryAdmissionEnv
}

func newHookPreservationEnv(t *testing.T) *hookPreservationEnv {
	t.Helper()
	return &hookPreservationEnv{canaryAdmissionEnv: newCanaryAdmissionEnv(t)}
}

// setOuterOK installs a healthy outer handshake so the attachment hook runs.
func (e *hookPreservationEnv) setOuterOK() {
	e.svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
}

// setHookFails installs the attachment-hook outcome.
func (e *hookPreservationEnv) setHookFails(fails bool) {
	e.svc.prober.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error {
		if fails {
			return errors.New("data-plane attach failed: remote peer registration unavailable")
		}
		return nil
	})
}

// probeOnce runs one real probe against the live pool row.
func (e *hookPreservationEnv) probeOnce(t *testing.T) (*models.BackendTunnel, error) {
	t.Helper()
	live, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	_, probeErr := e.svc.prober.ProbeTunnel(t.Context(), live)
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("re-read tunnel: %v", err)
	}
	return cur, probeErr
}

// admissible reports whether the currently attached device's fresh canary
// evidence authorizes admission for the current row.
func (e *hookPreservationEnv) admissible(t *testing.T, cur *models.BackendTunnel) bool {
	t.Helper()
	dev := e.svc.backendDevices[e.blocked.ID]
	if dev == nil {
		return false
	}
	var created time.Time
	if dg, ok := dev.(tunnel.DeviceGeneration); ok {
		created = dg.CreatedAt()
	}
	return e.svc.prober.CanaryAdmissible(cur, created)
}

// establishFreshCanary takes the backend to active with a healthy outer handshake
// so the inner canary records fresh evidence from the attached device.
func (e *hookPreservationEnv) establishFreshCanary(t *testing.T) {
	t.Helper()
	e.dev.state.Store(canaryDevAlive)
	e.setOuterOK()
	e.setHookFails(false)
	if cur, err := e.probeOnce(t); err != nil || cur.Status != models.TunnelStatusActive {
		t.Fatalf("precondition: status=%q err=%v, want active with fresh canary", cur.Status, err)
	}
	cur, _ := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if !e.admissible(t, cur) {
		t.Fatal("precondition: inner canary evidence is not admissible after a healthy probe")
	}
}

// TestHookFailurePreservesBackendWithFreshCanary is the headline requirement: the
// attachment-failure threshold must not withdraw a backend whose existing device
// still answers fresh matched replies. Routing eligibility is preserved as
// handshake_blocked (the outer handshake was never the failing observation here,
// but the backend must not be relabelled active while its attachment is failing),
// and the device, session, route and accounting survive.
func TestHookFailurePreservesBackendWithFreshCanary(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	devBefore := e.svc.backendDevices[e.blocked.ID]
	threshold := e.svc.prober.Config().FailureThreshold
	e.setHookFails(true)

	// Reach the attachment threshold. The inner path still answers throughout.
	var cur *models.BackendTunnel
	for i := 0; i < threshold; i++ {
		cur, _ = e.probeOnce(t)
		if cur.Status == models.TunnelStatusDisabled {
			t.Fatalf("attachment failure %d of %d health-disabled the backend while fresh matched canary evidence was admissible", i+1, threshold)
		}
	}

	if !cur.Enabled {
		t.Fatal("attachment failures cleared administrative eligibility")
	}
	if cur.DisableReason == models.DisableReasonHealth {
		t.Fatalf("attachment failure recorded a health disable reason: %q", cur.DisableReason)
	}
	if e.svc.backendDevices[e.blocked.ID] != devBefore {
		t.Fatal("preservation must keep the SAME attached device")
	}
	if devBefore.IsClosed() {
		t.Fatal("preservation must not close the established device")
	}
	if got := e.svc.GetBackendDeviceForTest(e.blocked.ID); got != devBefore {
		t.Fatal("device provider no longer returns the preserved device")
	}

	// The durable row must agree with the in-memory one.
	dbRow, err := e.svc.db.GetBackendTunnel(t.Context(), cur.ID)
	if err != nil || dbRow == nil {
		t.Fatalf("read durable row: %v", err)
	}
	if dbRow.Status == models.TunnelStatusDisabled {
		t.Fatalf("durable row was health-disabled: %q/%q", dbRow.Status, dbRow.DisableReason)
	}
}

// TestHookFailurePreservationKeepsAdmissionAndPayload proves the preserved
// backend is still the same working backend: an established client keeps its
// session/route/accounting and payload, and a brand-new client is admitted there.
func TestHookFailurePreservationKeepsAdmissionAndPayload(t *testing.T) {
	e := newHookPreservationEnv(t)

	conn, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "hook-preserve-existing")
	if err != nil {
		t.Fatalf("initial admission: %v", err)
	}
	if err := echo(conn, "hook-preserve-pre", 5*time.Second); err != nil {
		t.Fatalf("pre-failure payload: %v", err)
	}
	before := e.ownership(t, e.existing.publicKey)
	if !before.admitted || before.activeConns != 1 {
		t.Fatalf("precondition ownership = %+v", before)
	}

	devBefore := e.svc.backendDevices[e.blocked.ID]
	threshold := e.svc.prober.Config().FailureThreshold
	e.setOuterOK()
	e.setHookFails(true)
	for i := 0; i < threshold; i++ {
		e.probeOnce(t)
	}
	cur, _ := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if cur.Status == models.TunnelStatusDisabled {
		t.Fatalf("threshold attachment failures disabled the backend: %q/%q", cur.Status, cur.DisableReason)
	}

	after := e.ownership(t, e.existing.publicKey)
	if after.sessionID != before.sessionID {
		t.Fatalf("established session replaced: %q -> %q", before.sessionID, after.sessionID)
	}
	if after.routeSessionID != before.sessionID {
		t.Fatalf("forwarder route lost: %q, want %q", after.routeSessionID, before.sessionID)
	}
	if after.activeConns != before.activeConns {
		t.Fatalf("connection accounting changed: %d -> %d", before.activeConns, after.activeConns)
	}
	if e.svc.backendDevices[e.blocked.ID] != devBefore {
		t.Fatal("device replaced despite preserved inner evidence")
	}
	if err := echo(conn, "hook-preserve-post", 5*time.Second); err != nil {
		t.Fatalf("established client lost payload: %v", err)
	}

	// A new client must still be admitted onto the preserved backend.
	fresh, err := e.dial(t, e.fresh, e.freshSaved, 10*time.Second, "hook-preserve-fresh")
	if err != nil {
		t.Fatalf("new client refused on the preserved backend: %v", err)
	}
	if err := echo(fresh, "hook-preserve-new", 5*time.Second); err != nil {
		t.Fatalf("new client got no bidirectional payload: %v", err)
	}
}

// TestHookFailureRefusals pins every case where preservation must NOT apply.
func TestHookFailureRefusals(t *testing.T) {
	t.Run("no attached device is not preservation", func(t *testing.T) {
		e := newHookPreservationEnv(t)
		e.setOuterOK()
		e.setHookFails(true)
		// No device: there is no in-tunnel evidence, so the attachment threshold
		// must still withdraw the backend.
		e.svc.SetBackendDeviceForTest(e.blocked.ID, nil)
		threshold := e.svc.prober.Config().FailureThreshold
		var cur *models.BackendTunnel
		for i := 0; i < threshold; i++ {
			cur, _ = e.probeOnce(t)
		}
		if cur.Status != models.TunnelStatusDisabled || cur.DisableReason != models.DisableReasonHealth {
			t.Fatalf("unknown health was treated as health: status=%q reason=%q", cur.Status, cur.DisableReason)
		}
	})

	t.Run("failed inner canary still withdraws at threshold", func(t *testing.T) {
		e := newHookPreservationEnv(t)
		e.establishFreshCanary(t)
		// The device stops answering the canary: no fresh matched replies.
		e.dev.state.Store(canaryDevDead)
		e.setHookFails(true)
		threshold := e.svc.prober.Config().FailureThreshold
		var cur *models.BackendTunnel
		for i := 0; i < threshold; i++ {
			cur, _ = e.probeOnce(t)
		}
		if cur.Status != models.TunnelStatusDisabled {
			t.Fatalf("sustained attachment failure with a dead inner path did not withdraw: %q", cur.Status)
		}
	})

	t.Run("administrative disable is never overridden", func(t *testing.T) {
		e := newHookPreservationEnv(t)
		e.establishFreshCanary(t)
		e.setHookFails(true)
		if err := e.svc.pool.SetTunnelEnabled(t.Context(), e.blocked.ServerID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("administrative disable: %v", err)
		}
		for i := 0; i < e.svc.prober.Config().FailureThreshold; i++ {
			e.probeOnce(t)
		}
		cur, _ := e.svc.pool.GetTunnel(e.blocked.ServerID)
		if cur.Enabled {
			t.Fatal("preservation re-enabled an administratively disabled backend")
		}
	})

	t.Run("stale evidence from a replaced device is refused", func(t *testing.T) {
		e := newHookPreservationEnv(t)
		e.establishFreshCanary(t)
		cur, _ := e.svc.pool.GetTunnel(e.blocked.ServerID)
		if !e.admissible(t, cur) {
			t.Fatal("precondition: evidence should be admissible")
		}
		// Replace the device object (credential replacement / re-attach) and ask
		// the oracle with the NEW device's stamp: the old verdict must not carry.
		replacement := &canaryBackendDevice{inner: e.dev.inner, created: e.dev.created.Add(time.Hour), hooks: map[uint64]tunnel.CanaryResponseHook{}}
		_ = replacement.Close()
		if e.svc.prober.CanaryAdmissible(cur, replacement.created) {
			t.Fatal("evidence from the replaced device authorised the new device")
		}
	})

	t.Run("closed device cannot claim preservation", func(t *testing.T) {
		e := newHookPreservationEnv(t)
		e.establishFreshCanary(t)
		// The only attached device is closed: no in-tunnel evidence can exist, so
		// the attachment threshold must withdraw the backend.
		_ = e.dev.Close()
		e.setHookFails(true)
		threshold := e.svc.prober.Config().FailureThreshold
		var cur *models.BackendTunnel
		for i := 0; i < threshold; i++ {
			cur, _ = e.probeOnce(t)
		}
		if cur.Status != models.TunnelStatusDisabled {
			t.Fatalf("a closed device preserved the backend: %q", cur.Status)
		}
	})

	t.Run("pending enrollment keeps its own gating", func(t *testing.T) {
		e := newHookPreservationEnv(t)
		e.establishFreshCanary(t)
		e.setHookFails(true)
		// Genuine enrollment quarantine outranks inner evidence. It also gates
		// earlier than attachment: the probe keeps the backend "connecting", so it
		// is never routable and no attachment decision can release it.
		e.svc.prober.SetPendingEnrollment(e.blocked.ServerID, true)
		threshold := e.svc.prober.Config().FailureThreshold
		var cur *models.BackendTunnel
		for i := 0; i < threshold; i++ {
			cur, _ = e.probeOnce(t)
		}
		if cur.Status == models.TunnelStatusActive {
			t.Fatalf("inner evidence promoted a pending-enrollment backend to active: %q", cur.Status)
		}
		if !e.svc.prober.IsPendingEnrollment(e.blocked.ServerID) {
			t.Fatal("fixture: quarantine was not actually set")
		}
		if active := e.svc.pool.GetActiveTunnels(); len(active) != 0 {
			t.Fatalf("pending-enrollment backend became routable: %d active tunnels", len(active))
		}
	})
}
