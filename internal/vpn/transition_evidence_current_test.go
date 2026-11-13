package vpn

// Localized rework (issue #794, diagnostics round 10): the transition evidence must
// stay truthful when the backend CHANGES WITHOUT another recorded probe.
//
// Two contradictions were found in the round-9 projection:
//
//  1. The projection matched only the recorded tunnel ID and then took the state
//     version and administrative intent from the row it was handed, so an older
//     record could be presented as describing current state.
//  2. Freshness compared two RECORDED facts (the success device stamp and the
//     record's own device field). Neither is the device attached now, so a detach
//     or replacement that happened between probes never invalidated the evidence.
//
// Both are exercised here through the real consumer chain (real Service, real
// prober, real pool CAS, real attached netstack device, real diagnostics
// projection), not by calling the classifier directly. Each case asserts the
// PROJECTION a reader would see.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// projectEvidence returns the transition evidence for the live pool row, through
// the same accessor the diagnostics payload uses.
func (e *hookPreservationEnv) projectEvidence(t *testing.T) tunnel.TransitionEvidence {
	t.Helper()
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	ev, ok := e.svc.prober.TransitionEvidenceFor(cur)
	if !ok {
		t.Fatal("no transition evidence recorded for the current generation")
	}
	return ev
}

// TestEvidenceCurrent_HealthCannotSurviveDetachedDevice is contradiction 2 from the
// detach direction: fresh healthy evidence is recorded, then the actual backend
// device goes away WITHOUT another probe. The projection must stop calling that
// evidence fresh and must report that no device is attached now.
func TestEvidenceCurrent_HealthCannotSurviveDetachedDevice(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	before := e.projectEvidence(t)
	if before.SuccessFreshness != tunnel.FreshnessFresh {
		t.Fatalf("precondition: freshness = %q, want %q", before.SuccessFreshness, tunnel.FreshnessFresh)
	}
	if before.CurrentDeviceCreatedAt == nil {
		t.Fatal("precondition: no current device recorded while a device was attached")
	}

	// Detach the ACTUAL device without running a probe: drop it from the service's
	// device map, which is what the prober's provider reads.
	e.svc.mu.Lock()
	delete(e.svc.backendDevices, e.blocked.ID)
	e.svc.mu.Unlock()

	after := e.projectEvidence(t)

	if after.SuccessFreshness == tunnel.FreshnessFresh {
		t.Fatal("a detached device's recorded success was still reported as fresh: the detach happened without a probe, so nothing else would ever correct it")
	}
	if after.SuccessFreshness != tunnel.FreshnessNoDevice {
		t.Errorf("freshness = %q, want %q so the absence is explicit rather than merely 'stale'", after.SuccessFreshness, tunnel.FreshnessNoDevice)
	}
	if after.CurrentDeviceCreatedAt != nil {
		t.Errorf("current device stamp = %v, want nil while nothing is attached", after.CurrentDeviceCreatedAt)
	}
	// The recorded attempt history must survive: an operator still needs to see the
	// last observation and which device produced it.
	if after.LastSuccessAt == nil {
		t.Error("detaching the device erased the recorded success timestamp; history must survive the fence")
	}
	if after.DeviceCreatedAt == nil {
		t.Error("detaching the device erased the recorded device stamp; the evidence must stay attributable")
	}
	if before.DeviceCreatedAt == nil || after.DeviceCreatedAt == nil || !before.DeviceCreatedAt.Equal(*after.DeviceCreatedAt) {
		t.Errorf("recorded device stamp changed on a read: %v -> %v", before.DeviceCreatedAt, after.DeviceCreatedAt)
	}
}

// TestEvidenceCurrent_HealthCannotSurviveReplacedDevice is contradiction 2 from the
// replacement direction: a DIFFERENT device is attached without another probe. The
// recorded success belongs to the old device and must not speak for the new one.
func TestEvidenceCurrent_HealthCannotSurviveReplacedDevice(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	before := e.projectEvidence(t)
	if before.DeviceCreatedAt == nil {
		t.Fatal("precondition: recorded device stamp missing")
	}
	oldStamp := *before.DeviceCreatedAt

	// Replace the attached device with a distinct one (different creation stamp)
	// WITHOUT probing. This is the shape of a detach/re-attach or device swap.
	replacement := &canaryBackendDevice{
		inner:   e.dev.inner,
		created: oldStamp.Add(90 * time.Second),
	}
	replacement.state.Store(canaryDevAlive)
	e.svc.mu.Lock()
	e.svc.backendDevices[e.blocked.ID] = replacement
	e.svc.mu.Unlock()

	after := e.projectEvidence(t)

	if after.SuccessFreshness == tunnel.FreshnessFresh {
		t.Fatal("a replaced device inherited the previous device's fresh success")
	}
	if after.SuccessFreshness != tunnel.FreshnessPreviousDevice {
		t.Errorf("freshness = %q, want %q", after.SuccessFreshness, tunnel.FreshnessPreviousDevice)
	}
	if after.CurrentDeviceCreatedAt == nil {
		t.Fatal("the replacement device is attached but no current stamp is reported")
	}
	if after.CurrentDeviceCreatedAt.Equal(oldStamp) {
		t.Error("current device stamp still reports the replaced device")
	}
	// The evidence still names the device that actually produced it.
	if after.DeviceCreatedAt == nil || !after.DeviceCreatedAt.Equal(oldStamp) {
		t.Errorf("recorded device stamp = %v, want the producing device %v", after.DeviceCreatedAt, oldStamp)
	}
}

// TestEvidenceCurrent_AdministrativeIntentIsNotRestatedAsCurrent covers
// contradiction 1 for administrative intent: an ordinary recorded gate must not be
// presented as current after the backend is administratively disabled without
// another probe.
func TestEvidenceCurrent_AdministrativeIntentIsNotRestatedAsCurrent(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	before := e.projectEvidence(t)
	if !before.Current {
		t.Fatal("precondition: a just-recorded observation was not reported as current")
	}
	if !before.Enabled || !before.RecordedEnabled {
		t.Fatalf("precondition: enabled=%v recorded=%v, want both true", before.Enabled, before.RecordedEnabled)
	}

	// Administrative change WITHOUT a probe.
	if err := e.svc.pool.SetTunnelEnabled(t.Context(), e.blocked.ServerID, false, models.DisableReasonAdmin); err != nil {
		t.Fatalf("administrative disable: %v", err)
	}

	after := e.projectEvidence(t)

	if after.Current {
		t.Error("a record that predates the administrative change was still reported as current")
	}
	if after.Enabled {
		t.Error("evidence reports enabled=true after an administrative disable")
	}
	if after.RecordedEnabled != true {
		t.Errorf("recorded administrative intent = %v, want the true it was observed with", after.RecordedEnabled)
	}
	if after.Gate != tunnel.GateAdministrative {
		t.Errorf("gate = %q, want %q: automated health decisions do not apply to an administratively disabled backend", after.Gate, tunnel.GateAdministrative)
	}
	// The observation itself is preserved and still attributable.
	if after.LastAttemptOuter != tunnel.OutcomeSuccess {
		t.Errorf("recorded outer observation = %q, want the recorded %q", after.LastAttemptOuter, tunnel.OutcomeSuccess)
	}
}

// TestEvidenceCurrent_StateVersionMovedIsReported covers contradiction 1 for the
// state version: the projection must report the observed version it was recorded
// against, distinct from the version of the row it is asked about.
func TestEvidenceCurrent_StateVersionMovedIsReported(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	recorded := e.projectEvidence(t)
	if recorded.RecordedStateVersion != cur.StateVersion {
		t.Fatalf("recorded version = %d, want the read version %d", recorded.RecordedStateVersion, cur.StateVersion)
	}

	// The row moves on (any legitimate status write) without another gate record.
	moved := *cur
	moved.StateVersion = cur.StateVersion + 7
	ev, ok := e.svc.prober.TransitionEvidenceFor(&moved)
	if !ok {
		t.Fatal("no evidence for the same tunnel generation")
	}
	if ev.StateVersion != moved.StateVersion {
		t.Errorf("reported state version = %d, want the queried %d", ev.StateVersion, moved.StateVersion)
	}
	if ev.RecordedStateVersion == ev.StateVersion {
		t.Errorf("recorded and current versions both %d: a moved version must be visibly distinct", ev.RecordedStateVersion)
	}
	if ev.Current {
		t.Error("a record observed against an older version was reported as current")
	}
	// A legitimate version bump must not delete the evidence.
	if ev.LastAttemptOuter != tunnel.OutcomeSuccess {
		t.Errorf("the recorded attempt was discarded by a version bump: outer=%q", ev.LastAttemptOuter)
	}
}

// TestEvidenceCurrent_EndedQuarantineStopsExplainingConnecting covers
// contradiction 1 for enrollment: once the quarantine legitimately ends, the
// projection must stop attributing the state to enrollment.
func TestEvidenceCurrent_EndedQuarantineStopsExplainingConnecting(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.setOuterOK()
	e.setHookFails(false)

	// Enter enrollment quarantine through the production deploy mechanism.
	ctx := context.WithValue(t.Context(), tunnel.DeployEnrollmentKey, true)
	live, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if _, err := e.svc.prober.ProbeTunnel(ctx, live); err != nil {
		t.Fatalf("probe under enrollment quarantine: %v", err)
	}

	during := e.projectEvidence(t)
	if during.Gate != tunnel.GateEnrollmentQuarantine {
		t.Fatalf("precondition: gate = %q, want %q", during.Gate, tunnel.GateEnrollmentQuarantine)
	}

	// The quarantine ends (qualification) without another probe.
	if err := e.svc.PromoteQualifiedTunnel(t.Context(), e.blocked, 5); err != nil {
		t.Fatalf("qualify: %v", err)
	}
	if e.svc.prober.IsPendingEnrollment(e.blocked.ServerID) {
		t.Fatal("precondition: the prober still reports pending enrollment after qualification")
	}

	after := e.projectEvidence(t)
	if after.Gate == tunnel.GateEnrollmentQuarantine {
		t.Error("an ended enrollment quarantine is still offered as the explanation for the backend's state")
	}
}

// TestEvidenceCurrent_ProjectionTakesNoNestedProberLock is the deadlock guard: the
// projection must not hold hp.mu while consulting the device provider, which
// reaches Service.mu. A provider that asserts the prober lock is free is the
// cheapest honest proof.
func TestEvidenceCurrent_ProjectionTakesNoNestedProberLock(t *testing.T) {
	e := newHookPreservationEnv(t)
	e.establishFreshCanary(t)

	attempted := false
	e.svc.prober.SetDeviceProvider(func(int64) tunnel.PacketDevice {
		attempted = true
		// Taking the prober lock here would deadlock if the projection held it.
		// Performing a lock-taking operation proves the ordering is not nested.
		done := make(chan struct{})
		go func() {
			e.svc.prober.GetFailCount(e.blocked.ServerID)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("device provider could not take the prober lock: the projection holds hp.mu across the provider call")
		}
		return nil
	})
	if _, ok := e.svc.prober.TransitionEvidenceFor(&models.BackendTunnel{ID: e.blocked.ID, ServerID: e.blocked.ServerID, Enabled: true}); !ok {
		t.Fatal("no evidence projected")
	}
	if !attempted {
		t.Error("the projection did not consult the device provider, so the current-device fence is not wired")
	}
}
