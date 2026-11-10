package tunnel

import (
	"context"
	"errors"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// canaryResult is owned by HealthProber.mu. The sequence orders probe starts,
// so a late completion cannot erase a more recently accepted observation.
type canaryResult struct {
	tunnelID int64
	sequence uint64
}

// canarySuccess is the recorded inner data-plane success that authorizes a NEW
// admission onto an otherwise handshake-blocked backend (issue #731). Owned by
// HealthProber.mu.
//
// It exists because the status label is not evidence: handshake_blocked is
// written both when the inner canary SUCCEEDED under a failed outer handshake
// and when it FAILED below the confirmation threshold while sessions exist. A
// separate record also distinguishes "fresh success" from "never probed",
// "stale success" and "failed since".
//
// deviceCreated binds the evidence to the exact backend device that answered
// it, so a credential replacement, a detach/re-attach on the same tunnel ID, or
// any other device swap cannot inherit an earlier device's verdict. tunnelID
// binds it to the tunnel generation, because a server can be replaced by a new
// tunnel row with a new ID.
type canarySuccess struct {
	tunnelID      int64
	deviceCreated time.Time
	at            time.Time
}

// DeviceGeneration is implemented by backend devices that can report their
// creation stamp. It is an optional capability in the same composition style as
// CanaryDevice, CanaryResponseDemuxer and ProxyStreamDevice: every production
// backend device already exposes CreatedAt, so no device has to change.
//
// A device that cannot report a stamp cannot bind canary evidence to itself, so
// admission treats its evidence as unusable and fails closed.
type DeviceGeneration interface {
	CreatedAt() time.Time
}

// canaryCadenceJitterCeiling is the maximum factor jitterDuration applies to the
// configured probe interval (internal/vpn/tunnel/health_loop.go). Kept as a
// named constant so the freshness bound below is visibly derived from the
// existing cadence instead of introducing a product timer.
const canaryCadenceJitterCeiling = 1.2

func (hp *HealthProber) beginCanaryObservation() uint64 {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.canarySequence++
	return hp.canarySequence
}

// acceptCanaryObservation commits only in-memory history. Lock order is hp.mu
// then pool.mu, held together across validation and mutation, never across I/O
// or notification. Health-disabled tunnels may collect self-healing proof;
// administratively disabled, replaced and superseded snapshots may not.
func (hp *HealthProber) acceptCanaryObservation(t *models.BackendTunnel, sequence uint64, success bool, deviceCreated time.Time) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if hp.pool != nil {
		hp.pool.mu.RLock()
		defer hp.pool.mu.RUnlock()
		if err := hp.checkCanaryGenerationLocked(t); err != nil {
			return err
		}
	}
	previous := hp.canaryResults[t.ServerID]
	if sequence <= previous.sequence {
		return ErrStaleStateVersion
	}
	hp.ensureCanaryMapsLocked()
	if success || previous.tunnelID != t.ID {
		hp.canaryFailCounts[t.ServerID] = 0
	}
	if success {
		hp.canarySuccesses[t.ServerID] = canarySuccess{
			tunnelID:      t.ID,
			deviceCreated: deviceCreated,
			at:            hp.now(),
		}
	} else {
		// Any accepted failure — including a single transient one below the
		// confirmation threshold — withdraws the admission authority without
		// touching the status label or established routes.
		delete(hp.canarySuccesses, t.ServerID)
		hp.canaryFailCounts[t.ServerID]++
	}
	hp.canaryResults[t.ServerID] = canaryResult{tunnelID: t.ID, sequence: sequence}
	return nil
}

// ensureCanaryMapsLocked allocates the canary history maps on first write.
// Callers hold hp.mu.
func (hp *HealthProber) ensureCanaryMapsLocked() {
	if hp.canaryResults == nil {
		hp.canaryResults = make(map[int64]canaryResult)
	}
	if hp.canaryFailCounts == nil {
		hp.canaryFailCounts = make(map[int64]int)
	}
	if hp.canarySuccesses == nil {
		hp.canarySuccesses = make(map[int64]canarySuccess)
	}
}

// CanaryAdmissible reports whether recorded inner data-plane evidence authorizes
// a NEW admission onto t. It is a pure in-memory read: no I/O, no callbacks, no
// pool lock, so it is safe on the admission path while Service.mu is held
// (established order: Service.mu then prober mu; see Service.SetCanaryProbeFunc).
//
// The decision needs all of: the current generation to be enabled, a recorded
// success for THIS tunnel ID, no failure since that success, the evidence to
// come from the exact backend device still attached (deviceCreated), and the
// evidence to be no older than the bound derived from the configured probe
// cadence. A negative age (clock stepped backwards) is refused rather than
// treated as fresh.
//
// It deliberately says nothing about status: admission keeps the
// handshake_blocked label and only decides candidate eligibility.
func (hp *HealthProber) CanaryAdmissible(t *models.BackendTunnel, deviceCreated time.Time) bool {
	if hp == nil || t == nil || !t.Enabled || deviceCreated.IsZero() {
		return false
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	rec, ok := hp.canarySuccesses[t.ServerID]
	if !ok || !rec.matches(t.ID, deviceCreated) {
		return false
	}
	if hp.canaryFailCounts[t.ServerID] != 0 {
		return false
	}
	return hp.evidenceFreshLocked(rec)
}

// matches reports whether this record belongs to the given tunnel generation and
// the given backend device.
func (r canarySuccess) matches(tunnelID int64, deviceCreated time.Time) bool {
	return r.tunnelID == tunnelID && r.deviceCreated.Equal(deviceCreated)
}

// evidenceFreshLocked reports whether the record is within the derived freshness
// bound. A negative age means the clock moved backwards, which is not freshness.
// Callers hold hp.mu.
func (hp *HealthProber) evidenceFreshLocked(rec canarySuccess) bool {
	age := hp.now().Sub(rec.at)
	return age >= 0 && age <= hp.maxCanaryEvidenceAgeLocked()
}

// maxCanaryEvidenceAgeLocked derives the freshness bound from the existing
// health cadence: one jittered probe interval (a blocked backend is probed on
// every sweep) plus one probe timeout. Healthy values therefore survive exactly
// one missed sweep period; nothing here is an independent product timer.
func (hp *HealthProber) maxCanaryEvidenceAgeLocked() time.Duration {
	interval := hp.cfg.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	timeout := hp.cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return time.Duration(float64(interval)*canaryCadenceJitterCeiling) + timeout
}

// now returns the prober's time source. Callers hold hp.mu.
func (hp *HealthProber) now() time.Time {
	if hp.nowFn != nil {
		return hp.nowFn()
	}
	return time.Now()
}

// SetNowFuncForTest injects the prober's time source so freshness is decided
// deterministically. Nil restores the wall clock. Test-only; production never
// calls it.
func (hp *HealthProber) SetNowFuncForTest(fn func() time.Time) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.nowFn = fn
}

// checkCanaryGenerationLocked requires both hp.mu and pool.mu. Reused after
// lock-free callbacks as well as at the atomic history write boundary.
func (hp *HealthProber) checkCanaryGenerationLocked(t *models.BackendTunnel) error {
	current := hp.pool.tunnelsByServerID[t.ServerID]
	if current == nil || current.ID != t.ID {
		return ErrTunnelNotFound
	}
	if !current.Enabled {
		return ErrTunnelDisabled
	}
	if current.StateVersion != t.StateVersion {
		return ErrStaleStateVersion
	}
	return nil
}

func (hp *HealthProber) canaryObservationCurrent(t *models.BackendTunnel, sequence uint64) error {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	if hp.pool != nil {
		hp.pool.mu.RLock()
		defer hp.pool.mu.RUnlock()
		if err := hp.checkCanaryGenerationLocked(t); err != nil {
			return err
		}
	}
	if hp.canaryResults[t.ServerID] != (canaryResult{tunnelID: t.ID, sequence: sequence}) {
		return ErrStaleStateVersion
	}
	return nil
}

func isObsoleteCanary(err error) bool {
	return errors.Is(err, ErrTunnelNotFound) || errors.Is(err, ErrStaleStateVersion) ||
		errors.Is(err, ErrTunnelDisabled) || errors.Is(err, context.Canceled)
}

// CanaryFailureCount returns shared history only for the current tunnel identity.
func (hp *HealthProber) CanaryFailureCount(tunnelID int64) int {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	if hp.pool == nil {
		return 0
	}
	hp.pool.mu.RLock()
	defer hp.pool.mu.RUnlock()
	t := hp.pool.tunnelsByID[tunnelID]
	if t == nil || hp.canaryResults[t.ServerID].tunnelID != t.ID {
		return 0
	}
	return hp.canaryFailCounts[t.ServerID]
}

// confirmOuterFailure uses inner history whenever proof is available, even if
// the outer streak has already crossed its threshold. Successful inner probes
// do not reset outer history and outer history cannot stand in for inner loss.
func (hp *HealthProber) confirmOuterFailure(ctx context.Context, t *models.BackendTunnel, outerFailures int) error {
	if hp.hasCanaryProber(t) {
		err := hp.probeCanary(ctx, t)
		if isObsoleteCanary(err) {
			return err
		}
		if err == nil {
			return hp.transitionToHandshakeBlocked(ctx, t)
		}
		if hp.GetCanaryFailCount(t.ServerID) >= hp.cfg.FailureThreshold {
			return hp.transitionToThresholdDisabled(ctx, t)
		}
	} else if outerFailures >= hp.cfg.FailureThreshold {
		return hp.transitionToThresholdDisabled(ctx, t)
	}
	if t.ActiveConnections > 0 {
		return hp.transitionToHandshakeBlocked(ctx, t)
	}
	return hp.transitionToDegraded(ctx, t)
}
