package tunnel

import (
	"context"
	"errors"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// canaryResult is owned by HealthProber.mu. The sequence orders probe starts,
// so a late completion cannot erase a more recently accepted observation.
type canaryResult struct {
	tunnelID int64
	sequence uint64
}

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
func (hp *HealthProber) acceptCanaryObservation(t *models.BackendTunnel, sequence uint64, success bool) error {
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
	if hp.canaryResults == nil {
		hp.canaryResults = make(map[int64]canaryResult)
	}
	if hp.canaryFailCounts == nil {
		hp.canaryFailCounts = make(map[int64]int)
	}
	if success || previous.tunnelID != t.ID {
		hp.canaryFailCounts[t.ServerID] = 0
	}
	if !success {
		hp.canaryFailCounts[t.ServerID]++
	}
	hp.canaryResults[t.ServerID] = canaryResult{tunnelID: t.ID, sequence: sequence}
	return nil
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
