package tunnel

import (
	"fmt"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// CommitConnectionTransfer pins target eligibility and generation while commit
// accepts a placement. Its synchronous publish callback changes memory only and
// must be called at most once. Callers hold the service and session locks before
// entering; commit may take the database lock but must not re-enter the pool.
// Counter persistence is deliberately deferred until all nested locks are gone.
func (p *Pool) CommitConnectionTransfer(fromID, toID, expectedVersion int64, commit func(publish func()) error) (persist func(), err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	target, err := p.connectionTransferTargetLocked(toID, expectedVersion)
	if err != nil {
		return nil, err
	}
	err = commit(func() { persist = p.transferConnectionCountsLocked(fromID, target) })
	return persist, err
}

func (p *Pool) connectionTransferTargetLocked(toID, expectedVersion int64) (*models.BackendTunnel, error) {
	if p.closed {
		return nil, ErrPoolClosed
	}
	target, ok := p.tunnelsByID[toID]
	if !ok {
		return nil, ErrTunnelNotFound
	}
	if !target.Enabled || !strings.EqualFold(target.Status, "active") {
		return nil, fmt.Errorf("target backend tunnel %d is not eligible (enabled=%t status=%s)", toID, target.Enabled, target.Status)
	}
	if expectedVersion > 0 && target.StateVersion != expectedVersion {
		return nil, fmt.Errorf("target backend tunnel %d state version mismatch (expected %d, got %d)", toID, expectedVersion, target.StateVersion)
	}
	return target, nil
}

// transferConnectionCountsLocked captures the accepted gauge delta exactly once;
// the returned persistence action must run after releasing all owner locks.
func (p *Pool) transferConnectionCountsLocked(fromID int64, target *models.BackendTunnel) func() {
	var sourceCount int
	source, exists := p.tunnelsByID[fromID]
	if exists {
		if source.ActiveConnections > 0 {
			source.ActiveConnections--
		}
		sourceCount = source.ActiveConnections
	}
	target.ActiveConnections++
	targetID, targetCount := target.ID, target.ActiveConnections
	return func() {
		if exists {
			p.persistConnectionCount(fromID, int64(sourceCount))
		}
		p.persistConnectionCount(targetID, int64(targetCount))
	}
}
