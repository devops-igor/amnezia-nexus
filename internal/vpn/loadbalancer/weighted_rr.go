package loadbalancer

import (
	"context"
	"sync"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// WeightedRoundRobinBalancer distributes traffic proportionally based on backend weights using smooth weighted round-robin.
//
// Identity domain (issue #92): ALL scheduler state — configured weights and
// the runtime smooth-WRR current weights — is keyed by the backend's
// ServerID, the same identity the configured weight map uses. A single
// identity domain means a backend's scheduler state is removed with the
// backend (UpdateBackends prunes entries for servers no longer present) and
// a recreated/new tunnel for the same server starts from that server's
// carried-over smooth state (a fresh tunnel for an unknown server starts
// fresh at its effective weight). Nothing keys on the per-tunnel ID, so no
// stale per-ID entries can accumulate or skew scheduling.
type WeightedRoundRobinBalancer struct {
	mu             sync.Mutex
	weights        map[int64]int // ServerID -> configured weight
	currentWeights map[int64]int // ServerID -> smooth-WRR current weight
	caps           CapacityConfig
	tunnels        []*models.BackendTunnel
}

// NewWeightedRoundRobinBalancer creates a new weighted round-robin load balancer.
func NewWeightedRoundRobinBalancer(weights map[int64]int, caps CapacityConfig) *WeightedRoundRobinBalancer {
	wCopy := make(map[int64]int)
	for k, v := range weights {
		if v > 0 {
			wCopy[k] = v
		}
	}
	return &WeightedRoundRobinBalancer{
		weights:        wCopy,
		currentWeights: make(map[int64]int),
		caps:           caps,
	}
}

// UpdateBackends updates the internal list of available backend tunnels and
// prunes scheduler state for backends that are no longer present (issue
// #92): a removed backend's ServerID entries in both the current-weight map
// and the configured-weight map are dropped, so a recreated tunnel cannot
// inherit stale scheduler state, and the maps cannot grow without bound as
// backends churn. State for servers still present is preserved so the
// smooth-WRR distribution stays stable across membership updates.
func (wb *WeightedRoundRobinBalancer) UpdateBackends(tunnels []*models.BackendTunnel) {
	wb.mu.Lock()
	defer wb.mu.Unlock()
	wb.tunnels = tunnels
	present := make(map[int64]struct{}, len(tunnels))
	for _, t := range tunnels {
		present[t.ServerID] = struct{}{}
	}
	for sid := range wb.currentWeights {
		if _, ok := present[sid]; !ok {
			delete(wb.currentWeights, sid)
		}
	}
	for sid := range wb.weights {
		if _, ok := present[sid]; !ok {
			delete(wb.weights, sid)
		}
	}
}

// GetAlgorithm returns the algorithm identifier.
func (wb *WeightedRoundRobinBalancer) GetAlgorithm() models.LoadBalancingAlgorithm {
	return models.LBWeighted
}

// SetWeights updates the server weight mappings.
func (wb *WeightedRoundRobinBalancer) SetWeights(weights map[int64]int) {
	wb.mu.Lock()
	defer wb.mu.Unlock()
	wb.weights = make(map[int64]int)
	for k, v := range weights {
		if v > 0 {
			wb.weights[k] = v
		}
	}
	wb.currentWeights = make(map[int64]int)
}

// SelectBackend selects the next backend according to the smooth weighted round-robin algorithm.
func (wb *WeightedRoundRobinBalancer) SelectBackend(ctx context.Context, req *RoutingRequest) (*models.BackendTunnel, error) {
	wb.mu.Lock()
	defer wb.mu.Unlock()

	candidates := req.AvailableTunnels
	if len(candidates) == 0 {
		candidates = wb.tunnels
	}

	healthy := FilterHealthy(candidates, wb.caps.MaxPeersPerBackend)
	if len(healthy) == 0 {
		return nil, ErrNoActiveBackends
	}

	if wb.caps.MaxTotalPeers > 0 {
		var totalConnections int
		for _, t := range candidates {
			totalConnections += t.ActiveConnections
		}
		if totalConnections >= wb.caps.MaxTotalPeers {
			return nil, ErrCapacityExceeded
		}
	}

	// Smooth Weighted Round-Robin (Nginx algorithm)
	totalWeight := 0
	var best *models.BackendTunnel
	maxCurrentWeight := -1 << 31

	for _, t := range healthy {
		effectiveWeight, ok := wb.weights[t.ServerID]
		if !ok || effectiveWeight <= 0 {
			effectiveWeight = 100 // Default weight
		}
		totalWeight += effectiveWeight

		// Scheduler state is keyed by ServerID (issue #92): a tunnel that
		// is new to this balancer starts from its server's carried-over
		// smooth state, or at 0 for an unknown server (fresh start).
		wb.currentWeights[t.ServerID] += effectiveWeight
		if wb.currentWeights[t.ServerID] > maxCurrentWeight {
			maxCurrentWeight = wb.currentWeights[t.ServerID]
			best = t
		}
	}

	if best != nil {
		wb.currentWeights[best.ServerID] -= totalWeight
	}

	return best, nil
}
