package loadbalancer

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

var (
	ErrNoActiveBackends = errors.New("no active backend tunnels available")
	ErrCapacityExceeded = errors.New("load balancer capacity limit exceeded")
	ErrInvalidAlgorithm = errors.New("invalid load balancing algorithm")
)

// CapacityConfig defines capacity limits for routing.
type CapacityConfig struct {
	MaxTotalPeers      int
	MaxPeersPerBackend int
}

// RoutingRequest contains contextual information for routing decisions.
type RoutingRequest struct {
	UserID           string
	PeerPublicKey    string
	ClientIP         net.IP
	AvailableTunnels []*models.BackendTunnel
}

// LoadBalancer selects an optimal backend tunnel for an incoming peer connection.
type LoadBalancer interface {
	SelectBackend(ctx context.Context, req *RoutingRequest) (*models.BackendTunnel, error)
	UpdateBackends(tunnels []*models.BackendTunnel)
	GetAlgorithm() models.LoadBalancingAlgorithm
}

// FilterHealthy filters tunnels to only healthy ("active") tunnels within capacity limits.
//
// Serialization contract (issue #86): the ActiveConnections values read
// here are a best-effort snapshot — pool GetActiveTunnels returns copies,
// so a concurrent increment after selection is invisible to this function.
// The snapshot is safe for the capacity invariant ONLY because every
// counter mutator (HandleIncomingPeer select+increment, disconnect
// decrements, failover moves, rekey ReplacementHook) serializes under the
// VPN Service's s.mu (or the hook's nested sm.mu regime — see
// tunnel.Pool.IncrementConnections for the full contract). FilterHealthy
// itself takes no lock and must stay lock-free: the caller (today only
// HandleIncomingPeer) already holds the serializing lock when the snapshot
// is taken. A future caller invoking FilterHealthy outside s.mu reintroduces
// the check-then-allocate race (two selects both observe cap-1 → cap+1).
func FilterHealthy(tunnels []*models.BackendTunnel, maxPeersPerBackend int) []*models.BackendTunnel {
	var healthy []*models.BackendTunnel
	for _, t := range tunnels {
		if t == nil {
			continue
		}
		if !strings.EqualFold(t.Status, "active") {
			continue
		}
		if maxPeersPerBackend > 0 && t.ActiveConnections >= maxPeersPerBackend {
			continue
		}
		healthy = append(healthy, t)
	}
	return healthy
}

// NewLoadBalancer creates a LoadBalancer instance based on the algorithm enum.
func NewLoadBalancer(algo models.LoadBalancingAlgorithm, weights map[int64]int, caps CapacityConfig) (LoadBalancer, error) {
	switch algo {
	case models.LBLeastConnections, "":
		return NewLeastConnectionsBalancer(caps), nil
	case models.LBWeighted:
		return NewWeightedRoundRobinBalancer(weights, caps), nil
	case models.LBRoundRobin:
		return NewRoundRobinBalancer(caps), nil
	default:
		return nil, ErrInvalidAlgorithm
	}
}
