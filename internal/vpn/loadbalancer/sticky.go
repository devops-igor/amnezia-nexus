package loadbalancer

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// StickySessionManager manages session affinity and handles automatic failover.
type StickySessionManager struct {
	mu           sync.RWMutex
	db           *database.DB
	baseBalancer LoadBalancer
	caps         CapacityConfig
	userAffinity map[string]int64 // userID -> backendTunnelID
	peerAffinity map[string]int64 // peerPublicKey -> backendTunnelID
}

// NewStickySessionManager creates a new StickySessionManager wrapping a base load balancer.
func NewStickySessionManager(db *database.DB, baseBalancer LoadBalancer, caps CapacityConfig) *StickySessionManager {
	return &StickySessionManager{
		db:           db,
		baseBalancer: baseBalancer,
		caps:         caps,
		userAffinity: make(map[string]int64),
		peerAffinity: make(map[string]int64),
	}
}

// GetOrAssignBackend retrieves the sticky backend for a request or assigns an optimal healthy backend.
func (sm *StickySessionManager) GetOrAssignBackend(ctx context.Context, req *RoutingRequest) (*models.BackendTunnel, bool, error) {
	if req == nil {
		return nil, false, fmt.Errorf("routing request is nil")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check existing affinity by peerPublicKey first, then by userID
	var targetTunnelID int64
	var hasAffinity bool

	if req.PeerPublicKey != "" {
		if tid, ok := sm.peerAffinity[req.PeerPublicKey]; ok {
			targetTunnelID = tid
			hasAffinity = true
		}
	}
	if !hasAffinity && req.UserID != "" {
		if tid, ok := sm.userAffinity[req.UserID]; ok {
			targetTunnelID = tid
			hasAffinity = true
		}
	}

	// Verify if the sticky backend is still active and within capacity
	if hasAffinity {
		for _, t := range req.AvailableTunnels {
			if t.ID == targetTunnelID && t.Status == "active" {
				if sm.caps.MaxPeersPerBackend <= 0 || t.ActiveConnections < sm.caps.MaxPeersPerBackend {
					// Sticky affinity preserved
					return t, false, nil
				}
			}
		}
	}

	// Affinity missed or assigned backend degraded -> select new backend
	selected, err := sm.baseBalancer.SelectBackend(ctx, req)
	if err != nil {
		return nil, false, err
	}

	if req.UserID != "" {
		sm.userAffinity[req.UserID] = selected.ID
	}
	if req.PeerPublicKey != "" {
		sm.peerAffinity[req.PeerPublicKey] = selected.ID
	}

	return selected, true, nil
}

// AssignAffinity records an explicit affinity for a user.
func (sm *StickySessionManager) AssignAffinity(userID string, tunnelID int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.userAffinity[userID] = tunnelID
}

// AssignPeerAffinity records an explicit affinity for a peer public key.
func (sm *StickySessionManager) AssignPeerAffinity(peerKey string, tunnelID int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.peerAffinity[peerKey] = tunnelID
}

// ClearAffinity removes sticky affinity for a user.
func (sm *StickySessionManager) ClearAffinity(userID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.userAffinity, userID)
}

// ClearPeerAffinity removes sticky affinity for a peer public key.
func (sm *StickySessionManager) ClearPeerAffinity(peerKey string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.peerAffinity, peerKey)
}

// GetAffinity returns the assigned backend tunnel ID for a user.
func (sm *StickySessionManager) GetAffinity(userID string) (int64, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	tid, ok := sm.userAffinity[userID]
	return tid, ok
}

// FailoverMigration describes one session migrated off a degraded tunnel.
type FailoverMigration struct {
	PeerPublicKey      string
	UserID             string
	NewBackendTunnelID int64
}

// HandleFailover migrates all sessions assigned to degradedTunnelID to healthy available backends.
// It returns the per-session migrations so the caller can redirect live
// forwarder routes (forwarder.UpdateSessionBackend) — reassigning affinity
// alone leaves established sessions routed to the detached backend.
func (sm *StickySessionManager) HandleFailover(ctx context.Context, degradedTunnelID int64, availableTunnels []*models.BackendTunnel) ([]FailoverMigration, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	healthy := FilterHealthy(availableTunnels, sm.caps.MaxPeersPerBackend)
	if len(healthy) == 0 {
		return nil, ErrNoActiveBackends
	}

	var migrations []FailoverMigration

	// 1. Migrate in-memory user affinities
	for uID, tid := range sm.userAffinity {
		if tid == degradedTunnelID {
			req := &RoutingRequest{
				UserID:           uID,
				AvailableTunnels: healthy,
			}
			newBackend, err := sm.baseBalancer.SelectBackend(ctx, req)
			if err == nil {
				sm.userAffinity[uID] = newBackend.ID
			}
		}
	}

	// 2. Migrate in-memory peer affinities; record the live-traffic moves.
	// Iterating the map directly would emit migration records in Go's
	// randomized map order, making HandleFailover's output (redirected
	// forwarder routes, connection-count moves) nondeterministic run to
	// run. Sort keys first so records are emitted in a stable order.
	degradedPeers := make([]string, 0, len(sm.peerAffinity))
	for pKey, tid := range sm.peerAffinity {
		if tid == degradedTunnelID {
			degradedPeers = append(degradedPeers, pKey)
		}
	}
	sort.Strings(degradedPeers)
	for _, pKey := range degradedPeers {
		req := &RoutingRequest{
			PeerPublicKey:    pKey,
			AvailableTunnels: healthy,
		}
		newBackend, err := sm.baseBalancer.SelectBackend(ctx, req)
		if err == nil {
			sm.peerAffinity[pKey] = newBackend.ID
			migrations = append(migrations, FailoverMigration{
				PeerPublicKey:      pKey,
				NewBackendTunnelID: newBackend.ID,
			})
		}
	}

	// 3. Migrate active sessions in DB if db handle is provided; every moved
	// session must also appear in migrations so the forwarder route follows.
	if sm.db != nil {
		activeSessions, err := sm.db.GetActiveVPNSessions(ctx)
		if err == nil {
			migratedPeers := make(map[string]bool, len(migrations))
			for _, m := range migrations {
				migratedPeers[m.PeerPublicKey] = true
			}
			for _, sess := range activeSessions {
				if sess.BackendTunnelID == degradedTunnelID {
					// Peer affinity already picked a target for this peer.
					if migratedPeers[sess.PeerPublicKey] {
						for i := range migrations {
							if migrations[i].PeerPublicKey == sess.PeerPublicKey {
								sess.BackendTunnelID = migrations[i].NewBackendTunnelID
								break
							}
						}
					} else {
						req := &RoutingRequest{
							UserID:           sess.UserID,
							PeerPublicKey:    sess.PeerPublicKey,
							AvailableTunnels: healthy,
						}
						newBackend, err := sm.baseBalancer.SelectBackend(ctx, req)
						if err != nil {
							continue
						}
						sess.BackendTunnelID = newBackend.ID
						migrations = append(migrations, FailoverMigration{
							PeerPublicKey:      sess.PeerPublicKey,
							UserID:             sess.UserID,
							NewBackendTunnelID: newBackend.ID,
						})
					}
					_ = sm.db.CreateVPNSession(ctx, &sess)
				}
			}
		}
	}

	// Stable contract: records are returned sorted by peer public key.
	// The DB path iterates sessions ordered by connected_at DESC, whose
	// tiebreak is unspecified, so appends there can interleave differently
	// between runs even with the peer-affinity phase sorted.
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].PeerPublicKey < migrations[j].PeerPublicKey
	})

	return migrations, nil
}
