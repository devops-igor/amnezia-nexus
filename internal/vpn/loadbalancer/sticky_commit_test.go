package loadbalancer

import (
	"context"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type refusingDestinationStore struct {
	StickyStore
	attempts []int64
}

func (s *refusingDestinationStore) CommitVPNSessionDestination(ctx context.Context, targetID int64, row *models.VPNSession, publish func()) error {
	s.attempts = append(s.attempts, targetID)
	return database.ErrDestinationProviderAbsent
}

func TestFailoverDestinationRefusalDoesNotRetryTheSameTarget(t *testing.T) {
	caps := CapacityConfig{MaxTotalPeers: 100, MaxPeersPerBackend: 100}
	store := &refusingDestinationStore{}
	sm := NewStickySessionManager(store, NewLeastConnectionsBalancer(caps), caps)
	sm.AssignPeerAffinity("peer", 1)
	result := &FailoverResult{}
	err := sm.commitFailoverMove(t.Context(), 1, peerMove{peerKey: "peer", newID: 2}, nil,
		[]*models.BackendTunnel{{ID: 2, Enabled: true, Status: "active"}, {ID: 3, Enabled: true, Status: "active"}}, result, nil)
	if !errors.Is(err, database.ErrDestinationProviderAbsent) || len(store.attempts) != 2 || store.attempts[0] != 2 || store.attempts[1] != 3 {
		t.Fatalf("attempts=%v error=%v", store.attempts, err)
	}
	if len(result.Migrations) != 0 {
		t.Fatal("a refused destination was published")
	}
	if got, ok := sm.GetPeerAffinity("peer"); !ok || got != 1 {
		t.Fatalf("refusal changed affinity: %d/%t", got, ok)
	}
}

func TestFailoverAlternativeSelectionErrorIsReported(t *testing.T) {
	caps := CapacityConfig{MaxTotalPeers: 100, MaxPeersPerBackend: 100}
	store := &refusingDestinationStore{}
	balancer := &failingBalancer{inner: NewLeastConnectionsBalancer(caps), failPeers: map[string]bool{"peer": true}}
	sm := NewStickySessionManager(store, balancer, caps)
	result := &FailoverResult{}
	err := sm.commitFailoverMove(t.Context(), 1, peerMove{peerKey: "peer", newID: 2}, nil,
		[]*models.BackendTunnel{{ID: 2}, {ID: 3}}, result, nil)
	if err == nil || len(store.attempts) != 1 || len(result.Migrations) != 0 {
		t.Fatalf("attempts=%v migrations=%v error=%v", store.attempts, result.Migrations, err)
	}
}
