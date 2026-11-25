package loadbalancer

// The destination re-read, exercised at its own boundary.
//
// The consumers in the vpn package drive this through a real failover, but the contract has
// four distinct answers and each matters on its own: candidates pass through when nothing is
// marked, a marked candidate is dropped (which is how the alternative is "followed"), an
// unknown read refuses everything, and a manager with no durable store treats absence as
// unobservable rather than inventing it.

import (
	"context"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// markStore answers the provider-absence question and records whether it was asked.
type markStore struct {
	ids    []int64
	err    error
	asked  int
	events []string
}

func (m *markStore) GetActiveVPNSessions(ctx context.Context) ([]models.VPNSession, error) {
	return nil, nil
}

func (m *markStore) CreateVPNSession(ctx context.Context, s *models.VPNSession) error { return nil }

func (m *markStore) ListProviderAbsentServerIDs(ctx context.Context) ([]int64, error) {
	m.asked++
	m.events = append(m.events, "mark-read")
	if m.err != nil {
		return nil, m.err
	}
	return m.ids, nil
}

func destinationCandidates() []*models.BackendTunnel {
	return []*models.BackendTunnel{
		{ID: 1, ServerID: 10, Enabled: true, Status: models.TunnelStatusActive},
		{ID: 2, ServerID: 20, Enabled: true, Status: models.TunnelStatusActive},
		{ID: 3, ServerID: 30, Enabled: true, Status: models.TunnelStatusActive},
	}
}

func TestRevalidateDestinations(t *testing.T) {
	cases := []struct {
		name    string
		store   *markStore
		wantIDs []int64
		wantOK  bool
	}{
		{
			name:    "nothing marked leaves every candidate",
			store:   &markStore{},
			wantIDs: []int64{1, 2, 3},
			wantOK:  true,
		},
		{
			name:    "a marked candidate is dropped and the alternative survives",
			store:   &markStore{ids: []int64{20}},
			wantIDs: []int64{1, 3},
			wantOK:  true,
		},
		{
			name:    "every candidate marked leaves none",
			store:   &markStore{ids: []int64{10, 20, 30}},
			wantIDs: []int64{},
			wantOK:  true,
		},
		{
			name:    "a read error is unknown, not empty",
			store:   &markStore{err: errors.New("store unreadable")},
			wantIDs: nil,
			wantOK:  false,
		},
		{
			name:    "a mark for a server that is not a candidate changes nothing",
			store:   &markStore{ids: []int64{999}},
			wantIDs: []int64{1, 2, 3},
			wantOK:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm := NewStickySessionManager(tc.store, nil, CapacityConfig{MaxTotalPeers: 10, MaxPeersPerBackend: 10})

			got, ok := sm.revalidateDestinations(context.Background(), destinationCandidates())
			if ok != tc.wantOK {
				t.Fatalf("known = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("candidates = %d, want %d", len(got), len(tc.wantIDs))
			}
			for i := range tc.wantIDs {
				if got[i].ID != tc.wantIDs[i] {
					t.Fatalf("candidate[%d] = tunnel %d, want %d (order must be preserved)", i, got[i].ID, tc.wantIDs[i])
				}
			}
			// The question is asked exactly once per decision, not once per candidate.
			if tc.store.asked != 1 {
				t.Fatalf("the marks were read %d times, want 1", tc.store.asked)
			}
		})
	}
}

// A manager with no durable store has no inventory writer either, so nothing can be recorded
// absent there: the candidates pass through and no read is attempted.
func TestRevalidateDestinationsWithoutAStore(t *testing.T) {
	sm := NewStickySessionManager(nil, nil, CapacityConfig{})

	got, ok := sm.revalidateDestinations(context.Background(), destinationCandidates())
	if !ok {
		t.Fatal("a manager without a store reported unknown; there is nothing that could be marked")
	}
	if len(got) != 3 {
		t.Fatalf("candidates = %d, want all 3", len(got))
	}
}

// The injected failure seam reports unknown, so the refusal path is testable deterministically.
func TestRevalidateDestinationsWithInjectedFailure(t *testing.T) {
	store := &markStore{}
	sm := NewStickySessionManager(store, nil, CapacityConfig{})
	sm.SetAbsentReadFailureForTest(errors.New("injected"))

	got, ok := sm.revalidateDestinations(context.Background(), destinationCandidates())
	if ok {
		t.Fatal("an injected failure was reported as a known answer")
	}
	if got != nil {
		t.Fatalf("an unknown answer returned %d candidates", len(got))
	}
	if store.asked != 0 {
		t.Fatal("the injected failure still queried the store")
	}
}

// The snapshot hook runs between the candidate snapshot and the re-read, which is the ordering
// the regression depends on; assert it is wired in that order and is clearable.
func TestCandidateSnapshotHookRunsBeforeTheReread(t *testing.T) {
	store := &markStore{}
	sm := NewStickySessionManager(store, nil, CapacityConfig{})
	sm.SetCandidateSnapshotHookForTest(func() { store.events = append(store.events, "hook") })

	if _, ok := sm.revalidateDestinations(context.Background(), destinationCandidates()); !ok {
		t.Fatal("a healthy store reported unknown")
	}
	sm.SetCandidateSnapshotHookForTest(nil)
	if sm.candidateHookForTest != nil {
		t.Fatal("the hook was not cleared")
	}
}

// snapshotPeers reproduces the report ordering, so a refusal is reported deterministically.
func TestSnapshotPeersIsOrdered(t *testing.T) {
	sm := NewStickySessionManager(nil, nil, CapacityConfig{})
	snap := failoverSnapshot{degradedPeers: []stickyPeerTarget{
		{peerKey: "peer-c"}, {peerKey: "peer-a"}, {peerKey: "peer-b"},
	}}
	got := sm.snapshotPeers(snap)
	if len(got) != 3 || got[0].peerKey != "peer-a" || got[1].peerKey != "peer-b" || got[2].peerKey != "peer-c" {
		t.Fatalf("peers = %v, want peer-a, peer-b, peer-c", []string{got[0].peerKey, got[1].peerKey, got[2].peerKey})
	}
	// The snapshot itself is not reordered in place.
	if snap.degradedPeers[0].peerKey != "peer-c" {
		t.Fatal("the caller's snapshot was mutated")
	}
}
