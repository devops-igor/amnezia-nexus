package vpn

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

type destinationBoundaryBalancer struct {
	loadbalancer.LoadBalancer
	before func()
}

func (b destinationBoundaryBalancer) SelectBackend(ctx context.Context, req *loadbalancer.RoutingRequest) (*models.BackendTunnel, error) {
	b.before()
	return b.LoadBalancer.SelectBackend(ctx, req)
}

type destinationBoundaryStore struct {
	loadbalancer.StickyStore
	before func()
}

func (s destinationBoundaryStore) CommitVPNSessionDestination(ctx context.Context, targetID int64, row *models.VPNSession, publish func()) error {
	s.before()
	return s.StickyStore.CommitVPNSessionDestination(ctx, targetID, row, publish)
}

func TestAdminFailoverCommitsOnlyEligibleDestinations(t *testing.T) {
	for _, timing := range []string{"unmarked", "before_operation", "before_selector", "before_write"} {
		t.Run(timing, func(t *testing.T) {
			f := newFailoverFixture(t)
			marked := false
			mark := func() {
				if !marked {
					f.markAbsent(t, f.first)
					marked = true
				}
			}
			store := destinationBoundaryStore{StickyStore: f.svc.db, before: func() {}}
			balancer := destinationBoundaryBalancer{LoadBalancer: f.svc.balancer, before: func() {}}
			if timing == "before_selector" {
				balancer.before = mark
			}
			if timing == "before_write" {
				store.before = func() {
					mark()
					f.assertRoutedTo(t, f.source, f.first, f.second)
					if got, ok := f.svc.stickyMgr.GetPeerAffinity(f.peer.peerKey); !ok || got != f.source.ID {
						t.Errorf("affinity published before durable acceptance: %d/%t", got, ok)
					}
				}
			}
			f.svc.stickyMgr = loadbalancer.NewStickySessionManager(store, balancer, loadbalancer.CapacityConfig{})
			f.svc.stickyMgr.AssignPeerAffinity(f.peer.peerKey, f.source.ID)
			if timing == "before_operation" {
				mark()
			}
			if err := f.svc.DisableBackend(t.Context(), f.source.ServerID); err != nil {
				t.Fatal(err)
			}
			want := f.first
			if timing != "unmarked" {
				if !marked {
					t.Fatal("absence writer was not reached")
				}
				want = f.second
			}
			row, err := f.svc.db.GetVPNSessionByID(t.Context(), f.sess.ID)
			if err != nil || row == nil {
				t.Fatalf("durable read: %v", err)
			}
			if row.BackendTunnelID != want.ID {
				t.Errorf("durable backend = %d, want %d", row.BackendTunnelID, want.ID)
			}
			if got, ok := f.svc.stickyMgr.GetPeerAffinity(f.peer.peerKey); !ok || got != want.ID {
				t.Errorf("affinity = %d/%t, want %d", got, ok, want.ID)
			}
			f.assertRoutedTo(t, want, f.first, f.second, f.source)
		})
	}
}

func TestAdminFailoverReportsExhaustedDestinationsWithoutPublishing(t *testing.T) {
	f := newFailoverFixture(t)
	store := destinationBoundaryStore{StickyStore: f.svc.db, before: func() {
		f.markAbsent(t, f.first)
		f.markAbsent(t, f.second)
	}}
	f.svc.stickyMgr = loadbalancer.NewStickySessionManager(store, f.svc.balancer, loadbalancer.CapacityConfig{})
	f.svc.stickyMgr.AssignPeerAffinity(f.peer.peerKey, f.source.ID)
	if err := f.svc.DisableBackend(t.Context(), f.source.ServerID); err != nil {
		t.Fatal(err)
	}
	f.assertRoutedTo(t, f.source, f.first, f.second)
	row, err := f.svc.db.GetVPNSessionByID(t.Context(), f.sess.ID)
	if err != nil || row == nil || row.BackendTunnelID != f.source.ID {
		t.Fatalf("refusal changed durable row: row=%+v err=%v", row, err)
	}
	if got, ok := f.svc.stickyMgr.GetPeerAffinity(f.peer.peerKey); !ok || got != f.source.ID {
		t.Fatalf("refusal changed affinity: %d/%t", got, ok)
	}
	if got := f.svc.stickyMgr.SkippedMigrationsTotal(); got != 1 {
		t.Fatalf("exhausted destinations reported %d skips, want 1", got)
	}
}

func TestMigrationCompensationRestoresMarkedHeldDestination(t *testing.T) {
	f := newFailoverFixture(t)
	if err := f.svc.MigrateSession(t.Context(), f.sess.ID, f.first.ID); err != nil {
		t.Fatal(err)
	}
	f.markAbsent(t, f.source)
	if err := f.svc.rollbackMigration(t.Context(), f.sess.ID, f.peer.peerKey, f.source.ID, "connected", true, true, true); err != nil {
		t.Fatal(err)
	}
	f.assertRoutedTo(t, f.source, f.first)
	row, err := f.svc.db.GetVPNSessionByID(t.Context(), f.sess.ID)
	if err != nil || row == nil || row.BackendTunnelID != f.source.ID {
		t.Fatalf("compensation did not restore durable destination: row=%+v err=%v", row, err)
	}
}

func TestProviderMarkPreservesHeldRoute(t *testing.T) {
	f := newFailoverFixture(t)
	f.markAbsent(t, f.source)
	f.assertRoutedTo(t, f.source, f.first, f.second)
	row, err := f.svc.db.GetVPNSessionByID(t.Context(), f.sess.ID)
	if err != nil || row == nil || row.BackendTunnelID != f.source.ID || row.Status != "connected" {
		t.Fatalf("mark changed the held session: row=%+v err=%v", row, err)
	}
}
