package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func canaryHistoryFixture(t *testing.T) (*HealthProber, *Pool, *models.BackendTunnel) {
	t.Helper()
	db := setupTestDB(t)
	pool := NewPool(db)
	sid, err := db.CreateServer(t.Context(), &models.Server{Name: "history", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(t.Context(), sid, "192.0.2.10:51820", "fixture-public-key")
	if err != nil {
		t.Fatal(err)
	}
	return NewHealthProber(pool, db, DefaultHealthConfig()), pool, tun
}

func TestCanaryHistoryRejectsInvalidatedResults(t *testing.T) {
	for _, invalidation := range []string{"version", "replacement", "admin"} {
		for _, outcome := range []string{"success", "failure"} {
			t.Run(invalidation+"/"+outcome, func(t *testing.T) {
				hp, pool, tun := canaryHistoryFixture(t)
				calls := 0
				hp.SetCanarySuccessCallback(func(int64) { calls++ })
				t.Cleanup(func() { hp.SetCanarySuccessCallback(nil) })
				hp.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
					switch invalidation {
					case "version":
						if err := pool.SetTunnelStatus(t.Context(), tun.ServerID, models.TunnelStatusHandshakeBlocked, 0); err != nil {
							t.Fatal(err)
						}
					case "replacement":
						if err := pool.RemoveTunnel(t.Context(), tun.ServerID); err != nil {
							t.Fatal(err)
						}
						if _, err := pool.AddTunnel(t.Context(), tun.ServerID, "192.0.2.10:51820", "replacement-key"); err != nil {
							t.Fatal(err)
						}
					case "admin":
						if err := pool.SetTunnelEnabled(t.Context(), tun.ServerID, false, models.DisableReasonAdmin); err != nil {
							t.Fatal(err)
						}
					}
					current, err := pool.GetTunnel(tun.ServerID)
					if err != nil {
						t.Fatal(err)
					}
					// Model an accepted newer observation, not the stale completion.
					hp.mu.Lock()
					hp.canaryFailCounts[tun.ServerID] = 2
					hp.canaryResults = map[int64]canaryResult{tun.ServerID: {tunnelID: current.ID}}
					hp.mu.Unlock()
					if outcome == "failure" {
						return errors.New("old timeout")
					}
					return nil
				})
				err := hp.ProbeCanary(t.Context(), tun)
				if !isObsoleteCanary(err) {
					t.Fatalf("invalidated result accepted: %v", err)
				}
				if got := hp.GetCanaryFailCount(tun.ServerID); got != 2 || calls != 0 {
					t.Fatalf("invalidated result changed newer history: count=%d notifications=%d", got, calls)
				}
			})
		}
	}
}

func TestCanaryHistoryRejectsOutOfOrderCompletion(t *testing.T) {
	for _, oldSuccess := range []bool{false, true} {
		name := "old_failure_after_success"
		if oldSuccess {
			name = "old_success_after_failure"
		}
		t.Run(name, func(t *testing.T) {
			hp, _, tun := canaryHistoryFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			hp.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
				if calls.Add(1) == 1 {
					close(entered)
					<-release
					if oldSuccess {
						return nil
					}
					return errors.New("old loss")
				}
				if oldSuccess {
					return errors.New("new loss")
				}
				return nil
			})
			done := make(chan error, 1)
			go func() { done <- hp.ProbeCanary(t.Context(), tun) }()
			<-entered
			newErr := hp.ProbeCanary(t.Context(), tun)
			close(release)
			if err := <-done; !errors.Is(err, ErrStaleStateVersion) {
				t.Fatalf("late result accepted: %v", err)
			}
			want := 0
			if oldSuccess {
				want = 1
				if newErr == nil {
					t.Fatal("new loss not observed")
				}
			} else if newErr != nil {
				t.Fatal(newErr)
			}
			if got := hp.CanaryFailureCount(tun.ID); got != want {
				t.Fatalf("late result changed history: got %d want %d", got, want)
			}
		})
	}
}

func TestCanaryHistoryCanceledProbeDoesNotClearProof(t *testing.T) {
	hp, _, tun := canaryHistoryFixture(t)
	hp.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error { return errors.New("loss") })
	_ = hp.ProbeCanary(t.Context(), tun)
	ctx, cancel := context.WithCancel(t.Context())
	hp.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		cancel()
		return nil
	})
	if err := hp.ProbeCanary(ctx, tun); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe accepted: %v", err)
	}
	if got := hp.CanaryFailureCount(tun.ID); got != 1 {
		t.Fatalf("canceled success cleared history: %d", got)
	}
}
