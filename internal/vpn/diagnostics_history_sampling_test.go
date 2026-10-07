package vpn

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func newTestHistoryService(t *testing.T) (*Service, *forwarder.Forwarder, *testBackendDevice) {
	t.Helper()
	fwd, err := forwarder.NewForwarderWithLimits(nil, "10.100.0.0/16", 10, forwarder.DefaultBackendQueueSize)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}

	pool := tunnel.NewPool(nil)
	tun, err := pool.AddTunnel(t.Context(), 1, "nexus-backend.invalid:51820", "fixture-key")
	if err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}
	tun.Status = TunnelStatusActive

	dev := &testBackendDevice{lastHandshakeFn: func() time.Time { return time.Time{} }}
	fwd.AttachBackendDevice(1, dev)

	sessions := session.NewSessionManager(nil, nil)
	live, err := sessions.CreateSession(t.Context(), "user", "peer-history", "10.100.0.2", 1, "client")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	retPath := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
		return len(p), nil
	})
	fwd.RegisterSessionWithReturnPath(live.ID, "c", "peer-history", "10.100.0.2", 1, retPath)

	svc := &Service{
		forwarder:      fwd,
		sessionMgr:     sessions,
		pool:           pool,
		rollingHistory: NewRollingHistory(),
		running:        true,
		backendDevices: map[int64]BackendDevice{1: dev},
		ingressEngine:  &IngressEngine{running: true, peerSync: &peerSynchronizer{}},
		cfg:            &models.VPNConfig{PublicEndpoint: "nexus.invalid:51820"},
	}

	return svc, fwd, dev
}

// TestHistoryIndependentOfForegroundPolling_Loss demonstrates the consumptive loss bug:
// foreground status reads (at t=5) advance shared baselines and consume deltas,
// causing the fixed-cadence historical interval (t=10) to record zero loss.
func TestHistoryIndependentOfForegroundPolling_Loss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc, fwd, _ := newTestHistoryService(t)

		// Fill backend queue so next client packet will be refused with ErrQueueFull
		for range forwarder.DefaultBackendQueueSize {
			if err := fwd.RouteClientToBackend("peer-history", []byte("filler")); err != nil {
				t.Fatalf("filling backend queue: %v", err)
			}
		}

		ctx := context.Background()
		// Prime both foreground and history at t=0
		_, _ = svc.GetStatus(ctx)
		svc.sampleRollingHistory()

		time.Sleep(1 * time.Second)

		// Admit 1 loss at t=1
		if err := fwd.RouteClientToBackend("peer-history", []byte("overflow")); err != forwarder.ErrQueueFull {
			t.Fatalf("expected ErrQueueFull, got %v", err)
		}

		time.Sleep(4 * time.Second)

		// Foreground read at t=5 observes the loss and advances the shared baseline
		dashboard, err := svc.GetStatus(ctx)
		if err != nil {
			t.Fatalf("GetStatus: %v", err)
		}
		if dashboard.DropCategories.ReasonRates["client_backend_queue_full"] <= 0 {
			t.Fatalf("dashboard never observed the loss: %+v", dashboard.DropCategories)
		}

		time.Sleep(5 * time.Second)

		// History sample at t=10 must retain the loss that occurred in [0s, 10s]
		svc.sampleRollingHistory()

		points := svc.rollingHistory.Snapshot().Window15m
		if len(points) < 2 {
			t.Fatalf("expected at least 2 history points, got %d", len(points))
		}
		latest := points[len(points)-1]

		if latest.DropReasonRates["client_backend_queue_full"] <= 0 {
			t.Fatalf("FAIL: foreground read at t=5 consumed the loss; history at t=10 recorded zero: %+v", latest.DropReasonRates)
		}
		if latest.TotalDropRate <= 0 {
			t.Fatalf("FAIL: history at t=10 total drop rate was zero: %v", latest.TotalDropRate)
		}
	})
}

// TestHistoryIndependentOfForegroundPolling_Traffic demonstrates the consumptive traffic bug:
// foreground status reads at t=5 consume forwarder and backend traffic deltas,
// causing historical points at t=10 to record 0 throughput and packet rate.
func TestHistoryIndependentOfForegroundPolling_Traffic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc, fwd, _ := newTestHistoryService(t)

		ctx := context.Background()
		// Prime both foreground and history at t=0
		_, _ = svc.GetStatus(ctx)
		svc.sampleRollingHistory()

		time.Sleep(2 * time.Second)

		// Route client packet at t=2
		rxPkt := ownedIngressPacket("10.100.0.2")
		if err := fwd.RouteClientToBackend("peer-history", rxPkt); err != nil {
			t.Fatalf("routing client packet: %v", err)
		}

		time.Sleep(3 * time.Second)

		// Foreground read at t=5
		dashboard, err := svc.GetStatus(ctx)
		if err != nil {
			t.Fatalf("GetStatus: %v", err)
		}
		if !dashboard.Rates.Available || dashboard.Rates.RxPps <= 0 {
			t.Fatalf("dashboard missed initial traffic: %+v", dashboard.Rates)
		}

		time.Sleep(5 * time.Second)

		// History sample at t=10
		svc.sampleRollingHistory()

		points := svc.rollingHistory.Snapshot().Window15m
		if len(points) < 2 {
			t.Fatalf("expected at least 2 history points, got %d", len(points))
		}
		latest := points[len(points)-1]

		if latest.RxPps <= 0 {
			t.Fatalf("FAIL: foreground read consumed traffic; history at t=10 has RxPps=%v", latest.RxPps)
		}
		if latest.RxBps <= 0 {
			t.Fatalf("FAIL: history at t=10 has RxBps=%v", latest.RxBps)
		}

		foundBackend := false
		for _, b := range latest.Backends {
			if b.ID == 1 {
				foundBackend = true
				if b.RxPps <= 0 || b.RxBps <= 0 {
					t.Fatalf("FAIL: backend 1 history at t=10 lost traffic to foreground read: %+v", b)
				}
			}
		}
		if !foundBackend {
			t.Fatal("backend 1 missing from history")
		}
	})
}

// TestHistoryPollEquivalenceAndConservation tests that identical event streams
// produce equivalent fixed-cadence history regardless of foreground poll frequency,
// and that interval rate multiplied by duration conserves admitted events.
func TestHistoryPollEquivalenceAndConservation(t *testing.T) {
	runScenario := func(t *testing.T, pollIntervals []time.Duration) HistoryPoint {
		t.Helper()
		var point HistoryPoint
		synctest.Test(t, func(t *testing.T) {
			svc, fwd, _ := newTestHistoryService(t)

			// Fill queue to capacity - 1 so exactly 2 packets cause 1 drop
			for range forwarder.DefaultBackendQueueSize - 1 {
				if err := fwd.RouteClientToBackend("peer-history", []byte("fill")); err != nil {
					t.Fatalf("fill: %v", err)
				}
			}

			// Prime history at t=0
			svc.sampleRollingHistory()

			// Event timeline:
			// t=1: 1 packet admitted (reaches capacity)
			// t=2: 1 packet refused (queue full drop)
			time.Sleep(1 * time.Second)
			rxPkt := ownedIngressPacket("10.100.0.2")
			if err := fwd.RouteClientToBackend("peer-history", rxPkt); err != nil {
				t.Fatalf("admitted packet: %v", err)
			}

			time.Sleep(1 * time.Second)
			if err := fwd.RouteClientToBackend("peer-history", []byte("refused")); err != forwarder.ErrQueueFull {
				t.Fatalf("expected ErrQueueFull, got %v", err)
			}

			// Now advance to t=10, executing any foreground polls at requested intervals
			current := 2 * time.Second
			for _, pollAt := range pollIntervals {
				if pollAt > current && pollAt < 10*time.Second {
					time.Sleep(pollAt - current)
					current = pollAt
					_, _ = svc.GetStatus(context.Background())
				}
			}
			if current < 10*time.Second {
				time.Sleep(10*time.Second - current)
			}

			// Sample history at t=10
			svc.sampleRollingHistory()

			points := svc.rollingHistory.Snapshot().Window15m
			if len(points) < 2 {
				t.Fatalf("expected at least 2 points, got %d", len(points))
			}
			point = points[len(points)-1]
		})
		return point
	}

	t.Run("ZeroPolls", func(t *testing.T) {
		ptZero := runScenario(t, nil)
		if ptZero.DropReasonRates["client_backend_queue_full"] <= 0 {
			t.Fatalf("zero polls lost drop: %+v", ptZero.DropReasonRates)
		}
	})

	t.Run("Equivalence", func(t *testing.T) {
		ptZero := runScenario(t, nil)
		ptOne := runScenario(t, []time.Duration{5 * time.Second})
		ptMany := runScenario(t, []time.Duration{
			1 * time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second,
			5 * time.Second, 6 * time.Second, 7 * time.Second, 8 * time.Second, 9 * time.Second,
		})

		// Drop rate equivalence
		dropZero := ptZero.DropReasonRates["client_backend_queue_full"]
		dropOne := ptOne.DropReasonRates["client_backend_queue_full"]
		dropMany := ptMany.DropReasonRates["client_backend_queue_full"]

		if dropZero != dropOne || dropZero != dropMany {
			t.Fatalf("drop rate mismatch: zero=%v one=%v many=%v", dropZero, dropOne, dropMany)
		}

		// Rx PPS equivalence
		if ptZero.RxPps != ptOne.RxPps || ptZero.RxPps != ptMany.RxPps {
			t.Fatalf("RxPps mismatch: zero=%v one=%v many=%v", ptZero.RxPps, ptOne.RxPps, ptMany.RxPps)
		}

		// Conservation check: duration = 10s, exactly 1 packet and 1 drop occurred in [0s, 10s]
		// Rate * 10s should be ~1
		conservedDrops := dropZero * 10.0
		if conservedDrops < 0.99 || conservedDrops > 1.01 {
			t.Fatalf("drop conservation failure: rate=%v * 10s = %v, want 1", dropZero, conservedDrops)
		}
	})
}
