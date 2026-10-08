package vpn

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

func TestGetStatusLatencyHealthWindowSeconds(t *testing.T) {
	svc, err := NewVPNService(setupTestDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.forwarder = forwarder.NewForwarder(nil, "")
	svc.cfg = &models.VPNConfig{PublicEndpoint: "nexus.invalid:51820"}
	status, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.ForwardLatency.P95HealthWindowSec != 60 {
		t.Fatalf("60-second health window serialized as %d seconds", status.ForwardLatency.P95HealthWindowSec)
	}
}

func TestHistoryLatencyFreshnessAndAvailability(t *testing.T) {
	svc, err := NewVPNService(setupTestDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.cfg = &models.VPNConfig{PublicEndpoint: "nexus.invalid:51820"}
	synctest.Test(t, func(t *testing.T) {
		f := forwarder.NewForwarder(nil, "")
		svc.forwarder = f
		slow := true
		path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
			if slow {
				time.Sleep(200 * time.Millisecond)
			}
			return len(p), nil
		})
		f.RegisterSessionWithReturnPath("session", "connection", "peer", "192.0.2.1", 1, path)
		f.StartPumps(t.Context())
		defer f.StopPumps()
		packet := make([]byte, 28)
		packet[0], packet[3] = 0x45, 28
		packet[16], packet[18], packet[19] = 192, 2, 1
		enqueue := func() {
			t.Helper()
			if err := f.RouteBackendToClient(1, packet, "192.0.2.1"); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
		}
		sample := func(wantMS float64, wantSamples int) {
			t.Helper()
			svc.sampleRollingHistory()
			points := svc.rollingHistory.Snapshot().Window15m
			point := points[len(points)-1]
			if point.ForwardP95MS != wantMS {
				t.Errorf("current history p95=%v; want %v", point.ForwardP95MS, wantMS)
			}
			encoded, err := json.Marshal(point)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if count, ok := fields["fwd_p95_samples"]; !ok || count != float64(wantSamples) {
				t.Errorf("history must distinguish missing/zero observations: %s; want samples=%d", encoded, wantSamples)
			}
		}
		enqueue()
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		sample(200, 1)
		time.Sleep(61 * time.Second)
		sample(0, 0)
		status, err := svc.GetStatus(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if status.ForwardLatency.P95MS != 200 || status.ForwardLatency.P95HealthSamples != 0 {
			t.Fatalf("descriptive history must remain while current latency expires: %+v", status.ForwardLatency)
		}
		slow = false
		enqueue()
		sample(0, 1)
	})
}

func TestProblemRoutePressureNoteExactThreshold(t *testing.T) {
	for _, tc := range []struct {
		capacity, occupancy int
		queue               bool
	}{
		{1, 0, false}, {2, 1, false}, {5, 4, true}, {2048, 1638, false}, {2048, 1639, true},
	} {
		routes := []forwarder.RouteInfo{{PeerKey: "peer", HasPressure: true,
			Stats: forwarder.RouteQueueStats{Capacity: tc.capacity, Occupancy: tc.occupancy, WriteErrorsRecent: 1}}}
		note := collectProblemRoutes(routes)[0].PressureNote
		if strings.HasPrefix(note, "Queue pressure:") != tc.queue {
			t.Errorf("note for %d/%d=%q; queue pressure=%v", tc.occupancy, tc.capacity, note, tc.queue)
		}
	}
}

func TestGetStatus_CountersSince(t *testing.T) {
	svc, err := NewVPNService(setupTestDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.forwarder = forwarder.NewForwarder(nil, "")
	svc.cfg = &models.VPNConfig{PublicEndpoint: "nexus.invalid:51820"}

	// 1. Before Start, startedAt is zero, CountersSince is omitted
	status, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.CountersSince != "" {
		t.Fatalf("expected empty CountersSince before start, got %q", status.CountersSince)
	}

	// 2. Setting startedAt produces properly formatted baseline
	fixedTime := time.Date(2026, 10, 7, 6, 14, 0, 0, time.UTC)
	svc.mu.Lock()
	svc.startedAt = fixedTime
	svc.mu.Unlock()

	status, err = svc.GetStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.CountersSince != "2026-10-07 06:14 UTC" {
		t.Fatalf("expected CountersSince '2026-10-07 06:14 UTC', got %q", status.CountersSince)
	}

	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"counters_since":"2026-10-07 06:14 UTC"`) {
		t.Fatalf("serialized status missing counters_since: %s", string(raw))
	}

	// 3. Stop resets startedAt
	svc.running = true
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	status, err = svc.GetStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.CountersSince != "" {
		t.Fatalf("expected empty CountersSince after Stop, got %q", status.CountersSince)
	}
}
