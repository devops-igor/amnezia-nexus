package forwarder

import (
	"testing"
	"time"
)

type dummyWriter struct {
	writeDelay time.Duration
}

func (d *dummyWriter) Read(p []byte) (int, error) {
	return 0, nil
}

func (d *dummyWriter) Write(p []byte) (int, error) {
	if d.writeDelay > 0 {
		time.Sleep(d.writeDelay)
	}
	return len(p), nil
}

func (d *dummyWriter) Close() error {
	return nil
}

func TestInspectAndProblemRoutes(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}
	f.AttachBackendDevice(1, &dummyWriter{})

	// Register 3 routes
	// Route 1: normal
	f.RegisterSession("s1", "c1", "peer1", "10.100.0.2", 1)
	// Route 2: with drops
	f.RegisterSession("s2", "c2", "peer2", "10.100.0.3", 1)
	// Route 3: normal
	f.RegisterSession("s3", "c3", "peer3", "10.100.0.4", 1)

	// Simulate drops on Route 2
	f.mu.RLock()
	r2 := f.routesByPeer["peer2"]
	r2.queueFullDrops.Add(5)
	f.mu.RUnlock()

	routes := f.InspectRoutes()
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes in InspectRoutes, got %d", len(routes))
	}

	problemRoutes := f.ProblemRoutes(10)
	if len(problemRoutes) != 3 {
		t.Fatalf("expected 3 routes in ProblemRoutes, got %d", len(problemRoutes))
	}

	// First route must be peer2 because it has drops
	if problemRoutes[0].PeerKey != "peer2" {
		t.Errorf("expected peer2 to be ranked first due to drops, got %s", problemRoutes[0].PeerKey)
	}
	if !problemRoutes[0].HasPressure {
		t.Errorf("expected peer2 to have HasPressure=true")
	}

	// Limit ProblemRoutes to 1
	top1 := f.ProblemRoutes(1)
	if len(top1) != 1 || top1[0].PeerKey != "peer2" {
		t.Errorf("expected top 1 problem route to be peer2, got %+v", top1)
	}
}

func TestLatencyReservoir(t *testing.T) {
	res := &latencyReservoir{}

	p50, p95, p99 := res.percentiles()
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Fatalf("expected 0 for empty reservoir, got p50=%v p95=%v p99=%v", p50, p95, p99)
	}

	// Record 100 samples from 1ms to 100ms
	for i := 1; i <= 100; i++ {
		res.record(time.Duration(i) * time.Millisecond)
	}

	p50, p95, p99 = res.percentiles()
	if p50 < 45*time.Millisecond || p50 > 55*time.Millisecond {
		t.Errorf("expected p50 around 50ms, got %v", p50)
	}
	if p95 < 90*time.Millisecond || p95 > 98*time.Millisecond {
		t.Errorf("expected p95 around 95ms, got %v", p95)
	}
	if p99 < 95*time.Millisecond || p99 > 100*time.Millisecond {
		t.Errorf("expected p99 around 99ms, got %v", p99)
	}
}
