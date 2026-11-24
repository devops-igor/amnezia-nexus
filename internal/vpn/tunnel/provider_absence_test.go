package tunnel

// The runtime health prober is the automatic consumer that kept dialling in the
// previous round: it is a separate worker from the orchestrator's loop and it
// reaches the handshake path through probeEndpoint. These cases drive the real
// prober, pool and database, and intercept only the terminal handshake sender, so
// "no attempt" is counted rather than asserted.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// countingProbe records every terminal handshake the prober attempts and reports
// a healthy measurement so a live control stays green.
type countingProbe struct {
	mu        sync.Mutex
	endpoints []string
}

func (p *countingProbe) probe(_ context.Context, endpoint, _, _, _, _ string, _, _ any, _, _ int, _ time.Duration) (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endpoints = append(p.endpoints, endpoint)
	return 9 * time.Millisecond, nil
}

func (p *countingProbe) attempts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.endpoints...)
}

func TestHealthProber_ProbeAll_RefusesProviderAbsentServer(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	absentID, err := db.CreateServer(ctx, &models.Server{Name: "provider absent", Host: "192.0.2.101", SSHPort: 22})
	if err != nil {
		t.Fatalf("seeding the absent server: %v", err)
	}
	liveID, err := db.CreateServer(ctx, &models.Server{Name: "still listed", Host: "192.0.2.102", SSHPort: 22})
	if err != nil {
		t.Fatalf("seeding the listed server: %v", err)
	}
	if _, err := pool.AddTunnel(ctx, absentID, "192.0.2.101:51820", "absent-key"); err != nil {
		t.Fatalf("seeding the absent server's tunnel: %v", err)
	}
	if _, err := pool.AddTunnel(ctx, liveID, "192.0.2.102:51820", "live-key"); err != nil {
		t.Fatalf("seeding the listed server's tunnel: %v", err)
	}
	if err := db.SetServerProviderAbsence(ctx, absentID, time.Now().UTC()); err != nil {
		t.Fatalf("recording the provider absence: %v", err)
	}

	absentBefore, err := pool.GetTunnel(absentID)
	if err != nil || absentBefore == nil {
		t.Fatalf("reading the absent server's tunnel: %v", err)
	}

	probe := &countingProbe{}
	hp := NewHealthProber(pool, db, HealthConfig{
		Interval:         time.Minute,
		Timeout:          2 * time.Second,
		FailureThreshold: 3,
	}, probe.probe)

	results := hp.ProbeAll(ctx)

	attempts := probe.attempts()
	if len(attempts) != 1 {
		t.Fatalf("expected exactly one handshake attempt (the listed server), got %d: %v", len(attempts), attempts)
	}
	if attempts[0] != "192.0.2.102:51820" {
		t.Fatalf("the handshake was attempted against %q, want only the listed server's endpoint", attempts[0])
	}
	if !errors.Is(results[absentID], ErrProviderAbsent) {
		t.Fatalf("the absent server's result is %v, want ErrProviderAbsent", results[absentID])
	}
	if results[liveID] != nil {
		t.Fatalf("the listed server's probe failed: %v", results[liveID])
	}

	// A refusal is not a measurement: the retained row and its prior health stand.
	absentAfter, err := pool.GetTunnel(absentID)
	if err != nil || absentAfter == nil {
		t.Fatalf("re-reading the absent server's tunnel: %v", err)
	}
	if absentAfter.Status != absentBefore.Status || absentAfter.LatencyMS != absentBefore.LatencyMS {
		t.Fatalf("the refusal changed the absent tunnel's health: before=%+v after=%+v", absentBefore, absentAfter)
	}
	hp.mu.RLock()
	failures := hp.failCounts[absentID]
	hp.mu.RUnlock()
	if failures != 0 {
		t.Fatalf("the refusal was recorded as %d probe failure(s)", failures)
	}

	// The listed server's measurement is recorded normally.
	liveAfter, err := pool.GetTunnel(liveID)
	if err != nil || liveAfter == nil {
		t.Fatalf("reading the listed server's tunnel: %v", err)
	}
	if liveAfter.LatencyMS != 9 {
		t.Fatalf("the listed server's latency was not recorded: %+v", liveAfter)
	}
}

func TestHealthProber_SelfHealing_RefusesProviderAbsentServer(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	absentID, err := db.CreateServer(ctx, &models.Server{Name: "provider absent", Host: "192.0.2.111"})
	if err != nil {
		t.Fatalf("seeding the absent server: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, absentID, "192.0.2.111:51820", "absent-key")
	if err != nil {
		t.Fatalf("seeding the tunnel: %v", err)
	}
	if err := db.SetServerProviderAbsence(ctx, absentID, time.Now().UTC()); err != nil {
		t.Fatalf("recording the provider absence: %v", err)
	}

	probe := &countingProbe{}
	hp := NewHealthProber(pool, db, HealthConfig{Interval: time.Minute, Timeout: 2 * time.Second}, probe.probe)

	// The self-healing sweep reports "not measured" rather than an outer failure, so
	// the caller neither records a failure nor consults the inner canary.
	latency, ready, outerFailed := hp.probeAndFlapDamp(ctx, tun, 2)
	if latency != 0 || ready || outerFailed {
		t.Fatalf("self-healing reported latency=%d ready=%v outerFailed=%v, want a not-measured result", latency, ready, outerFailed)
	}
	if attempts := probe.attempts(); len(attempts) != 0 {
		t.Fatalf("the self-healing sweep attempted %d handshake(s) against an absent server: %v", len(attempts), attempts)
	}
	hp.mu.RLock()
	successes := hp.successCounts[absentID]
	hp.mu.RUnlock()
	if successes != 0 {
		t.Fatalf("the refusal was recorded as %d successful probe(s)", successes)
	}
}

func TestReconnectManager_RefusesProviderAbsentServer(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	absentID, err := db.CreateServer(ctx, &models.Server{Name: "provider absent", Host: "192.0.2.121"})
	if err != nil {
		t.Fatalf("seeding the absent server: %v", err)
	}
	if _, err := pool.AddTunnel(ctx, absentID, "192.0.2.121:51820", "absent-key"); err != nil {
		t.Fatalf("seeding the tunnel: %v", err)
	}
	if err := pool.SetTunnelStatus(ctx, absentID, models.TunnelStatusDegraded, 0); err != nil {
		t.Fatalf("marking the tunnel degraded: %v", err)
	}
	if err := db.SetServerProviderAbsence(ctx, absentID, time.Now().UTC()); err != nil {
		t.Fatalf("recording the provider absence: %v", err)
	}

	probe := &countingProbe{}
	hp := NewHealthProber(pool, db, HealthConfig{Interval: time.Minute, Timeout: 2 * time.Second}, probe.probe)
	rm := NewReconnectManager(pool, hp, DefaultReconnectConfig())

	if got := rm.CheckAndReconnect(ctx); got != 0 {
		t.Fatalf("the reconnect sweep reported %d reconnections, want 0", got)
	}
	if attempts := probe.attempts(); len(attempts) != 0 {
		t.Fatalf("the reconnect sweep attempted %d handshake(s) against an absent server: %v", len(attempts), attempts)
	}
	retries, nextAttempt, backoff := rm.GetTunnelRetryState(absentID)
	if retries != 0 || !nextAttempt.IsZero() || backoff != 0 {
		t.Fatalf("the refusal changed retry accounting: retries=%d next=%v backoff=%v", retries, nextAttempt, backoff)
	}
	after, err := pool.GetTunnel(absentID)
	if err != nil || after == nil {
		t.Fatalf("re-reading the tunnel: %v", err)
	}
	if after.Status != models.TunnelStatusDegraded {
		t.Fatalf("the refusal rewrote the tunnel status to %q", after.Status)
	}
}
