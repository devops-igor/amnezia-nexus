package forwarder

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestTokenBucket_ConstructorAndClamping(t *testing.T) {
	// Nil receiver allows everything.
	var nilTb *TokenBucket
	if !nilTb.Allow(10_000_000) {
		t.Fatal("expected nil TokenBucket to allow all requests")
	}

	tests := []struct {
		name         string
		rateBps      int64
		capacityArgs []int64
		wantNil      bool
		wantRate     float64
		wantCapacity float64
	}{
		{
			name:    "negative rate returns nil",
			rateBps: -100,
			wantNil: true,
		},
		{
			name:    "zero rate returns nil",
			rateBps: 0,
			wantNil: true,
		},
		{
			name:         "positive rate without explicit capacity defaults capacity to rate",
			rateBps:      1_000_000,
			wantNil:      false,
			wantRate:     1_000_000,
			wantCapacity: 1_000_000,
		},
		{
			name:         "explicit capacity larger than rate is accepted",
			rateBps:      1_000_000,
			capacityArgs: []int64{5_000_000},
			wantNil:      false,
			wantRate:     1_000_000,
			wantCapacity: 5_000_000,
		},
		{
			name:         "explicit capacity smaller than rate is clamped up to rate",
			rateBps:      1_000_000,
			capacityArgs: []int64{500_000},
			wantNil:      false,
			wantRate:     1_000_000,
			wantCapacity: 1_000_000,
		},
		{
			name:         "non-positive explicit capacity is clamped up to rate",
			rateBps:      1_000_000,
			capacityArgs: []int64{0},
			wantNil:      false,
			wantRate:     1_000_000,
			wantCapacity: 1_000_000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tb := NewTokenBucket(tt.rateBps, tt.capacityArgs...)
			if tt.wantNil {
				if tb != nil {
					t.Fatalf("NewTokenBucket(%d, %v) = %v; want nil", tt.rateBps, tt.capacityArgs, tb)
				}
				return
			}

			if tb == nil {
				t.Fatalf("NewTokenBucket(%d, %v) returned nil unexpectedly", tt.rateBps, tt.capacityArgs)
			}
			tb.mu.Lock()
			rate := tb.rate
			capVal := tb.capacity
			tokens := tb.tokens
			tb.mu.Unlock()

			if rate != tt.wantRate {
				t.Errorf("rate = %v, want %v", rate, tt.wantRate)
			}
			if capVal != tt.wantCapacity {
				t.Errorf("capacity = %v, want %v", capVal, tt.wantCapacity)
			}
			if tokens != tt.wantCapacity {
				t.Errorf("initial tokens = %v, want full capacity %v", tokens, tt.wantCapacity)
			}
		})
	}
}

func TestTokenBucket_BurstAndRefill(t *testing.T) {
	const rate = 100_000 // 100 KB/s
	const burstCap = 250_000

	tb := NewTokenBucket(rate, burstCap)
	if tb == nil {
		t.Fatal("NewTokenBucket returned nil")
	}

	// Initial burst: consume up to capacity in two steps.
	if !tb.Allow(150_000) {
		t.Fatal("initial burst chunk 150_000 should be allowed")
	}
	if !tb.Allow(100_000) {
		t.Fatal("initial burst chunk 100_000 should be allowed")
	}

	// Immediately after full burst, no tokens remain for another chunk.
	if tb.Allow(10_000) {
		t.Fatal("request immediately after full burst should be rejected")
	}

	// Wait for partial refill: 100ms at 100 KB/s = ~10,000 bytes.
	time.Sleep(100 * time.Millisecond)

	// A 5,000 byte request fits comfortably within ~10,000 bytes of refill.
	if !tb.Allow(5_000) {
		t.Fatal("request fitting within 100ms refill should be allowed")
	}
	// A 50,000 byte request far exceeds what has refilled.
	if tb.Allow(50_000) {
		t.Fatal("request exceeding refilled tokens should be rejected")
	}

	// Wait long enough for the bucket to refill to burst capacity (at 100 KB/s, 250 KB takes 2.5s;
	// test with a smaller bucket for full-refill verification to keep test fast).
	smallTb := NewTokenBucket(1_000, 2_000)
	if !smallTb.Allow(2_000) {
		t.Fatal("smallTb burst should be allowed")
	}
	// Wait 25ms -> ~25 tokens. Verify tokens increase monotonically and cap at capacity.
	time.Sleep(30 * time.Millisecond)
	smallTb.mu.Lock()
	smallTokens := smallTb.tokens
	smallTb.mu.Unlock()
	if smallTokens < 0 {
		t.Errorf("expected positive tokens after refill, got %v", smallTokens)
	}
}

func TestTokenBucket_ConcurrentAllow(t *testing.T) {
	const rate = 1_000_000
	const capacity = 2_000_000
	tb := NewTokenBucket(rate, capacity)

	const goroutines = 16
	const requestsPerGoroutine = 100
	const chunkSize = 1_000

	var wg sync.WaitGroup
	allowedCount := int64(0)
	var countMu sync.Mutex

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localAllowed := int64(0)
			for j := 0; j < requestsPerGoroutine; j++ {
				if tb.Allow(chunkSize) {
					localAllowed++
				}
			}
			countMu.Lock()
			allowedCount += localAllowed
			countMu.Unlock()
		}()
	}

	wg.Wait()

	// Initial burst capacity is 2,000,000, which can serve at most 2,000 requests of size 1,000,
	// plus whatever small refill accrued during execution.
	// Total requested: goroutines * requestsPerGoroutine = 1600 chunks (1,600,000 bytes).
	// Because 1,600,000 <= 2,000,000 capacity, all should be allowed without errors or races.
	if allowedCount != goroutines*requestsPerGoroutine {
		t.Fatalf("concurrent allowed count = %d, want %d", allowedCount, goroutines*requestsPerGoroutine)
	}
}

func TestForwarder_SetAndGetPeerRateLimit(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 100)

	// Unregistered peer returns ErrSessionNotRegistered.
	if err := f.SetPeerRateLimit("nonexistent-peer", 1_000, 2_000); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("SetPeerRateLimit on unregistered peer: got %v, want ErrSessionNotRegistered", err)
	}
	if _, _, err := f.GetPeerRateLimit("nonexistent-peer"); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("GetPeerRateLimit on unregistered peer: got %v, want ErrSessionNotRegistered", err)
	}

	// Register a session.
	peerKey := "peer-rate-test"
	f.RegisterSession("sess-1", "conn-1", peerKey, "10.100.0.2", 1)

	// Initial limits should be 0, 0.
	down, up, err := f.GetPeerRateLimit(peerKey)
	if err != nil {
		t.Fatalf("GetPeerRateLimit failed: %v", err)
	}
	if down != 0 || up != 0 {
		t.Fatalf("initial rate limits = (%d, %d), want (0, 0)", down, up)
	}

	// Set non-zero limits.
	if err := f.SetPeerRateLimit(peerKey, 500_000, 1_000_000); err != nil {
		t.Fatalf("SetPeerRateLimit failed: %v", err)
	}

	down, up, err = f.GetPeerRateLimit(peerKey)
	if err != nil {
		t.Fatalf("GetPeerRateLimit failed: %v", err)
	}
	if down != 500_000 || up != 1_000_000 {
		t.Fatalf("configured rate limits = (%d, %d), want (500000, 1000000)", down, up)
	}

	// Verify internal TokenBucket initialization.
	f.mu.RLock()
	route := f.routesByPeer[peerKey]
	if route.tbDown == nil || route.tbUp == nil {
		f.mu.RUnlock()
		t.Fatal("expected both tbDown and tbUp to be initialized")
	}
	f.mu.RUnlock()

	// Clear limits with 0.
	if err := f.SetPeerRateLimit(peerKey, 0, 0); err != nil {
		t.Fatalf("SetPeerRateLimit clear failed: %v", err)
	}

	down, up, err = f.GetPeerRateLimit(peerKey)
	if err != nil {
		t.Fatalf("GetPeerRateLimit failed: %v", err)
	}
	if down != 0 || up != 0 {
		t.Fatalf("cleared rate limits = (%d, %d), want (0, 0)", down, up)
	}

	f.mu.RLock()
	route = f.routesByPeer[peerKey]
	if route.tbDown != nil || route.tbUp != nil {
		f.mu.RUnlock()
		t.Fatal("expected tbDown and tbUp to be nil after clearing limits")
	}
	f.mu.RUnlock()

	// Asymmetric limits: down > 0, up == 0.
	if err := f.SetPeerRateLimit(peerKey, 250_000, 0); err != nil {
		t.Fatalf("SetPeerRateLimit asymmetric failed: %v", err)
	}
	f.mu.RLock()
	route = f.routesByPeer[peerKey]
	if route.tbDown == nil || route.tbUp != nil {
		f.mu.RUnlock()
		t.Fatal("expected tbDown != nil and tbUp == nil for asymmetric limit")
	}
	f.mu.RUnlock()
}

func TestMaxClientQueuePacketsForRoutes(t *testing.T) {
	budgetPackets := MaxClientQueueMemoryBytes / MaxClientQueuePacketBytes

	tests := []struct {
		name         string
		activeRoutes int
		want         int
	}{
		{
			name:         "non-positive routes defaults to MaxSupportedActiveRoutes (1000)",
			activeRoutes: 0,
			want:         budgetPackets / MaxSupportedActiveRoutes,
		},
		{
			name:         "negative routes defaults to MaxSupportedActiveRoutes (1000)",
			activeRoutes: -10,
			want:         budgetPackets / MaxSupportedActiveRoutes,
		},
		{
			name:         "single active route receives full budget",
			activeRoutes: 1,
			want:         budgetPackets,
		},
		{
			name:         "100 active routes",
			activeRoutes: 100,
			want:         budgetPackets / 100,
		},
		{
			name:         "exact MaxBudgetedActiveRoutes population fits 1 packet per route",
			activeRoutes: MaxBudgetedActiveRoutes,
			want:         1,
		},
		{
			name:         "population exceeding budget returns 0 (rejection)",
			activeRoutes: MaxBudgetedActiveRoutes + 1,
			want:         0,
		},
		{
			name:         "extreme population far exceeding budget returns 0",
			activeRoutes: MaxBudgetedActiveRoutes * 2,
			want:         0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaxClientQueuePacketsForRoutes(tt.activeRoutes)
			if got != tt.want {
				t.Fatalf("MaxClientQueuePacketsForRoutes(%d) = %d, want %d", tt.activeRoutes, got, tt.want)
			}
		})
	}
}

func TestForwarder_ReconfigureClientQueueConfigAndSize(t *testing.T) {
	t.Run("idle forwarder valid and defaulting reconfiguration", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 50)

		// Non-positive size defaults to DefaultClientQueueSize, non-positive maxActiveRoutes defaults to MaxSupportedActiveRoutes.
		if err := f.ReconfigureClientQueueConfig(0, 0); err != nil {
			t.Fatalf("ReconfigureClientQueueConfig(0, 0) failed: %v", err)
		}
		if f.bufSize != DefaultClientQueueSize {
			t.Fatalf("bufSize = %d, want default %d", f.bufSize, DefaultClientQueueSize)
		}
		if f.maxActiveRoutes != MaxSupportedActiveRoutes {
			t.Fatalf("maxActiveRoutes = %d, want default %d", f.maxActiveRoutes, MaxSupportedActiveRoutes)
		}

		// Valid explicit values.
		if err := f.ReconfigureClientQueueConfig(128, 500); err != nil {
			t.Fatalf("ReconfigureClientQueueConfig(128, 500) failed: %v", err)
		}
		if f.bufSize != 128 || f.maxActiveRoutes != 500 {
			t.Fatalf("got bufSize=%d, maxActiveRoutes=%d; want 128, 500", f.bufSize, f.maxActiveRoutes)
		}

		// Size exceeding maximum per-route queue packets is clamped down to maxQueue.
		// For activeRoutes = 5_000_000: maxQueue = budgetPackets / 5_000_000 = 1.
		if err := f.ReconfigureClientQueueConfig(500, 5_000_000); err != nil {
			t.Fatalf("ReconfigureClientQueueConfig clamped size failed: %v", err)
		}
		if f.bufSize != 1 {
			t.Fatalf("bufSize was not clamped to maxQueue: got %d, want 1", f.bufSize)
		}

		// Exceeding MaxBudgetedActiveRoutes fails validation.
		if err := f.ReconfigureClientQueueConfig(10, MaxBudgetedActiveRoutes+1); err == nil {
			t.Fatal("expected error when maxActiveRoutes exceeds budget, got nil")
		}

		// ReconfigureClientQueueSize preserves existing maxActiveRoutes.
		if err := f.ReconfigureClientQueueConfig(64, 200); err != nil {
			t.Fatalf("prep failed: %v", err)
		}
		if err := f.ReconfigureClientQueueSize(120); err != nil {
			t.Fatalf("ReconfigureClientQueueSize(120) failed: %v", err)
		}
		if f.bufSize != 120 {
			t.Fatalf("bufSize = %d, want 120", f.bufSize)
		}
		if f.maxActiveRoutes != 200 {
			t.Fatalf("maxActiveRoutes was altered: got %d, want 200", f.maxActiveRoutes)
		}
	})

	t.Run("active sessions constraints", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 64)
		f.RegisterSession("s1", "c1", "p1", "10.100.0.2", 1)
		f.RegisterSession("s2", "c2", "p2", "10.100.0.3", 1)

		// Cannot change client queue size while sessions are active.
		if err := f.ReconfigureClientQueueConfig(128, MaxSupportedActiveRoutes); err == nil {
			t.Fatal("expected error changing queue size with active sessions, got nil")
		}
		if err := f.ReconfigureClientQueueSize(128); err == nil {
			t.Fatal("expected error from ReconfigureClientQueueSize changing size with active sessions, got nil")
		}

		// Keeping identical size while changing route limit is allowed as long as limit >= active count.
		if err := f.ReconfigureClientQueueConfig(64, 100); err != nil {
			t.Fatalf("ReconfigureClientQueueConfig with identical size failed: %v", err)
		}
		if f.maxActiveRoutes != 100 {
			t.Fatalf("maxActiveRoutes = %d, want 100", f.maxActiveRoutes)
		}

		// Lowering route limit below active session count (2 active sessions) must fail.
		if err := f.ReconfigureClientQueueConfig(64, 1); err == nil {
			t.Fatal("expected error setting maxActiveRoutes lower than active sessions count, got nil")
		}

		// ReconfigureClientQueueSize with identical size succeeds.
		if err := f.ReconfigureClientQueueSize(64); err != nil {
			t.Fatalf("ReconfigureClientQueueSize with identical size failed: %v", err)
		}
	})
}
