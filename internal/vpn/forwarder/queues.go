package forwarder

import (
	"errors"
	"sync"
	"time"
)

// TokenBucket implements a token bucket rate limiter for per-peer bandwidth throttling.
//
// Rate-vs-burst semantics (issue #94): `rate` is the SUSTAINED throughput in
// bytes per second — the long-run average the bucket refills at. `capacity`
// is the BURST budget: the maximum number of bytes that can be consumed
// instantaneously, bounded by the tokens accumulated in the bucket. The two
// are independent: a bucket configured at 1 MB/s with a 4 MB capacity can
// deliver a 4 MB burst immediately and then sustain 1 MB/s; a bucket at
// 1 MB/s with capacity 128 KB can only ever burst 128 KB before waiting for
// refills. `limitBps` alone is therefore NOT a hard per-second ceiling —
// short windows may exceed it by up to the burst capacity.
//
// With no explicit capacity, NewTokenBucket defaults capacity to the rate,
// i.e. the bucket starts full and permits an initial burst of up to one
// full second of configured bandwidth (a configured 1 MB/s limit permits a
// ~1 MB initial burst). Any supplied capacity is clamped to at least the
// rate (see NewTokenBucket). Tokens refill continuously at the rate while
// idle and cap at capacity.
//
// The bucket is mutex-guarded: Allow is safe for concurrent use from
// multiple goroutines (per-peer limit buckets are shared by concurrent
// packet pumps — see sessionRoute.tbDown/tbUp and RouteClientToBackend /
// RouteBackendToClient).
type TokenBucket struct {
	rate       float64 // bytes per second (sustained refill rate)
	capacity   float64 // burst capacity in bytes (max instantaneous burst)
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket with rate in bytes per second.
//
// rateBps is the sustained refill rate in bytes/second; an optional second
// argument overrides the burst capacity in bytes. Defaults and clamping:
//   - capacity defaults to rateBps, so the bucket starts full and permits an
//     initial burst of up to one second's worth of configured bandwidth
//     (1 MB/s ⇒ ~1 MB initial burst — issue #94).
//   - a capacity below rateBps is clamped UP to rateBps; the sustained rate
//     always remains achievable.
//   - tokens start at capacity (full bucket).
//
// A non-positive rate returns nil; callers treat a nil *TokenBucket as
// "unlimited" (Allow on a nil receiver always returns true).
func NewTokenBucket(rateBps int64, capacity ...int64) *TokenBucket {
	if rateBps <= 0 {
		return nil
	}
	capVal := float64(rateBps)
	if len(capacity) > 0 && capacity[0] > 0 {
		capVal = float64(capacity[0])
	}
	if capVal < float64(rateBps) {
		capVal = float64(rateBps)
	}
	return &TokenBucket{
		rate:       float64(rateBps),
		capacity:   capVal,
		tokens:     capVal,
		lastUpdate: time.Now(),
	}
}

// Allow returns true if n bytes can be consumed from the bucket, and deducts the tokens.
func (tb *TokenBucket) Allow(n int64) bool {
	if tb == nil {
		return true
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.lastUpdate = now

	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}
	return false
}

// MaxClientQueuePacketsForRoutes returns the largest per-route queue capacity
// that keeps the configured active-route population within the aggregate
// queued-payload memory budget. Zero means the population cannot fit even one
// packet per route and must be rejected.
func MaxClientQueuePacketsForRoutes(activeRoutes int) int {
	if activeRoutes <= 0 {
		activeRoutes = MaxSupportedActiveRoutes
	}
	maxBudgetPackets := MaxClientQueueMemoryBytes / MaxClientQueuePacketBytes
	if activeRoutes > maxBudgetPackets {
		return 0
	}
	maxPackets := maxBudgetPackets / activeRoutes
	if maxPackets < 1 {
		return 1
	}
	return maxPackets
}

// SetPeerRateLimit sets per-peer bandwidth throttling limits in bytes per second.
//
// Rate-limit wiring (issue #94): the limits are SUSTAINED rates in
// bytes/second (see TokenBucket); each replaces the peer's per-direction
// bucket with a fresh one at burst capacity = rate. Passing 0 for a
// direction removes that direction's bucket (unlimited).
func (f *Forwarder) SetPeerRateLimit(peerKey string, limitDownBps, limitUpBps int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	route, ok := f.routesByPeer[peerKey]
	if !ok {
		return ErrSessionNotRegistered
	}

	route.limitDownBps = limitDownBps
	route.limitUpBps = limitUpBps
	if limitDownBps > 0 {
		route.tbDown = NewTokenBucket(limitDownBps)
	} else {
		route.tbDown = nil
	}
	if limitUpBps > 0 {
		route.tbUp = NewTokenBucket(limitUpBps)
	} else {
		route.tbUp = nil
	}

	return nil
}

// GetPeerRateLimit returns the configured rate limits for a peer in bytes per second.
func (f *Forwarder) GetPeerRateLimit(peerKey string) (limitDownBps, limitUpBps int64, err error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	route, ok := f.routesByPeer[peerKey]
	if !ok {
		return 0, 0, ErrSessionNotRegistered
	}

	return route.limitDownBps, route.limitUpBps, nil
}

// ReconfigureClientQueueConfig changes the capacity used for subsequently
// registered client routes. A route-limit change is safe with live sessions
// when it accommodates them and the existing queue size fits the new budget.
// Resizing live channels still requires all sessions to disconnect first.
func (f *Forwarder) ReconfigureClientQueueConfig(size, maxActiveRoutes int) error {
	if err := ValidateClientRouteLimit(maxActiveRoutes); err != nil {
		return err
	}
	if maxActiveRoutes <= 0 {
		maxActiveRoutes = MaxSupportedActiveRoutes
	}
	maxQueue := MaxClientQueuePacketsForRoutes(maxActiveRoutes)
	if size <= 0 {
		size = DefaultClientQueueSize
	}
	if size > maxQueue {
		size = maxQueue
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.routesByPeer) > 0 && size != f.bufSize {
		return errors.New("client queue size cannot change while sessions are active")
	}
	if len(f.routesByPeer) > maxActiveRoutes {
		return errors.New("client route limit cannot be lower than the active route count")
	}
	f.bufSize = size
	f.maxActiveRoutes = maxActiveRoutes
	return nil
}

// ReconfigureClientQueueSize reconfigures the client queue size using the currently configured maximum active routes.
func (f *Forwarder) ReconfigureClientQueueSize(size int) error {
	f.mu.RLock()
	maxActiveRoutes := f.maxActiveRoutes
	f.mu.RUnlock()
	return f.ReconfigureClientQueueConfig(size, maxActiveRoutes)
}
