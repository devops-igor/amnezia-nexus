package ingress

import (
	"sync"
	"sync/atomic"
	"time"
)

// TouchSessionThrottleSeconds is the minimum interval in seconds between
// liveness refreshes for one peer. It mirrors the custom listener's
// touchSessionThrottleSeconds (issue #294) so the ingress path costs the
// SessionManager no more mutex contention than the transport path: under
// sustained traffic at most one refresh per peer per window reaches the
// SessionManager, and the packet hot path pays one atomic load.
const TouchSessionThrottleSeconds = 2

// SessionLiveness adapts the SessionManager's TouchSession to the ingress
// Liveness seam (issue #388): accepted plaintext refreshes the backend
// routing session's in-memory LastSeen so active sessions survive the idle
// reaper. Refreshes are throttled per peer with the same CAS-on-unix-seconds
// pattern the listener's touchPeerSession uses (issue #294); 100 rapid
// packets within one window collapse to at most a few SessionManager calls.
//
// A peer's throttle state lives in a small map of *atomic.Int64 guarded by
// mu (the map is touched only when a peer's throttle entry is created or
// removed; the per-packet fast path is a pure atomic load/CAS on the entry)
// and is deleted by Forget when the session goes away, so the map never
// grows with dead peers. A SessionLiveness is safe for concurrent use.
type SessionLiveness struct {
	touch func(peerPublicKey string)

	mu     sync.Mutex
	lastNs map[string]*atomic.Int64 // peer -> unix nanos of last refresh
}

// NewSessionLiveness adapts touch (production: SessionManager.TouchSession).
// A nil touch is a programming error and panics.
func NewSessionLiveness(touch func(peerPublicKey string)) *SessionLiveness {
	if touch == nil {
		panic("ingress: NewSessionLiveness requires a touch function")
	}
	return &SessionLiveness{touch: touch, lastNs: make(map[string]*atomic.Int64)}
}

// Touch refreshes the peer's liveness unconditionally. Prefer TouchThrottled
// on the data path; this entry point exists for callers that already
// throttle or for tests.
func (l *SessionLiveness) Touch(peerPublicKey string) {
	l.touch(peerPublicKey)
}

// TouchThrottled refreshes the peer's liveness at most once per
// TouchSessionThrottleSeconds. CAS-on-unix-nanos: the winner of the window
// calls the SessionManager, everyone else returns after one atomic load —
// no mutex on the per-packet path for known peers.
func (l *SessionLiveness) TouchThrottled(peerPublicKey string) {
	now := time.Now().UnixNano()
	window := int64(TouchSessionThrottleSeconds) * int64(time.Second)

	l.mu.Lock()
	last, ok := l.lastNs[peerPublicKey]
	if !ok {
		last = &atomic.Int64{}
		l.lastNs[peerPublicKey] = last
	}
	l.mu.Unlock()

	prev := last.Load()
	if (now-prev >= window || now < prev) && last.CompareAndSwap(prev, now) {
		l.touch(peerPublicKey)
	}
}

// Forget drops one peer's throttle state (call when its session closes) so
// the map does not retain dead peers.
func (l *SessionLiveness) Forget(peerPublicKey string) {
	l.mu.Lock()
	delete(l.lastNs, peerPublicKey)
	l.mu.Unlock()
}
