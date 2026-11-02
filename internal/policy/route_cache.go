package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Decision represents the routing decision for a destination IP.
type Decision uint8

const (
	// Unknown is the zero value and safe fallback.
	Unknown Decision = 0
	// Direct routes traffic directly to the WAN.
	Direct Decision = 1
	// Proxy routes traffic through the configured proxy egress.
	Proxy Decision = 2
)

// String returns the human-readable name of the Decision.
func (d Decision) String() string {
	switch d {
	case Direct:
		return "DIRECT"
	case Proxy:
		return "PROXY"
	default:
		return "UNKNOWN"
	}
}

// Scope identifies an authenticated client session and its ownership epoch.
type Scope struct {
	SessionID      string
	OwnershipEpoch uint64
}

// Observation represents a route decision for an IPv4 address with an expiration deadline.
type Observation struct {
	IP        netip.Addr
	Decision  Decision
	ExpiresAt time.Time
}

// CacheConfig controls capacity and TTL bounds for RouteCache.
type CacheConfig struct {
	MaxSessions          int
	MaxEntriesPerSession int
	MaxEntriesTotal      int
	MaxTTL               time.Duration
}

const (
	defaultMaxSessions          = 128
	defaultMaxEntriesPerSession = 1024
	defaultMaxEntriesTotal      = 65536
	defaultMaxTTL               = 3600 * time.Second

	hardMaxSessions          = 65536
	hardMaxEntriesPerSession = 65536
	hardMaxEntriesTotal      = 1048576
	hardMaxTTL               = 24 * time.Hour
)

var (
	// ErrInvalidScope indicates an invalid or empty Scope.
	ErrInvalidScope = errors.New("invalid session scope")
	// ErrMaxSessionsReached indicates the cache cannot admit more sessions.
	ErrMaxSessionsReached = errors.New("max sessions reached")
	// ErrSessionRetired indicates the session cache is retired and cannot accept observations.
	ErrSessionRetired = errors.New("session is retired")
	// ErrGenerationMismatch indicates the observation was compiled against a stale policy generation.
	ErrGenerationMismatch = errors.New("policy generation mismatch")
	// ErrInvalidGeneration indicates an empty or invalid policy generation string.
	ErrInvalidGeneration = errors.New("invalid policy generation")
	// ErrInvalidObservation indicates an invalid observation (non-IPv4, non-public, or bad TTL).
	ErrInvalidObservation = errors.New("invalid observation")
	// ErrCapacityExceeded indicates capacity overflow triggering session quarantine.
	ErrCapacityExceeded = errors.New("session capacity exceeded; quarantined")
)

type routeEntry struct {
	decision  Decision
	expiresAt time.Time
}

type routeView struct {
	entries          map[[4]byte]routeEntry
	policyGeneration string
	unknownUntil     time.Time
	retired          bool
}

// SessionCache manages route decisions scoped to an authenticated client session.
type SessionCache struct {
	cache *RouteCache
	scope Scope
	view  atomic.Pointer[routeView]
}

// RouteCache manages route evidence across client sessions with atomic views and bounded capacity.
type RouteCache struct {
	mu               sync.Mutex
	cfg              CacheConfig
	policyGeneration string
	sessions         map[Scope]*SessionCache
	totalEntries     int
}

// NewRouteCache constructs a new RouteCache with the specified configuration.
func NewRouteCache(cfg CacheConfig) (*RouteCache, error) {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = defaultMaxSessions
	}
	if cfg.MaxEntriesPerSession <= 0 {
		cfg.MaxEntriesPerSession = defaultMaxEntriesPerSession
	}
	if cfg.MaxEntriesTotal <= 0 {
		cfg.MaxEntriesTotal = defaultMaxEntriesTotal
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = defaultMaxTTL
	}

	if cfg.MaxSessions > hardMaxSessions ||
		cfg.MaxEntriesPerSession > hardMaxEntriesPerSession ||
		cfg.MaxEntriesTotal > hardMaxEntriesTotal ||
		cfg.MaxTTL > hardMaxTTL {
		return nil, errors.New("cache config limits exceed hard maximums")
	}

	return &RouteCache{
		cfg:      cfg,
		sessions: make(map[Scope]*SessionCache),
	}, nil
}

// SetPolicyGeneration updates the active policy generation string.
// Synchronously resets existing session views so stale generation lookups return UNKNOWN.
func (c *RouteCache) SetPolicyGeneration(generation string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if generation == c.policyGeneration {
		return
	}
	c.policyGeneration = generation

	for _, s := range c.sessions {
		oldV := s.view.Load()
		if oldV == nil || oldV.retired {
			continue
		}
		newV := &routeView{
			entries:          make(map[[4]byte]routeEntry),
			policyGeneration: generation,
			unknownUntil:     oldV.unknownUntil,
			retired:          false,
		}
		s.view.Store(newV)
	}
	c.totalEntries = 0
}

// Open retrieves an existing SessionCache or creates a new one for scope.
func (c *RouteCache) Open(scope Scope) (*SessionCache, error) {
	if scope.SessionID == "" {
		return nil, ErrInvalidScope
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if s, ok := c.sessions[scope]; ok {
		return s, nil
	}
	if len(c.sessions) >= c.cfg.MaxSessions {
		return nil, ErrMaxSessionsReached
	}

	s := &SessionCache{
		cache: c,
		scope: scope,
	}
	initView := &routeView{
		entries:          make(map[[4]byte]routeEntry),
		policyGeneration: c.policyGeneration,
		retired:          false,
	}
	s.view.Store(initView)
	c.sessions[scope] = s
	return s, nil
}

// Lookup queries the route decision for destination IPv4 under the active policy generation.
// Reader path is zero-mutex contention: single atomic view load, generation, quarantine, and expiry checks.
func (s *SessionCache) Lookup(ip netip.Addr, policyGeneration string, now time.Time) Decision {
	v := s.view.Load()
	if v == nil || v.retired {
		return Unknown
	}
	if v.policyGeneration == "" || v.policyGeneration != policyGeneration {
		return Unknown
	}
	if !v.unknownUntil.IsZero() && now.Before(v.unknownUntil) {
		return Unknown
	}
	if !ip.IsValid() || !ip.Is4() {
		return Unknown
	}
	entry, ok := v.entries[ip.As4()]
	if !ok {
		return Unknown
	}
	if !now.Before(entry.expiresAt) {
		return Unknown
	}
	return entry.decision
}

// Observe records a validated batch of route observations for this session.
// Validates IP addresses (native public IPv4 only), deadlines, and policy generation.
// Implements PROXY-wins conflict resolution and capacity overflow quarantine.
func (s *SessionCache) Observe(policyGeneration string, batch []Observation, now time.Time) error {
	if policyGeneration == "" {
		return ErrInvalidGeneration
	}
	if len(batch) == 0 {
		return nil
	}

	maxDeadline := now.Add(s.cache.cfg.MaxTTL)
	for _, obs := range batch {
		if obs.Decision != Direct && obs.Decision != Proxy {
			return fmt.Errorf("%w: decision must be Direct or Proxy", ErrInvalidObservation)
		}
		if !obs.IP.IsValid() || !obs.IP.Is4() {
			return fmt.Errorf("%w: IP must be valid IPv4", ErrInvalidObservation)
		}
		if err := ValidateFetchIP(obs.IP); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidObservation, err)
		}
		if !obs.ExpiresAt.After(now) {
			return fmt.Errorf("%w: expired deadline", ErrInvalidObservation)
		}
		if obs.ExpiresAt.After(maxDeadline) {
			return fmt.Errorf("%w: deadline exceeds MaxTTL", ErrInvalidObservation)
		}
	}

	// Fold duplicate IPs within the batch with PROXY precedence.
	folded := make(map[[4]byte]Observation, len(batch))
	for _, obs := range batch {
		k := obs.IP.As4()
		existing, ok := folded[k]
		if !ok {
			folded[k] = obs
			continue
		}
		if existing.Decision == Direct && obs.Decision == Proxy {
			folded[k] = obs
		} else if existing.Decision == Proxy && obs.Decision == Direct {
			continue // Keep existing PROXY and its deadline.
		} else if existing.Decision == Direct && obs.Decision == Direct {
			if obs.ExpiresAt.After(existing.ExpiresAt) {
				folded[k] = obs
			}
		} else if existing.Decision == Proxy && obs.Decision == Proxy {
			if obs.ExpiresAt.After(existing.ExpiresAt) {
				folded[k] = obs
			}
		}
	}

	c := s.cache
	c.mu.Lock()
	defer c.mu.Unlock()

	currentView := s.view.Load()
	if currentView == nil || currentView.retired {
		return ErrSessionRetired
	}
	if policyGeneration != c.policyGeneration || c.policyGeneration != currentView.policyGeneration {
		return ErrGenerationMismatch
	}

	// If currently quarantined, suppress DIRECT and extend quarantine with incoming PROXY observations.
	if !currentView.unknownUntil.IsZero() && now.Before(currentView.unknownUntil) {
		newUnknownUntil := currentView.unknownUntil
		for _, obs := range folded {
			if obs.Decision == Proxy && obs.ExpiresAt.After(newUnknownUntil) {
				newUnknownUntil = obs.ExpiresAt
			}
		}
		if newUnknownUntil != currentView.unknownUntil {
			s.view.Store(&routeView{
				entries:          make(map[[4]byte]routeEntry),
				policyGeneration: c.policyGeneration,
				unknownUntil:     newUnknownUntil,
				retired:          false,
			})
		}
		return ErrCapacityExceeded
	}

	// Clone and prune expired entries from current view.
	newEntries := make(map[[4]byte]routeEntry, len(currentView.entries)+len(folded))
	for k, entry := range currentView.entries {
		if now.Before(entry.expiresAt) {
			newEntries[k] = entry
		}
	}

	// Apply conflict resolution: PROXY wins.
	hasIncomingProxy := false
	for k, obs := range folded {
		if obs.Decision == Proxy {
			hasIncomingProxy = true
		}
		existing, exists := newEntries[k]
		if !exists {
			newEntries[k] = routeEntry{decision: obs.Decision, expiresAt: obs.ExpiresAt}
			continue
		}
		if existing.decision == Direct && obs.Decision == Direct {
			newEntries[k] = routeEntry{
				decision:  Direct,
				expiresAt: maxTime(existing.expiresAt, obs.ExpiresAt),
			}
		} else if existing.decision == Direct && obs.Decision == Proxy {
			// PROXY discards old DIRECT evidence.
			newEntries[k] = routeEntry{
				decision:  Proxy,
				expiresAt: obs.ExpiresAt,
			}
		} else if existing.decision == Proxy && obs.Decision == Direct {
			// Keep existing PROXY and its deadline; ignore DIRECT.
		} else if existing.decision == Proxy && obs.Decision == Proxy {
			newEntries[k] = routeEntry{
				decision:  Proxy,
				expiresAt: maxTime(existing.expiresAt, obs.ExpiresAt),
			}
		}
	}

	// Check capacity bounds.
	directEvictionNeeded := 0
	sessionExcess := len(newEntries) - c.cfg.MaxEntriesPerSession
	if sessionExcess > 0 {
		directEvictionNeeded = sessionExcess
	}
	entriesDelta := len(newEntries) - len(currentView.entries)
	totalExcess := (c.totalEntries + entriesDelta) - c.cfg.MaxEntriesTotal
	if totalExcess > directEvictionNeeded {
		directEvictionNeeded = totalExcess
	}

	// If capacity exceeded, attempt to prune DIRECT entries to make room.
	if directEvictionNeeded > 0 {
		evictedDirect := 0
		for k, entry := range newEntries {
			if entry.decision == Direct {
				delete(newEntries, k)
				evictedDirect++
				if evictedDirect >= directEvictionNeeded {
					break
				}
			}
		}

		// Recheck if it now fits without evicting any PROXY.
		recheckEntriesDelta := len(newEntries) - len(currentView.entries)
		if len(newEntries) > c.cfg.MaxEntriesPerSession ||
			(c.totalEntries+recheckEntriesDelta) > c.cfg.MaxEntriesTotal ||
			(hasIncomingProxy && evictedDirect < directEvictionNeeded) {
			// Cannot represent all PROXY observations safely -> Quarantine session!
			unknownUntil := currentView.unknownUntil
			for _, entry := range currentView.entries {
				if entry.expiresAt.After(unknownUntil) {
					unknownUntil = entry.expiresAt
				}
			}
			for _, obs := range folded {
				if obs.ExpiresAt.After(unknownUntil) {
					unknownUntil = obs.ExpiresAt
				}
			}
			s.view.Store(&routeView{
				entries:          make(map[[4]byte]routeEntry),
				policyGeneration: c.policyGeneration,
				unknownUntil:     unknownUntil,
				retired:          false,
			})
			c.totalEntries -= len(currentView.entries)
			return ErrCapacityExceeded
		}
	}

	// Publish new view atomically.
	s.view.Store(&routeView{
		entries:          newEntries,
		policyGeneration: c.policyGeneration,
		unknownUntil:     time.Time{},
		retired:          false,
	})
	c.totalEntries += len(newEntries) - len(currentView.entries)
	return nil
}

// Invalidate permanently retires this session cache, publishing an empty retired view.
// Synchronous, memory-only, and idempotent.
func (s *SessionCache) Invalidate() {
	c := s.cache
	c.mu.Lock()
	defer c.mu.Unlock()

	oldV := s.view.Load()
	if oldV != nil && oldV.retired {
		return
	}

	s.view.Store(&routeView{
		entries: make(map[[4]byte]routeEntry),
		retired: true,
	})

	if oldV != nil {
		c.totalEntries -= len(oldV.entries)
	}
	delete(c.sessions, s.scope)
}

// Sweep prunes expired entries from active sessions and cleans up expired quarantine deadlines.
func (c *RouteCache) Sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for scope, s := range c.sessions {
		v := s.view.Load()
		if v == nil || v.retired {
			delete(c.sessions, scope)
			continue
		}

		clearedQuarantine := false
		unknownUntil := v.unknownUntil
		if !unknownUntil.IsZero() && !now.Before(unknownUntil) {
			unknownUntil = time.Time{}
			clearedQuarantine = true
		}

		var newEntries map[[4]byte]routeEntry
		pruned := 0
		for k, e := range v.entries {
			if !now.Before(e.expiresAt) {
				pruned++
				if newEntries == nil {
					newEntries = make(map[[4]byte]routeEntry, len(v.entries)-1)
					for k2, e2 := range v.entries {
						if k2 != k && now.Before(e2.expiresAt) {
							newEntries[k2] = e2
						}
					}
				}
			}
		}

		if pruned > 0 || clearedQuarantine {
			if newEntries == nil {
				newEntries = v.entries
			}
			c.totalEntries -= pruned
			s.view.Store(&routeView{
				entries:          newEntries,
				policyGeneration: v.policyGeneration,
				unknownUntil:     unknownUntil,
				retired:          false,
			})
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
