// Package captcha provides a server-side, in-memory TTL store for CAPTCHA
// challenges (issue #84). The client cookie only ever receives an opaque
// captcha_id; the answer, expiry and attempt bookkeeping never leave the
// server.
package captcha

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultTTL is how long a captcha challenge remains valid.
	DefaultTTL = 10 * time.Minute
	// MaxAttempts caps wrong-answer verifications before the id is invalidated.
	MaxAttempts = 5
	// maxEntries bounds memory: expired entries are swept lazily and
	// aggressively once this many live entries exist.
	maxEntries = 10000
)

// entry is a single stored challenge.
type entry struct {
	answer   string
	expires  time.Time
	attempts int
}

// Store is a mutex-protected in-memory captcha store. One-time-use: a verify
// attempt (correct or wrong beyond MaxAttempts) consumes the entry. Expired
// entries are removed lazily on access and during a full sweep triggered when
// the map grows beyond maxEntries.
type Store struct {
	mu      sync.Mutex
	entries map[string]entry
	ttl     time.Duration
	now     func() time.Time
}

// NewStore returns a store with the default TTL.
func NewStore() *Store {
	return NewStoreWithTTL(DefaultTTL)
}

// NewStoreWithTTL returns a store with a custom TTL (for tests).
func NewStoreWithTTL(ttl time.Duration) *Store {
	return &Store{
		entries: make(map[string]entry),
		ttl:     ttl,
		now:     time.Now,
	}
}

// NewID generates a fresh opaque captcha id.
func NewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Create stores a new challenge and returns its opaque id.
func (s *Store) New(answer string) (string, error) {
	id, err := NewID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= maxEntries {
		s.sweepLocked(true)
	}
	s.entries[id] = entry{
		answer:   answer,
		expires:  s.now().Add(s.ttl),
		attempts: 0,
	}
	return id, nil
}

// Verify checks the submitted answer against the stored challenge. The entry
// is consumed on the first verification attempt (one-time-use), so a wrong
// answer forces the user to request a fresh captcha. It returns false for
// unknown, expired or already-consumed ids.
func (s *Store) Verify(id, answer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[id]
	if !ok {
		return false
	}
	delete(s.entries, id) // one-time-use: consume before comparing
	if s.now().After(e.expires) {
		return false
	}
	if e.attempts >= MaxAttempts {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(answer), e.answer)
}

// Len returns the number of live (non-expired) entries, sweeping expired ones.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(false)
	return len(s.entries)
}

// sweepLocked removes expired entries. When force is set (memory pressure),
// it also evicts the oldest entries down to 3/4 of maxEntries regardless of
// expiry.
func (s *Store) sweepLocked(force bool) {
	now := s.now()
	for id, e := range s.entries {
		if now.After(e.expires) {
			delete(s.entries, id)
		}
	}
	if force && len(s.entries) >= maxEntries {
		// Deterministic under lock: drop entries with the earliest expiry.
		type kv struct {
			id      string
			expires time.Time
		}
		all := make([]kv, 0, len(s.entries))
		for id, e := range s.entries {
			all = append(all, kv{id, e.expires})
		}
		for i := 0; i < len(all)-1; i++ {
			for j := i + 1; j < len(all); j++ {
				if all[j].expires.Before(all[i].expires) {
					all[i], all[j] = all[j], all[i]
				}
			}
		}
		keep := maxEntries / 2
		for _, e := range all[keep:] {
			delete(s.entries, e.id)
		}
	}
}
