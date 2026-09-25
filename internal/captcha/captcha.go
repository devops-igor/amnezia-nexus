// Package captcha keeps slide challenges and verification tickets on the server.
// Only opaque identifiers are sent to the browser.
package captcha

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

const (
	DefaultTTL = 10 * time.Minute
	TicketTTL  = 2 * time.Minute
	Tolerance  = 4
	maxEntries = 10000
)

type entry struct {
	x, y        int
	challengeID string // non-empty for a verified ticket
	expires     time.Time
}

// Store is a bounded, mutex-protected, single-use challenge and ticket store.
// Both successful and unsuccessful checks consume the submitted identifier.
type Store struct {
	mu      sync.Mutex
	entries map[string]entry
	ttl     time.Duration
	now     func() time.Time
}

func NewStore() *Store { return NewStoreWithTTL(DefaultTTL) }

func NewStoreWithTTL(ttl time.Duration) *Store {
	return &Store{entries: make(map[string]entry), ttl: ttl, now: time.Now}
}

// NewID generates 128 bits of unpredictable entropy.
func NewID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// NewSlide stores the server-only target position.
func (s *Store) NewSlide(x, y int) (string, error) {
	id, err := NewID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.insertLocked(id, entry{x: x, y: y, expires: s.now().Add(s.ttl)})
	return id, nil
}

// VerifySlide consumes a challenge and returns a short-lived ticket when the
// supplied coordinates match. An incorrect attempt cannot be retried.
func (s *Store) VerifySlide(id string, x, y int) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok || e.challengeID != "" {
		return "", false, nil
	}
	delete(s.entries, id)
	if !s.now().Before(e.expires) || !within(x, e.x) || !within(y, e.y) {
		return "", false, nil
	}
	ticket, err := NewID()
	if err != nil {
		return "", false, err
	}
	s.insertLocked(ticket, entry{challengeID: id, expires: s.now().Add(TicketTTL)})
	return ticket, true, nil
}

// ConsumeTicket accepts only a ticket issued for the challenge in the signed
// session cookie. Deletion is atomic, so concurrent logins cannot replay it.
func (s *Store) ConsumeTicket(challengeID, ticket string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[ticket]
	if !ok || e.challengeID == "" {
		return false
	}
	delete(s.entries, ticket)
	return challengeID != "" && e.challengeID == challengeID && s.now().Before(e.expires)
}

// Check bounds without subtracting untrusted integers (which could overflow).
func within(got, want int) bool {
	return got >= want-Tolerance && got <= want+Tolerance
}

func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(false)
	return len(s.entries)
}

func (s *Store) insertLocked(id string, e entry) {
	if len(s.entries) >= maxEntries {
		s.sweepLocked(true)
	}
	s.entries[id] = e
}

func (s *Store) sweepLocked(force bool) {
	now := s.now()
	for id, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, id)
		}
	}
	if force && len(s.entries) >= maxEntries {
		type item struct {
			id      string
			expires time.Time
		}
		all := make([]item, 0, len(s.entries))
		for id, e := range s.entries {
			all = append(all, item{id: id, expires: e.expires})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].expires.Before(all[j].expires) })
		for _, e := range all[maxEntries/2:] {
			delete(s.entries, e.id)
		}
	}
}
