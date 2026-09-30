package ingress

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/devops-igor/amnezia-nexus/internal/database"
)

// PeerOwnership is the durable ownership record for one assigned client IPv4.
type PeerOwnership struct {
	PeerPublicKey string
	ConnectionID  string
	UserID        string
	IP            netip.Addr // always 4-byte IPv4 (AddrFrom4), no zone
}

// Resolver is the in-memory assigned-IP -> ownership map built from durable
// state. Lookups take an RLock and are safe for concurrent use on the packet
// hot path; Update, Remove, and Reload serialize under the write lock. The
// zero value is not usable: construct with NewResolver or LoadResolver.
type Resolver struct {
	mu     sync.RWMutex
	byIP   map[netip.Addr]PeerOwnership
	byPeer map[string]netip.Addr
}

// NewResolver returns an empty resolver.
func NewResolver() *Resolver {
	return &Resolver{
		byIP:   make(map[netip.Addr]PeerOwnership),
		byPeer: make(map[string]netip.Addr),
	}
}

// LoadStats reports what one durable-state load observed. The skip counters
// exist so silent filtering stays observable: rows the loader refuses to
// treat as ownership are counted, never dropped unnoticed.
type LoadStats struct {
	// Loaded is the number of ownership entries installed.
	Loaded int `json:"loaded"`
	// SkippedNeedsMigration counts session-only legacy leases
	// (NeedsMigration=true: the IP exists only in vpn_sessions before
	// restart cleanup migrates it into client_params). Stale runtime
	// residue must never authorize a source IP, so these rows are skipped
	// and counted, never inserted. The legacy fallback itself stays with
	// startup reconciliation (reservePersistedClientIPs), which is not a
	// data-path authority.
	SkippedNeedsMigration int `json:"skipped_needs_migration"`
	// SkippedWithoutDurableIP counts portal rows with no assigned_ip at
	// all. Defensive: today's accessor filters empty-IP rows at the source
	// (readVPNClientIPAssignments appends only rows with a non-empty
	// AssignedIP), so this stays zero unless that guarantee changes.
	SkippedWithoutDurableIP int `json:"skipped_without_durable_ip"`
	// SkippedUnparseableIP counts rows whose assigned_ip is not a usable
	// 4-byte IPv4 address (corrupt or non-conforming durable data).
	SkippedUnparseableIP int `json:"skipped_unparseable_ip"`
}

// LoadResolver builds a resolver from durable portal client leases using
// database.DB.GetVPNClientIPAssignments — the same accessor the vpn service's
// startup IP reservation uses, so it observes exactly the durable state
// client leases come from. That accessor already restricts rows to portal
// connections (server_id 0) whose normalized protocol is awg and whose
// client_id (the peer public key) is set, and flags session-only legacy
// leases with NeedsMigration=true; LoadResolver is durable-only — it skips
// and counts those legacy rows plus rows without a durable assigned_ip,
// mirroring the /32-only epic decision, and collapses exact duplicate rows
// for one connection (the accessor's LEFT JOIN can surface one lease twice
// when legacy session rows linger).
//
// Load fails closed on durable conflicts: two different peers owning one IP,
// or one peer owning two different IPs, abort the load with an error naming
// the conflicting address. Peer keys in errors are redacted.
func LoadResolver(ctx context.Context, db *database.DB) (*Resolver, *LoadStats, error) {
	if db == nil {
		return nil, nil, fmt.Errorf("ingress: nil configuration database")
	}
	assignments, err := db.GetVPNClientIPAssignments(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("ingress: load client IP assignments: %w", err)
	}
	r := NewResolver()
	stats := &LoadStats{}
	seen := make(map[string]bool, len(assignments)) // connectionID+"|"+IP -> duplicated row
	for _, a := range assignments {
		if a.NeedsMigration {
			// Session-only legacy lease: runtime residue, not durable
			// ownership. Never authorize a source IP from it (#388).
			stats.SkippedNeedsMigration++
			continue
		}
		if a.AssignedIP == "" {
			stats.SkippedWithoutDurableIP++
			continue
		}
		if seen[a.ConnectionID+"|"+a.AssignedIP] {
			continue
		}
		seen[a.ConnectionID+"|"+a.AssignedIP] = true
		ip, err := netip.ParseAddr(a.AssignedIP)
		if err != nil || !ip.Is4() || ip.Unmap() != ip {
			stats.SkippedUnparseableIP++
			continue
		}
		if err := r.insert(PeerOwnership{
			PeerPublicKey: a.PeerKey,
			ConnectionID:  a.ConnectionID,
			UserID:        a.UserID,
			IP:            netip.AddrFrom4(ip.As4()),
		}); err != nil {
			return nil, nil, err
		}
		stats.Loaded++
	}
	return r, stats, nil
}

// RedactKey renders a peer public key safe for error text and counters: the
// first 8 characters plus an ellipsis, or full masking for shorter values.
func RedactKey(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:8] + "…"
}

// insert adds one ownership entry, failing closed on conflicts. Caller holds
// no locks; used by LoadResolver on a fresh resolver only.
func (r *Resolver) insert(o PeerOwnership) error {
	if old, ok := r.byIP[o.IP]; ok {
		return fmt.Errorf("ingress: assigned IP %s owned by conflicting peers %s and %s", o.IP, RedactKey(old.PeerPublicKey), RedactKey(o.PeerPublicKey))
	}
	if old, ok := r.byPeer[o.PeerPublicKey]; ok {
		return fmt.Errorf("ingress: peer %s owns conflicting assigned IPs %s and %s", RedactKey(o.PeerPublicKey), old, o.IP)
	}
	r.byIP[o.IP] = o
	r.byPeer[o.PeerPublicKey] = o.IP
	return nil
}

// Lookup returns the durable owner of an assigned IPv4. Non-IPv4 (or invalid)
// addresses yield a miss. Lock-cheap (RLock) — safe on the packet hot path.
func (r *Resolver) Lookup(ip netip.Addr) (PeerOwnership, bool) {
	if !ip.IsValid() || !ip.Is4() {
		return PeerOwnership{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	o, ok := r.byIP[ip]
	return o, ok
}

// LookupByPeer returns the durable assignment of a peer public key.
func (r *Resolver) LookupByPeer(peerPublicKey string) (netip.Addr, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ip, ok := r.byPeer[peerPublicKey]
	return ip, ok
}

// Len returns the number of tracked assignments.
func (r *Resolver) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byIP)
}

// Update registers one assigned IPv4's ownership with replacement
// semantics: a peer whose durable lease moves to a different IP has its
// old mapping swapped atomically (the previous IP becomes unmapped, the
// new one maps to the peer), while concurrent lookups observe old-or-new,
// never a mixture. The load-time invariants still hold after the swap —
// one IP per peer, one peer per IP. Re-asserting a peer's exact current
// ownership is a no-op, so a #391 re-sync of an unchanged lease cannot
// fail. Updating an IP durably owned by a *different* peer remains a
// fail-closed conflict: replacement is scoped to a peer's own lease, it
// never repossesses someone else's address. The assignment must be a
// 4-byte IPv4 address and carry a peer key; anything else is rejected.
// Error strings name the conflicting address and redact peer keys.
func (r *Resolver) Update(o PeerOwnership) error {
	if !o.IP.IsValid() || !o.IP.Is4() || o.IP.Unmap() != o.IP || o.IP == (netip.Addr{}) {
		return fmt.Errorf("ingress: assignment must be a nonzero 4-byte IPv4 address, got %v", o.IP)
	}
	if o.PeerPublicKey == "" {
		return fmt.Errorf("ingress: assignment for %s has no peer public key", o.IP)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.byIP[o.IP]; ok && old.PeerPublicKey != o.PeerPublicKey {
		return fmt.Errorf("ingress: assigned IP %s owned by conflicting peers %s and %s", o.IP, RedactKey(old.PeerPublicKey), RedactKey(o.PeerPublicKey))
	}
	if oldIP, ok := r.byPeer[o.PeerPublicKey]; ok && oldIP != o.IP {
		// Replacement: the peer's lease moved. Drop the stale IP mapping
		// inside the same critical section so no concurrent Lookup can
		// observe the old IP still pointing at this peer after the new
		// one is installed (and vice versa).
		if cur, tracked := r.byIP[oldIP]; tracked && cur.PeerPublicKey == o.PeerPublicKey {
			delete(r.byIP, oldIP)
		}
	}
	r.byIP[o.IP] = o
	r.byPeer[o.PeerPublicKey] = o.IP
	return nil
}

// Remove drops one peer's assignment and reports the removed address when the
// peer was tracked. Removing an unknown peer is a no-op.
func (r *Resolver) Remove(peerPublicKey string) (netip.Addr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ip, ok := r.byPeer[peerPublicKey]
	if !ok {
		return netip.Addr{}, false
	}
	if o, tracked := r.byIP[ip]; tracked && o.PeerPublicKey == peerPublicKey {
		delete(r.byIP, ip)
	}
	delete(r.byPeer, peerPublicKey)
	return ip, true
}

// FilterIPs reports the ownership entries currently installed for the given
// addresses, in the same order as the input, skipping addresses with no
// tracked owner. Read-only snapshot for targeted withdrawal during fail-closed
// identity transitions: a caller removes the reported owners by key when the
// address must become unauthorized. Concurrent Replace or Update can swap the
// entries afterwards, so callers treat the result as a snapshot, not a lease.
func (r *Resolver) FilterIPs(ips []netip.Addr) []PeerOwnership {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PeerOwnership, 0, len(ips))
	for _, ip := range ips {
		if o, ok := r.byIP[ip]; ok {
			out = append(out, o)
		}
	}
	return out
}

// Reload atomically replaces the resolver contents from durable state using
// the same durable-only eligibility and conflict rules as LoadResolver. On
// success the backing maps are swapped in one step: concurrent lookups
// observe either the old or the new contents, never a mixture. On error the
// previous contents are left untouched.
func (r *Resolver) Reload(ctx context.Context, db *database.DB) error {
	fresh, _, err := LoadResolver(ctx, db)
	if err != nil {
		return err
	}
	fresh.mu.RLock()
	byIP, byPeer := fresh.byIP, fresh.byPeer
	fresh.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.byIP, r.byPeer = byIP, byPeer
	return nil
}

// Replace installs one validated desired ownership snapshot atomically. It is
// used with the exact durable peer set given to the upstream device, so a
// revoked peer cannot keep a stale plaintext route while removal is retried.
func (r *Resolver) Replace(owners []PeerOwnership) error {
	fresh := NewResolver()
	for _, owner := range owners {
		if !owner.IP.IsValid() || !owner.IP.Is4() || owner.PeerPublicKey == "" {
			return fmt.Errorf("ingress: invalid desired peer ownership")
		}
		if err := fresh.insert(owner); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.byIP, r.byPeer = fresh.byIP, fresh.byPeer
	r.mu.Unlock()
	return nil
}
