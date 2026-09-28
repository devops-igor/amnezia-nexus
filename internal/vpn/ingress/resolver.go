// Package ingress routes plaintext client packets produced by the upstream
// client-facing AWG device (clientawg.ClientAWGDevice.ReceiveOutbound) into
// Nexus backend sessions (issue #388). It provides two components:
//
//   - Resolver: the durable assigned-IP -> peer ownership map. Loaded at
//     startup from the same durable state the portal leases client IPs from
//     (user_connections.client_params["assigned_ip"], read through
//     database.DB.GetVPNClientIPAssignments) and kept current through an
//     explicit mutation API that issue #391's event-driven sync builds on.
//   - Router: safe IPv4 parsing plus the ownership checks that gate lazy
//     admission and forwarder route registration for every plaintext packet.
//     There is no forwarder self-heal on this path: a packet whose source IP
//     is not exactly the resolved peer's durable assignment is dropped and
//     counted, never rebound (issue #89's rebind exists only on the legacy
//     custom-listener path, which stays untouched until #393).
//
// Admission is injectable through the Admission interface. Production wiring
// adapts vpn.Service.HandleIncomingPeer, so the #86 capacity serialization and
// rekey-stable live-session reuse are reused verbatim rather than
// reimplemented. The components ship standalone in this session; listener
// wiring is #393.
//
// IP representation: assigned addresses are stored and compared as 4-byte
// netip.Addr values (netip.AddrFrom4; Is4() holds for every stored entry).
// String rendering for errors and counters uses netip's canonical dotted
// form, which matches the persisted lease text.
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

// LoadResolver builds a resolver from durable portal client leases using
// database.DB.GetVPNClientIPAssignments — the same accessor the vpn service's
// startup IP reservation uses, so it observes exactly the durable state
// client leases come from. That accessor already restricts rows to portal
// connections (server_id 0) whose normalized protocol is awg and whose
// client_id (the peer public key) is set; LoadResolver additionally skips
// rows without a parseable IPv4 assignment, mirroring the /32-only epic
// decision, and collapses exact duplicate rows for one connection (the
// accessor's LEFT JOIN can surface one lease twice when legacy session rows
// linger).
//
// Load fails closed on durable conflicts: two different peers owning one IP,
// or one peer owning two different IPs, abort the load with an error naming
// the conflicting address. Peer keys in errors are redacted.
func LoadResolver(ctx context.Context, db *database.DB) (*Resolver, error) {
	if db == nil {
		return nil, fmt.Errorf("ingress: nil configuration database")
	}
	assignments, err := db.GetVPNClientIPAssignments(ctx)
	if err != nil {
		return nil, fmt.Errorf("ingress: load client IP assignments: %w", err)
	}
	r := NewResolver()
	seen := make(map[string]bool, len(assignments)) // connectionID+"|"+IP -> duplicated row
	for _, a := range assignments {
		if a.AssignedIP == "" {
			continue
		}
		if seen[a.ConnectionID+"|"+a.AssignedIP] {
			continue
		}
		seen[a.ConnectionID+"|"+a.AssignedIP] = true
		ip, err := netip.ParseAddr(a.AssignedIP)
		if err != nil || !ip.Is4() || ip.Unmap() != ip {
			continue
		}
		if err := r.insert(PeerOwnership{
			PeerPublicKey: a.PeerKey,
			ConnectionID:  a.ConnectionID,
			UserID:        a.UserID,
			IP:            netip.AddrFrom4(ip.As4()),
		}); err != nil {
			return nil, err
		}
	}
	return r, nil
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

// Update registers or replaces one assigned IPv4's ownership, preserving the
// load-time invariants: one IP per peer, one peer per IP. Re-asserting a
// peer's exact current ownership is a no-op, so a #391 re-sync of an unchanged
// lease cannot fail. The assignment must be a 4-byte IPv4 address and carry a
// peer key; anything else is rejected. Error strings name the conflicting
// address and redact peer keys.
func (r *Resolver) Update(o PeerOwnership) error {
	if !o.IP.IsValid() || !o.IP.Is4() || o.IP.Unmap() != o.IP || o.IP == (netip.Addr{}) {
		return fmt.Errorf("ingress: assignment must be a nonzero 4-byte IPv4 address, got %v", o.IP)
	}
	if o.PeerPublicKey == "" {
		return fmt.Errorf("ingress: assignment for %s has no peer public key", o.IP)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if oldIP, ok := r.byPeer[o.PeerPublicKey]; ok && oldIP != o.IP {
		return fmt.Errorf("ingress: peer %s owns conflicting assigned IPs %s and %s", RedactKey(o.PeerPublicKey), oldIP, o.IP)
	}
	if old, ok := r.byIP[o.IP]; ok && old.PeerPublicKey != o.PeerPublicKey {
		return fmt.Errorf("ingress: assigned IP %s owned by conflicting peers %s and %s", o.IP, RedactKey(old.PeerPublicKey), RedactKey(o.PeerPublicKey))
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

// Reload atomically replaces the resolver contents from durable state using
// the same eligibility and conflict rules as LoadResolver. On success the
// backing maps are swapped in one step: concurrent lookups observe either the
// old or the new contents, never a mixture. On error the previous contents
// are left untouched.
func (r *Resolver) Reload(ctx context.Context, db *database.DB) error {
	fresh, err := LoadResolver(ctx, db)
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
