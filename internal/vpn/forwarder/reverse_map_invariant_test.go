package forwarder

import (
	"encoding/binary"
	"testing"
)

// innerClientPacket builds a minimal client→backend IPv4 packet whose inner
// source address is src — the attacker-claimable field that drives the
// legacy rebind self-heal in routeClientToBackend.
func innerClientPacket(src [4]byte) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[9] = 17 // UDP
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], []byte{10, 0, 0, 1}) // backend-facing destination, unused here
	return pkt
}

// TestHasSessionRouteWithReturnPathDetectsReverseMapDeletion reproduces the
// reviewed HIGH trigger chain (tasks/389-backend-return REVIEW_REQUEST_CHANGES_2.md):
//
//  1. a legacy peer squats the OFFLINE upstream peer's IP (existing rebind
//     self-heal — legal while the IP is unassigned),
//  2. the upstream peer connects and registers its rightful IP (the reverse
//     map points at the upstream route again; the memo check is healthy),
//  3. the legacy peer rebinds back to its original IP — its rebind path
//     deletes f.routesByIP[route.assignedIP] WITHOUT the cur == route guard,
//     removing the UPSTREAM route's reverse mapping (the unguarded legacy
//     deletion that predates #389),
//  4. HasSessionRouteWithReturnPath must report NOT-healthy so the router
//     recovers the session, instead of skipping recovery while every reply
//     fails "session route not registered".
//
// After step 3 the route, session, connection, assigned IP and returnPath
// themselves are intact — only the reverse mapping is gone. That is exactly
// the state the restored invariant (f.routesByIP[assignedIP] == r) detects;
// without it the check reported healthy and recovery was skipped.
//
// The "direct" subtest pins the same memo-check contract by removing the
// reverse entry directly, so the regression stays covered even if the rebind
// path is later hardened and the full chain can no longer reach this state.
//
// Both subtests loop (>=50 iterations each) so a race between the
// rebind-path writer and the memo check's reader surfaces under -race
// (parity with the reviewer's 10/10 race reproductions). The chain is fully
// synchronous — registration and rebind mutate state under f.mu, and no
// pumps are started — so no sleeps or polling are needed.
func TestHasSessionRouteWithReturnPathDetectsReverseMapDeletion(t *testing.T) {
	const (
		upstreamIP  = "10.100.0.7"
		legacyHome  = "10.100.0.8" // the legacy peer's own (original) IP
		legacySquat = "10.100.0.9" // squat target for the direct-delete variant
	)
	upstreamAddr := [4]byte{10, 100, 0, 7}
	homeAddr := [4]byte{10, 100, 0, 8}

	for _, tt := range []struct {
		name string
		// breakReverseMap drives the legacy peer's real rebind path (full
		// production chain) or deletes the reverse entry directly.
		breakReverseMap func(t *testing.T, f *Forwarder)
	}{
		{
			name: "legacy_rebind_chain",
			breakReverseMap: func(t *testing.T, f *Forwarder) {
				// Step 3: the legacy peer returns to its original IP.
				// Its route still claims the upstream IP as assignedIP,
				// so the rebind's unguarded delete removes the UPSTREAM
				// route's routesByIP entry.
				if err := f.RouteClientToBackend("peer-legacy", innerClientPacket(homeAddr)); err != nil {
					t.Fatalf("legacy rebind home failed: %v", err)
				}
			},
		},
		{
			name: "direct_reverse_map_delete",
			breakReverseMap: func(t *testing.T, f *Forwarder) {
				f.mu.Lock()
				delete(f.routesByIP, upstreamIP)
				f.mu.Unlock()
			},
		},
	} {
		for iteration := 0; iteration < 50; iteration++ {
			f := NewForwarder(nil, "10.100.0.0/16", 64)
			path := NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })

			// The legacy peer holds a live route on its own IP (path-less).
			if _, err := f.TryRegisterSessionWithReturnPath("sess-legacy", "conn-legacy", "peer-legacy", legacyHome, 2, 0, 0, nil); err != nil {
				t.Fatal(err)
			}

			// Step 1: the legacy peer squats the offline upstream IP via
			// the rebind self-heal (the claimed IP is inside the portal
			// subnet and currently unassigned, so the rebind is accepted).
			if err := f.RouteClientToBackend("peer-legacy", innerClientPacket(upstreamAddr)); err != nil {
				t.Fatalf("legacy squat rebind failed: %v", err)
			}
			f.mu.RLock()
			squatter := f.routesByIP[upstreamIP]
			f.mu.RUnlock()
			if squatter == nil || squatter.peerKey != "peer-legacy" {
				t.Fatalf("%s: squat setup failed: upstream IP not held by the legacy peer", tt.name)
			}

			// Step 2: the upstream peer registers its rightful IP with a
			// return path; the memo check must be healthy right now.
			if _, err := f.TryRegisterSessionWithReturnPath("sess-upstream", "conn-upstream", "peer-upstream", upstreamIP, 1, 0, 0, path); err != nil {
				t.Fatal(err)
			}
			if !f.HasSessionRouteWithReturnPath("peer-upstream", "sess-upstream", "conn-upstream", upstreamIP, 1, path) {
				t.Fatalf("%s: upstream route not healthy after registering its rightful IP", tt.name)
			}

			// Step 3: the legacy reverse-map deletion.
			tt.breakReverseMap(t, f)

			// Post-state guard: route/session/returnPath intact, reverse
			// mapping gone — the exact reviewed trigger state.
			f.mu.RLock()
			route := f.routesByPeer["peer-upstream"]
			_, mapped := f.routesByIP[upstreamIP]
			f.mu.RUnlock()
			if route == nil || route.stopped || route.returnPath != path || mapped {
				t.Fatalf("%s: unexpected post-deletion state (route=%v mapped=%v)", tt.name, route != nil, mapped)
			}

			// Step 4: the memo check must detect the broken reverse
			// mapping so the router recovers instead of skipping it.
			if f.HasSessionRouteWithReturnPath("peer-upstream", "sess-upstream", "conn-upstream", upstreamIP, 1, path) {
				t.Fatalf("%s (iteration %d): memo check reported healthy for a route whose reverse mapping was deleted", tt.name, iteration)
			}
			if f.HasSessionRoute("peer-upstream", "sess-upstream", "conn-upstream", upstreamIP, 1) {
				t.Fatalf("%s (iteration %d): legacy memo check disagreed with the return-path check", tt.name, iteration)
			}
		}
	}
}
