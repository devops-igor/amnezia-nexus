package forwarder

import (
	"encoding/binary"
	"errors"
	"testing"
)

// innerClientPacket builds a minimal client→backend IPv4 packet whose inner
// source address is src.
func innerClientPacket(src [4]byte) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[9] = 17 // UDP
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], []byte{10, 0, 0, 1}) // backend-facing destination, unused here
	return pkt
}

// TestHasSessionRouteWithReturnPathDetectsReverseMapDeletion tests that
// HasSessionRouteWithReturnPath and HasSessionRoute detect when the reverse
// mapping is deleted directly, ensuring recovery is triggered.
func TestHasSessionRouteWithReturnPathDetectsReverseMapDeletion(t *testing.T) {
	const upstreamIP = "10.100.0.7"

	for iteration := 0; iteration < 50; iteration++ {
		f := NewForwarder(nil, "10.100.0.0/16", 64)
		path := NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })

		// Step 1: the upstream peer registers its rightful IP with a
		// return path; the memo check must be healthy right now.
		if _, err := f.TryRegisterSessionWithReturnPath("sess-upstream", "conn-upstream", "peer-upstream", upstreamIP, 1, 0, 0, path); err != nil {
			t.Fatal(err)
		}
		if !f.HasSessionRouteWithReturnPath("peer-upstream", "sess-upstream", "conn-upstream", upstreamIP, 1, path) {
			t.Fatal("upstream route not healthy after registering its rightful IP")
		}

		// Step 2: delete the reverse mapping directly.
		f.mu.Lock()
		delete(f.routesByIP, upstreamIP)
		f.mu.Unlock()

		// Post-state guard: route/session/returnPath intact, reverse
		// mapping gone — the exact reviewed trigger state.
		f.mu.RLock()
		route := f.routesByPeer["peer-upstream"]
		_, mapped := f.routesByIP[upstreamIP]
		f.mu.RUnlock()
		if route == nil || route.stopped || route.returnPath != path || mapped {
			t.Fatalf("unexpected post-deletion state (route=%v mapped=%v)", route != nil, mapped)
		}

		// Step 3: the memo check must detect the broken reverse
		// mapping so the router recovers instead of skipping it.
		if f.HasSessionRouteWithReturnPath("peer-upstream", "sess-upstream", "conn-upstream", upstreamIP, 1, path) {
			t.Fatalf("iteration %d: memo check reported healthy for a route whose reverse mapping was deleted", iteration)
		}
		if f.HasSessionRoute("peer-upstream", "sess-upstream", "conn-upstream", upstreamIP, 1) {
			t.Fatalf("iteration %d: legacy memo check disagreed with the return-path check", iteration)
		}
	}
}

// TestSquatAttemptRejectedAndCannotCorruptReverseMap verifies that an unassigned IP
// cannot be squatted via packet-driven rebind, and that spoofed packets cannot corrupt
// the reverse map.
func TestSquatAttemptRejectedAndCannotCorruptReverseMap(t *testing.T) {
	const (
		upstreamIP = "10.100.0.7"
		legacyHome = "10.100.0.8"
	)
	upstreamAddr := [4]byte{10, 100, 0, 7}

	f := NewForwarder(nil, "10.100.0.0/16", 64)
	path := NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })

	// The legacy peer holds a live route on its own IP.
	if _, err := f.TryRegisterSessionWithReturnPath("sess-legacy", "conn-legacy", "peer-legacy", legacyHome, 2, 0, 0, nil); err != nil {
		t.Fatal(err)
	}

	// Step 1: the legacy peer attempts to squat the offline upstream IP.
	// With dynamic rebind removed, this must be rejected with ErrSpoofedSourceIP.
	err := f.RouteClientToBackend("peer-legacy", innerClientPacket(upstreamAddr))
	if !errors.Is(err, ErrSpoofedSourceIP) {
		t.Fatalf("expected ErrSpoofedSourceIP on squat attempt, got: %v", err)
	}

	f.mu.RLock()
	squatter := f.routesByIP[upstreamIP]
	f.mu.RUnlock()
	if squatter != nil {
		t.Fatal("upstream IP was squatted despite spoofed source IP")
	}

	// Step 2: upstream peer registers its IP with return path.
	if _, err := f.TryRegisterSessionWithReturnPath("sess-upstream", "conn-upstream", "peer-upstream", upstreamIP, 1, 0, 0, path); err != nil {
		t.Fatal(err)
	}
	if !f.HasSessionRouteWithReturnPath("peer-upstream", "sess-upstream", "conn-upstream", upstreamIP, 1, path) {
		t.Fatal("upstream route not healthy after registration")
	}

	// Step 3: legacy peer attempts again to spoof upstream IP.
	err = f.RouteClientToBackend("peer-legacy", innerClientPacket(upstreamAddr))
	if !errors.Is(err, ErrSpoofedSourceIP) {
		t.Fatalf("expected ErrSpoofedSourceIP on second squat attempt, got: %v", err)
	}

	// Step 4: upstream route remains completely healthy in reverse map.
	if !f.HasSessionRouteWithReturnPath("peer-upstream", "sess-upstream", "conn-upstream", upstreamIP, 1, path) {
		t.Fatal("upstream route corrupted after failed squat attempt")
	}
}
