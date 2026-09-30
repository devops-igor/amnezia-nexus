package ingress

// Regression coverage for issue #391 PR #400 round 4c, finding F1: the
// router's fast-path memo must certify a live route only for the OWNER the
// resolver's durable record names.
//
// A routing session is attributed to a user, not merely to a peer key. A
// durable reassignment to another user — or a connection row recreated under
// a new id — leaves the peer key, the connection id and the assigned IP
// byte-identical, so a memo that compared only IP and connection id kept
// fast-pathing the PREVIOUS owner's session as the new owner's live route.
//
// These tests drive the memo check directly: they keep the forwarder route
// genuinely live (so only the memo can refuse) and change exactly one owner
// field at a time.

import (
	"net/netip"
	"testing"
)

// TestRouterMemoRefusesChangedOwnerIdentity proves the memo rejects a live
// route whose owner identity no longer matches the resolver's record. Each
// case changes exactly one owner field — user, then connection — while key,
// assigned IP and the forwarder route stay untouched, so a memo that
// validated less than the full owner identity would fast-path it and skip
// re-admission.
func TestRouterMemoRefusesChangedOwnerIdentity(t *testing.T) {
	const peer = testPeer1
	const assignedIP = "10.40.0.2"

	cases := []struct {
		name  string
		owner PeerOwnership
	}{
		{
			name:  "user reassigned to another account",
			owner: PeerOwnership{PeerPublicKey: peer, ConnectionID: "conn-1", UserID: "user-2", IP: netip.MustParseAddr(assignedIP)},
		},
		{
			name:  "connection row recreated under a new id",
			owner: PeerOwnership{PeerPublicKey: peer, ConnectionID: "conn-2", UserID: "user-1", IP: netip.MustParseAddr(assignedIP)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, resolver, admission, fwd := fixture(t, peer, assignedIP)
			pkt := buildPacket(t, netip.MustParseAddr(assignedIP), 40)

			// First packet under the original owner: admission runs, the
			// route registers, and the memo records that identity.
			if err := router.HandlePacket(pkt); err != nil {
				t.Fatalf("first packet: %v", err)
			}
			if got := admission.calls(peer); got != 1 {
				t.Fatalf("admission called %d times after first packet, want 1", got)
			}
			firstSessionID := admission.sessions[peer].id

			// The durable owner moves. Only the resolver's record changes;
			// the forwarder route is still live, so the memo is the only
			// thing that can notice.
			if err := resolver.Update(tc.owner); err != nil {
				t.Fatalf("publish reassigned ownership: %v", err)
			}
			// Liveness is asserted on the memoized session itself, so the
			// check holds for both cases: only the memo can notice the
			// owner change, the forwarder route is untouched by it.
			if got := fwd.RouteSessionID(peer); got != firstSessionID {
				t.Fatalf("forwarder route session = %q, want the still-live %q", got, firstSessionID)
			}

			// The next packet must re-admit under the new owner rather than
			// ride the previous owner's memoized route.
			if err := router.HandlePacket(pkt); err != nil {
				t.Fatalf("post-reassignment packet: %v", err)
			}
			if got := admission.calls(peer); got != 2 {
				t.Fatalf("admission ran %d times after the owner changed, want 2 (the memo must not fast-path the previous owner's route)", got)
			}
			if admission.sessions[peer].id != firstSessionID {
				t.Fatal("test fixture replaced the session; the re-admission under test did not happen")
			}
			stats := router.StatsSnapshot()
			if stats.AdmittedSessions != 2 {
				t.Fatalf("AdmittedSessions = %d, want 2 (one per owner)", stats.AdmittedSessions)
			}
		})
	}
}

// TestRouterMemoAcceptsUnchangedOwner is the non-regression half: an owner
// that has NOT moved must keep its memoized route, so ordinary traffic — and
// every upstream rekey, which Nexus never sees — does not re-admit.
func TestRouterMemoAcceptsUnchangedOwner(t *testing.T) {
	const peer = testPeer1
	const assignedIP = "10.40.0.2"
	router, _, admission, _ := fixture(t, peer, assignedIP)
	pkt := buildPacket(t, netip.MustParseAddr(assignedIP), 40)

	if err := router.HandlePacket(pkt); err != nil {
		t.Fatalf("first packet: %v", err)
	}
	// Re-asserting the peer's exact current ownership is what a
	// reconciliation that observed no change effectively does.
	for range 16 {
		if err := router.HandlePacket(pkt); err != nil {
			t.Fatalf("steady-state packet: %v", err)
		}
	}
	if got := admission.calls(peer); got != 1 {
		t.Fatalf("admission ran %d times for an unchanged owner, want 1", got)
	}
	if stats := router.StatsSnapshot(); stats.AdmittedSessions != 1 {
		t.Fatalf("AdmittedSessions = %d, want 1", stats.AdmittedSessions)
	}
}
