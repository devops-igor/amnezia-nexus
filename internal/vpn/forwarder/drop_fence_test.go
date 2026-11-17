package forwarder

import (
	"net/netip"
	"testing"
	"time"
)

// Publication fence and generation lifetime of pre-flow DROP evidence (issue #861, R21).

// TestRetiredDropCannotBePublishedByAPausedProducer is the reported defect: the producer
// decides to refuse, is paused, the session is retired, and only then does the publication
// run with the route pointer it captured earlier. Without a final ownership check the
// refusal is written back and a direct snapshot reports ended content as current.
func TestRetiredDropCannotBePublishedByAPausedProducer(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	route := fwd.routesByPeer[peer] // exactly the pointer the producer captured
	if route == nil {
		t.Fatal("no live route to capture")
	}

	// The honest positive on the same path: while the route is live the refusal publishes.
	if err := fwd.RouteClientToBackend(peer, []byte{0x45, 0x00, 0x00}); err == nil {
		t.Fatal("a truncated packet was accepted")
	}
	live := fwd.ClientDropSnapshot(sessionID, route.generation, 0)
	if live.Total != 1 {
		t.Fatalf("live publication = %d records, want the one refusal", live.Total)
	}

	fwd.UnregisterSession(peer)

	// The paused producer resumes here with the route it captured before retirement.
	fwd.recordClientDrop(peer, route, DropReasonInvalidPacket, 0, netip.Addr{}, 0, false, 3)

	if got := fwd.ClientDropSnapshot(sessionID, route.generation, 0); got.Total != 0 {
		t.Fatalf("retired drop record resurrected: total=%d", got.Total)
	}
}

// TestRetiredDropCannotBePublishedByAConcurrentProducer is the same fence under real
// concurrency: the producer is genuinely in flight when the session retires.
func TestRetiredDropCannotBePublishedByAConcurrentProducer(t *testing.T) {
	for range 20 {
		fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = fwd.RouteClientToBackend(peer, []byte{0x45, 0x00, 0x00})
		}()
		fwd.UnregisterSession(peer)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("the producer did not finish")
		}
		if got := fwd.ClientDropSnapshot(sessionID, 0, 0).Total; got != 0 {
			t.Fatalf("a refusal published after retirement: total=%d", got)
		}
	}
}

// TestDropRowsFollowTheSelectedGeneration is the rekey control: a replaced incarnation's
// rows are not returned as the current client's evidence, and the successor's own rows are.
func TestDropRowsFollowTheSelectedGeneration(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	first := fwd.routesByPeer[peer]
	prohibited := netip.MustParseAddr("169.254.169.254")

	if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
		netip.MustParseAddr("10.100.0.7"), prohibited, 47000, 80, 0x02, nil)); err == nil {
		t.Fatal("a prohibited destination was accepted")
	}
	if got := fwd.ClientDropSnapshot(sessionID, first.generation, 0); got.Total != 1 {
		t.Fatalf("generation %d rows = %d, want the refusal", first.generation, got.Total)
	}

	// Same-session rekey: same session id, new incarnation.
	fwd.RegisterSessionWithReturnPath(sessionID, "conn-2", peer, "10.100.0.7", 31, newTestCaptureReturnPath().path)
	second := fwd.routesByPeer[peer]
	if second == nil || second.generation == first.generation {
		t.Fatalf("rekey did not advance the generation: %+v", second)
	}

	if got := fwd.ClientDropSnapshot(sessionID, second.generation, 0); got.Total != 0 {
		t.Errorf("the successor reports %d of the previous generation's refusals", got.Total)
	}
	// Explicitly asking for the old generation still answers for it: this is historical
	// evidence, not a claim about the current incarnation. Retirement of that generation
	// removes it.
	if got := fwd.ClientDropSnapshot(sessionID, first.generation, 0); got.Total != 1 {
		t.Errorf("historical generation read = %d, want the refusal retained for its own generation", got.Total)
	}

	// The successor's own refusal is published under its own generation only.
	if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
		netip.MustParseAddr("10.100.0.7"), prohibited, 47001, 80, 0x02, nil)); err == nil {
		t.Fatal("a prohibited destination was accepted")
	}
	if got := fwd.ClientDropSnapshot(sessionID, second.generation, 0); got.Total != 1 {
		t.Errorf("successor rows = %d, want its own refusal", got.Total)
	}
	if got := fwd.ClientDropSnapshot(sessionID, first.generation, 0); got.Total != 1 {
		t.Errorf("the old generation gained the successor's refusal: %d rows", got.Total)
	}
}

// TestDropCoverageSeparatesSessionFromLedger keeps other clients' retention out of a
// client-scoped page.
func TestDropCoverageSeparatesSessionFromLedger(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newDropLedger(func() time.Time { return now })

	ledger.Record("sess-a", 1, DropReasonProhibitedDestination, 6, netip.MustParseAddr("1.1.1.1"), 443, true, 40, now)
	ledger.Record("sess-a", 1, DropReasonProhibitedDestination, 6, netip.MustParseAddr("2.2.2.2"), 443, true, 40, now)
	ledger.Record("sess-b", 1, DropReasonProhibitedDestination, 6, netip.MustParseAddr("3.3.3.3"), 443, true, 40, now)

	snap := ledger.SessionSnapshot("sess-a", 1, 0, now)
	if snap.Coverage.SessionKeys != 2 {
		t.Errorf("session keys = %d, want this session's two", snap.Coverage.SessionKeys)
	}
	if snap.Coverage.Keys != 3 {
		t.Errorf("ledger keys = %d, want the ledger-wide three", snap.Coverage.Keys)
	}
	if snap.Total != 2 {
		t.Errorf("rows = %d, want only this session's", snap.Total)
	}
	if snap.Generation != 1 {
		t.Errorf("generation = %d, want the selected one echoed", snap.Generation)
	}
}

// TestDropRetentionIsAgeFilteredNotPhysical documents the actual retention semantics: the
// read filters by age, the store is pruned on the next write, and the counters say which
// happened.
func TestDropRetentionIsAgeFilteredNotPhysical(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newDropLedger(func() time.Time { return now })
	ledger.Record("sess", 1, DropReasonProhibitedDestination, 6, netip.MustParseAddr("4.4.4.4"), 443, true, 40, now)

	past := ledger.SessionSnapshot("sess", 1, 0, now.Add(DropMaxAge+time.Second))
	if past.Total != 0 {
		t.Fatalf("rows past the window = %d, want 0", past.Total)
	}
	if past.Coverage.SessionKeys != 0 {
		t.Errorf("session keys past the window = %d, want 0 (the read is age-filtered)", past.Coverage.SessionKeys)
	}
	// Still physically present in the store until a write prunes it.
	ledger.mu.Lock()
	physical := len(ledger.byKey)
	ledger.mu.Unlock()
	if physical != 1 {
		t.Errorf("physical records = %d, want 1: retention is pruned on write, not at the read", physical)
	}
	ledger.Record("sess", 1, DropReasonInvalidPacket, 0, netip.Addr{}, 0, false, 3, now.Add(DropMaxAge+2*time.Second))
	if pruned := ledger.SessionSnapshot("sess", 1, 0, now.Add(DropMaxAge+2*time.Second)).Coverage.Pruned; pruned == 0 {
		t.Error("the aged record was not pruned on the next write")
	}
}
