package forwarder

import (
	"net/netip"
	"testing"
	"time"
)

// No-flow refusal sinks (issue #861, R24).
//
// The three refusals below leave nothing for a later read to find: the flow table is full,
// a NAT port cannot be allocated, or there is no direct-egress manager at all. Each control
// drives the real dispatch path and reads the bounded ledger through the same publication
// fence the other producers use.

// refuseFixture builds a policy-active forwarder whose direct egress has the given limits and
// a route cache that puts the test destinations on the DIRECT path.
func refuseFixture(t *testing.T, cfg DirectEgressConfig) (*Forwarder, *testRouteCache, string, string) {
	t.Helper()
	fwd := NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetPBREnabled(true)
	cfg.HostWANIP = netip.MustParseAddr("203.0.113.1")
	cfg.GatewayDNSIP = netip.MustParseAddr("10.100.0.1")
	fwd.SetDirectEgress(NewDirectEgressManager(cfg, fwd))
	cache := newTestRouteCache()
	fwd.SetRouteCache(cache)
	fwd.RegisterSessionWithReturnPath("sess-refuse", "conn-1", "peer-refuse", "10.100.0.7", 31, newTestCaptureReturnPath().path)
	t.Cleanup(fwd.StopPumps)
	return fwd, cache, "peer-refuse", "sess-refuse"
}

// directDecision marks a destination DIRECT in the route cache, which is the client-scoped
// DNS evidence branch of the real decision.
func directDecision(cache *testRouteCache, sessionID, dst string) {
	cache.Set(sessionID, netip.MustParseAddr(dst), 1) // policy.Direct
}

// TestRefusalSinkFlowTableFull proves a full flow table is recorded per client with the
// destination that could not be installed.
func TestRefusalSinkFlowTableFull(t *testing.T) {
	fwd, cache, peer, sessionID := refuseFixture(t, DirectEgressConfig{
		WANDevice: newMockPacketDev(),
		MaxFlows:  1,
	})
	directDecision(cache, sessionID, "93.184.216.20")
	directDecision(cache, sessionID, "93.184.216.21")

	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.20", 50000, 443)); err != nil {
		t.Fatalf("first direct packet: %v", err)
	}
	err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.21", 50001, 443))
	if err == nil {
		t.Fatal("the flow-table cap did not refuse the second flow; the control needs the real refusal")
	}

	snap := fwd.ClientDropSnapshot(sessionID, 0, 0)
	if snap.Total != 1 {
		t.Fatalf("refusals recorded = %d, want the one refused flow", snap.Total)
	}
	row := snap.Entries[0]
	if row.Key.Reason != DropReasonFlowTableFull {
		t.Errorf("reason = %q, want %q", row.Key.Reason, DropReasonFlowTableFull)
	}
	if !row.Key.HasTuple || netip.AddrFrom4(row.Key.DstIP).String() != "93.184.216.21" || row.Key.DstPort != 443 {
		t.Errorf("tuple = %+v, want the refused destination", row.Key)
	}
	if row.Count != 1 || row.Bytes == 0 {
		t.Errorf("count/bytes = %d/%d, want 1 and a real packet size", row.Count, row.Bytes)
	}
}

// TestRefusalSinkNATPortExhaustion proves a port-allocation refusal is recorded even though
// the entry created for it is removed again.
func TestRefusalSinkNATPortExhaustion(t *testing.T) {
	fwd, cache, peer, sessionID := refuseFixture(t, DirectEgressConfig{
		WANDevice: newMockPacketDev(),
		MinPort:   50100,
		MaxPort:   50100,
	})
	directDecision(cache, sessionID, "93.184.216.30")
	directDecision(cache, sessionID, "93.184.216.31")

	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.30", 50002, 443)); err != nil {
		t.Fatalf("first direct packet: %v", err)
	}
	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.31", 50003, 443)); err == nil {
		t.Fatal("the single-port pool admitted a second flow; the control needs the real refusal")
	}

	snap := fwd.ClientDropSnapshot(sessionID, 0, 0)
	if snap.Total != 1 {
		t.Fatalf("refusals recorded = %d, want the one refused flow", snap.Total)
	}
	if got := snap.Entries[0].Key.Reason; got != DropReasonNATPortExhaustion {
		t.Errorf("reason = %q, want %q", got, DropReasonNATPortExhaustion)
	}
	// The entry created for the refused flow must not survive: nothing to read, which is why
	// the ledger row is the only evidence.
	if flows := fwd.DirectEgress().SnapshotSessionFlows(sessionID, 0, time.Now(), 0); flows.Total != 1 {
		t.Errorf("flows after the refusal = %d, want only the admitted one", flows.Total)
	}
}

// TestRefusalSinkEgressUnavailable proves the pre-entry direct-egress refusal is attributed.
func TestRefusalSinkEgressUnavailable(t *testing.T) {
	fwd, cache, peer, sessionID := refuseFixture(t, DirectEgressConfig{WANDevice: newMockPacketDev()})
	fwd.SetDirectEgress(nil) // the decision path has no manager to dispatch through
	directDecision(cache, sessionID, "93.184.216.40")

	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.40", 50004, 443)); err == nil {
		t.Fatal("a packet was dispatched without a direct-egress manager")
	}

	snap := fwd.ClientDropSnapshot(sessionID, 0, 0)
	if snap.Total != 1 {
		t.Fatalf("refusals recorded = %d, want the one refusal", snap.Total)
	}
	if got := snap.Entries[0].Key.Reason; got != DropReasonEgressUnavailable {
		t.Errorf("reason = %q, want %q", got, DropReasonEgressUnavailable)
	}
}

// TestRefusalSinkIsFencedAfterRetirement proves the new producers respect the same
// publication fence: a refusal that resumes after the session ended stores nothing.
func TestRefusalSinkIsFencedAfterRetirement(t *testing.T) {
	fwd, cache, peer, sessionID := refuseFixture(t, DirectEgressConfig{WANDevice: newMockPacketDev()})
	route := fwd.routesByPeer[peer]
	fwd.SetDirectEgress(nil)
	directDecision(cache, sessionID, "93.184.216.50")

	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.50", 50005, 443)); err == nil {
		t.Fatal("a packet was dispatched without a direct-egress manager")
	}
	if snap := fwd.ClientDropSnapshot(sessionID, 0, 0); snap.Total != 1 {
		t.Fatalf("live refusal = %d, want 1", snap.Total)
	}

	fwd.UnregisterSession(peer)
	// The paused producer resumes with the route it captured.
	fwd.recordDirectRefusal(peer, route, flowClientPacket("10.100.0.7", "93.184.216.50", 50005, 443), 60, ErrDirectEgressUnavailable)
	if snap := fwd.ClientDropSnapshot(sessionID, 0, 0); snap.Total != 0 {
		t.Errorf("a retired session's refusal was published: total=%d", snap.Total)
	}
}
