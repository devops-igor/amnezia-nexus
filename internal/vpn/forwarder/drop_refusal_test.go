package forwarder

import (
	"errors"
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

// refuseFixture builds a policy-active forwarder whose direct egress has the given limits.
// Its classifier treats every destination as an allocation member, so each flow in these
// controls takes the DIRECT path where the refusal happens.
func refuseFixture(t *testing.T, cfg DirectEgressConfig) (*Forwarder, string, string) {
	t.Helper()
	fwd := NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetPBREnabled(true)
	cfg.HostWANIP = netip.MustParseAddr("203.0.113.1")
	fwd.SetDirectEgress(NewDirectEgressManager(cfg, fwd))
	dem := fwd.DirectEgress()
	// The manager owns a WAN reader; retire it with the test that created it.
	t.Cleanup(func() { _ = dem.Close() })
	fwd.SetDestinationClassifier(newAllDirectTestClassifier())
	fwd.RegisterSessionWithReturnPath("sess-refuse", "conn-1", "peer-refuse", "10.100.0.7", 31, newTestCaptureReturnPath().path)
	t.Cleanup(fwd.StopPumps)
	return fwd, "peer-refuse", "sess-refuse"
}

// TestRefusalSinkFlowTableFull proves a full flow table is recorded per client with the
// destination that could not be installed.
func TestRefusalSinkFlowTableFull(t *testing.T) {
	fwd, peer, sessionID := refuseFixture(t, DirectEgressConfig{
		WANDevice: newMockPacketDev(),
		MaxFlows:  1,
	})

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
	fwd, peer, sessionID := refuseFixture(t, DirectEgressConfig{
		WANDevice: newMockPacketDev(),
		MinPort:   50100,
		MaxPort:   50100,
	})

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
	fwd, peer, sessionID := refuseFixture(t, DirectEgressConfig{WANDevice: newMockPacketDev()})
	fwd.SetDirectEgress(nil) // the decision path has no manager to dispatch through

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

// TestRefusalSinkIsFencedAfterRetirement is a unit control of the publication fence for the
// new producers: the resumed call is made directly, so this does NOT stand in for the
// real-hook pause control, which is run as an overlay against the dispatch path.
func TestRefusalSinkIsFencedAfterRetirement(t *testing.T) {
	fwd, peer, sessionID := refuseFixture(t, DirectEgressConfig{WANDevice: newMockPacketDev()})
	route := fwd.routesByPeer[peer]
	fwd.SetDirectEgress(nil)

	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.50", 50005, 443)); err == nil {
		t.Fatal("a packet was dispatched without a direct-egress manager")
	}
	if snap := fwd.ClientDropSnapshot(sessionID, 0, 0); snap.Total != 1 {
		t.Fatalf("live refusal = %d, want 1", snap.Total)
	}

	fwd.UnregisterSession(peer)
	// The paused producer resumes with the route it captured.
	fwd.recordDirectRefusal(peer, route, flowClientPacket("10.100.0.7", "93.184.216.50", 50005, 443), 60, ErrDirectEgressUnavailable, refusalBeforeDispatch)
	if snap := fwd.ClientDropSnapshot(sessionID, 0, 0); snap.Total != 0 {
		t.Errorf("a retired session's refusal was published: total=%d", snap.Total)
	}
}

// TestPostEntryWANFailureIsNotDuplicatedInTheLedger is the reported duplicate control: a write
// that fails after the flow entry exists belongs to that flow's evidence, and the per-client
// ledger must not report the same refusal a second time.
func TestPostEntryWANFailureIsNotDuplicatedInTheLedger(t *testing.T) {
	// No WAN device: the entry is installed, then the write step refuses.
	fwd, peer, sessionID := refuseFixture(t, DirectEgressConfig{WANDevice: nil})

	err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.60", 50010, 443))
	if !errors.Is(err, ErrDirectEgressUnavailable) {
		t.Fatalf("dispatch = %v, want ErrDirectEgressUnavailable", err)
	}

	// The flow owns the outcome: it exists and its evidence records the failure.
	list := fwd.DirectEgress().SnapshotSessionFlows(sessionID, 0, time.Now(), 0)
	if list.Total != 1 {
		t.Fatalf("flows = %d, want the entry that recorded the failure", list.Total)
	}
	flow := list.Flows[0]
	if flow.ForwardFailed != 1 || flow.ForwardFailure != FlowFailureEgressUnavailable {
		t.Errorf("flow evidence = failed %d (%q), want 1 with %q",
			flow.ForwardFailed, flow.ForwardFailure, FlowFailureEgressUnavailable)
	}

	// And the ledger stays empty: one refusal, one owner.
	if snap := fwd.ClientDropSnapshot(sessionID, 0, 0); snap.Total != 0 {
		t.Errorf("the same refusal was also published as a drop: %d rows (reason %q)",
			snap.Total, snap.Entries[0].Key.Reason)
	}
}

// TestRefusalSinkRecoversAfterCapacityIsReleased proves the refusal is not sticky: once the
// capacity is free the same client's next packet installs a flow, while the earlier refusal
// remains recorded history.
func TestRefusalSinkRecoversAfterCapacityIsReleased(t *testing.T) {
	fwd, peer, sessionID := refuseFixture(t, DirectEgressConfig{
		WANDevice: newMockPacketDev(),
		MaxFlows:  1,
	})

	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.70", 50011, 443)); err != nil {
		t.Fatalf("first direct packet: %v", err)
	}
	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.71", 50012, 443)); err == nil {
		t.Fatal("the cap did not refuse; the recovery control needs the refusal")
	}
	if snap := fwd.ClientDropSnapshot(sessionID, 0, 0); snap.Total != 1 {
		t.Fatalf("refusals = %d, want 1 before recovery", snap.Total)
	}

	// Release the capacity the way production does: the flow ages out of the table.
	fwd.DirectEgress().PurgePeer(peer)
	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "93.184.216.71", 50012, 443)); err != nil {
		t.Fatalf("retry after capacity was released: %v", err)
	}

	list := fwd.DirectEgress().SnapshotSessionFlows(sessionID, 0, time.Now(), 0)
	if list.Total != 1 {
		t.Errorf("flows after recovery = %d, want the recovered flow", list.Total)
	}
	// The refusal stays as recorded history; it is not silently rewritten.
	if snap := fwd.ClientDropSnapshot(sessionID, 0, 0); snap.Total != 1 {
		t.Errorf("refusals after recovery = %d, want the earlier one retained", snap.Total)
	}
}
