package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Coupled producer→API controls for the no-flow refusal sinks (issue #861, R25).
//
// Each case drives the real dispatch path, asserts the exact error the packet path returned,
// and then reads the same fact through the real diagnosis service.

// tightDirectEgress replaces the fixture's manager with one whose limits force the refusal.
func tightDirectEgress(t *testing.T, f *clientDiagFixture, cfg forwarder.DirectEgressConfig) {
	t.Helper()
	cfg.HostWANIP = netip.MustParseAddr("203.0.113.1")
	cfg.GatewayDNSIP = netip.MustParseAddr("10.100.0.1")
	f.fwd.SetDirectEgress(forwarder.NewDirectEgressManager(cfg, f.fwd))
}

// directRouteFor marks the destination DIRECT in the fixture's route cache.
func directRouteFor(t *testing.T, f *clientDiagFixture, dst string) {
	t.Helper()
	f.routeCache.Set(f.sessionID(t), netip.MustParseAddr(dst), 1) // policy.Direct
}

func diagnosisFor(t *testing.T, f *clientDiagFixture) ClientDiagnosisResponse {
	t.Helper()
	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	return answer
}

// TestClientDiagnosisReportsFlowTableFullRefusal proves a full table reaches the client's own
// drop section with a row, and leaves no flow behind for the refused destination.
func TestClientDiagnosisReportsFlowTableFullRefusal(t *testing.T) {
	f := newClientDiagFixture(t)
	tightDirectEgress(t, f, forwarder.DirectEgressConfig{WANDevice: &mockPBRDevice{}, MaxFlows: 1})
	directRouteFor(t, f, "93.184.216.80")
	directRouteFor(t, f, "93.184.216.81")

	if err := f.fwd.RouteClientToBackend(f.peerKey, buildTestPBRTCPPacket(f.clientIP, netip.MustParseAddr("93.184.216.80"), 52000, 443, nil)); err != nil {
		t.Fatalf("first direct packet: %v", err)
	}
	err := f.fwd.RouteClientToBackend(f.peerKey, buildTestPBRTCPPacket(f.clientIP, netip.MustParseAddr("93.184.216.81"), 52001, 443, nil))
	if !errors.Is(err, forwarder.ErrFlowTableFull) {
		t.Fatalf("dispatch = %v, want ErrFlowTableFull", err)
	}

	answer := diagnosisFor(t, f)
	if answer.Drops.Total != 1 || len(answer.Drops.Entries) != 1 {
		t.Fatalf("drops = total %d entries %d, want the one refusal", answer.Drops.Total, len(answer.Drops.Entries))
	}
	row := answer.Drops.Entries[0]
	if row.Reason != "flow_table_full" {
		t.Errorf("reason = %q, want flow_table_full", row.Reason)
	}
	if !row.HasTuple || row.DestinationIP != "93.184.216.81" || row.DestinationPort != 443 {
		t.Errorf("row tuple = %+v, want the refused destination", row)
	}
	if answer.Drops.Coverage.Generation == 0 {
		t.Error("the drop section does not state the generation it belongs to")
	}
	// No flow survived for the refused destination, and there is no duplicate sibling row.
	if len(answer.Flows.Entries) != 1 {
		t.Errorf("flows = %d, want only the admitted one", len(answer.Flows.Entries))
	}
	for _, flow := range answer.Flows.Entries {
		if flow.DestinationIP == "93.184.216.81" {
			t.Error("the refused destination has a flow record")
		}
	}
}

// TestClientDiagnosisReportsNATExhaustionRefusal proves the removed-entry refusal is still
// attributed to the client.
func TestClientDiagnosisReportsNATExhaustionRefusal(t *testing.T) {
	f := newClientDiagFixture(t)
	tightDirectEgress(t, f, forwarder.DirectEgressConfig{
		WANDevice: &mockPBRDevice{}, MinPort: 50200, MaxPort: 50200,
	})
	directRouteFor(t, f, "93.184.216.82")
	directRouteFor(t, f, "93.184.216.83")

	if err := f.fwd.RouteClientToBackend(f.peerKey, buildTestPBRTCPPacket(f.clientIP, netip.MustParseAddr("93.184.216.82"), 52002, 443, nil)); err != nil {
		t.Fatalf("first direct packet: %v", err)
	}
	err := f.fwd.RouteClientToBackend(f.peerKey, buildTestPBRTCPPacket(f.clientIP, netip.MustParseAddr("93.184.216.83"), 52003, 443, nil))
	if !errors.Is(err, forwarder.ErrNATPortExhaustion) {
		t.Fatalf("dispatch = %v, want ErrNATPortExhaustion", err)
	}

	answer := diagnosisFor(t, f)
	if answer.Drops.Total != 1 {
		t.Fatalf("drops = %d, want the one refusal", answer.Drops.Total)
	}
	if answer.Drops.Entries[0].Reason != "nat_port_exhaustion" {
		t.Errorf("reason = %q, want nat_port_exhaustion", answer.Drops.Entries[0].Reason)
	}
	if len(answer.Flows.Entries) != 1 {
		t.Errorf("flows = %d, want only the admitted one (the refused entry must be gone)", len(answer.Flows.Entries))
	}
}

// TestClientDiagnosisReportsPreEntryEgressRefusal proves the pre-dispatch refusal is attributed
// when there is no direct-egress manager at all.
func TestClientDiagnosisReportsPreEntryEgressRefusal(t *testing.T) {
	f := newClientDiagFixture(t)
	directRouteFor(t, f, "93.184.216.84")
	f.fwd.SetDirectEgress(nil)

	err := f.fwd.RouteClientToBackend(f.peerKey, buildTestPBRTCPPacket(f.clientIP, netip.MustParseAddr("93.184.216.84"), 52004, 443, nil))
	if !errors.Is(err, forwarder.ErrDirectEgressUnavailable) {
		t.Fatalf("dispatch = %v, want ErrDirectEgressUnavailable", err)
	}

	answer := diagnosisFor(t, f)
	if answer.Drops.Total != 1 {
		t.Fatalf("drops = %d, want the one refusal", answer.Drops.Total)
	}
	if answer.Drops.Entries[0].Reason != "direct_egress_unavailable" {
		t.Errorf("reason = %q, want direct_egress_unavailable", answer.Drops.Entries[0].Reason)
	}
	if len(answer.Flows.Entries) != 0 {
		t.Errorf("flows = %d, want none for a pre-entry refusal", len(answer.Flows.Entries))
	}
}

// TestClientDiagnosisDoesNotDuplicatePostEntryWANFailure is the reported duplicate, read
// through the API: the flow states the failure and the drop section stays empty.
func TestClientDiagnosisDoesNotDuplicatePostEntryWANFailure(t *testing.T) {
	f := newClientDiagFixture(t)
	tightDirectEgress(t, f, forwarder.DirectEgressConfig{WANDevice: nil})
	directRouteFor(t, f, "93.184.216.85")

	err := f.fwd.RouteClientToBackend(f.peerKey, buildTestPBRTCPPacket(f.clientIP, netip.MustParseAddr("93.184.216.85"), 52005, 443, nil))
	if !errors.Is(err, forwarder.ErrDirectEgressUnavailable) {
		t.Fatalf("dispatch = %v, want ErrDirectEgressUnavailable", err)
	}

	answer := diagnosisFor(t, f)
	if answer.Drops.Total != 0 {
		t.Errorf("drops = %d, want none: the flow already retains this refusal", answer.Drops.Total)
	}
	if len(answer.Flows.Entries) != 1 {
		t.Fatalf("flows = %d, want the flow that recorded the failure", len(answer.Flows.Entries))
	}
	flow := answer.Flows.Entries[0]
	if flow.Forward.Failed != 1 || flow.Forward.Failure != forwarder.FlowFailureEgressUnavailable {
		t.Errorf("flow failure = %d (%q), want 1 with %q",
			flow.Forward.Failed, flow.Forward.Failure, forwarder.FlowFailureEgressUnavailable)
	}
}
