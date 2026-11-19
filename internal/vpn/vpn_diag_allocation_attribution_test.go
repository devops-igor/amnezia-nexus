package vpn

import (
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Per-flow attribution for address-classified flows (issue #918).
//
// Two things must be readable from the existing diagnosis shape without
// redesigning the page:
//
//   - the deciding rule says allocation-matched, never that a service is hosted
//     in Russia, because allocation membership is an approximation; and
//   - "routed direct and worked" is distinguishable from "routed direct and
//     failed", because the second one is the signal that the egress location —
//     not the classifier — is the problem.

func TestDirectAllocationAttributionSeparatesWorkedFromFailed(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	base := func() forwarder.SessionFlow {
		return forwarder.SessionFlow{
			Protocol:         6,
			SrcPort:          41001,
			DstIP:            netip.MustParseAddr("213.180.204.186"),
			DstPort:          443,
			Choice:           forwarder.EgressChoiceDirect,
			Generation:       1,
			LastSeen:         now.Add(-time.Second),
			DecidedAt:        now.Add(-time.Minute),
			DecisionReason:   forwarder.EgressReasonAllocationDirect,
			PolicyGeneration: "gen-1",
		}
	}

	worked := base()
	worked.ForwardPackets = 3
	worked.ForwardBytes = 420

	failed := base()
	failed.ForwardFailed = 1
	failed.ForwardFailure = forwarder.FlowFailureEgressUnavailable

	workedWire := clientDiagnosisFlow(worked, nil, false, nil, now)
	failedWire := clientDiagnosisFlow(failed, nil, false, nil, now)

	// The deciding rule is the allocation token on both, so an operator reads
	// "allocation matched" rather than a claim about where the service runs.
	for name, flow := range map[string]ClientDiagnosisFlow{"worked": workedWire, "failed": failedWire} {
		if flow.DecisionReason != string(forwarder.EgressReasonAllocationDirect) {
			t.Errorf("%s flow decision reason = %q, want %q", name, flow.DecisionReason, forwarder.EgressReasonAllocationDirect)
		}
		if flow.Choice != "DIRECT" {
			t.Errorf("%s flow choice = %q, want DIRECT", name, flow.Choice)
		}
	}

	if workedWire.Dispatch.State != forwarder.FlowForwardWritten {
		t.Errorf("worked flow dispatch state = %q, want %q", workedWire.Dispatch.State, forwarder.FlowForwardWritten)
	}
	if workedWire.Dispatch.Reason != "" {
		t.Errorf("worked flow dispatch reason = %q, want none", workedWire.Dispatch.Reason)
	}

	if failedWire.Dispatch.State != forwarder.FlowForwardFailed {
		t.Errorf("failed flow dispatch state = %q, want %q", failedWire.Dispatch.State, forwarder.FlowForwardFailed)
	}
	if failedWire.Dispatch.Reason != forwarder.FlowFailureEgressUnavailable {
		t.Errorf("failed flow dispatch reason = %q, want %q", failedWire.Dispatch.Reason, forwarder.FlowFailureEgressUnavailable)
	}

	// The reason tokens are wire values the controller translates; both must be
	// documented families, which the handlers-side token test asserts separately.
	if want := "allocation_direct"; string(forwarder.EgressReasonAllocationDirect) != want {
		t.Fatalf("allocation reason token = %q, want %q", forwarder.EgressReasonAllocationDirect, want)
	}
	if want := "allocation_cdn_excluded"; string(forwarder.EgressReasonAllocationCDNExcluded) != want {
		t.Fatalf("CDN exclusion reason token = %q, want %q", forwarder.EgressReasonAllocationCDNExcluded, want)
	}
}

// TestAllocationCDNExclusionIsVisiblePerFlow keeps the CDN caveat readable: a
// flow that stayed proxied because its allocation range belongs to a CDN names
// that branch rather than the generic default.
func TestAllocationCDNExclusionIsVisiblePerFlow(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	flow := forwarder.SessionFlow{
		Protocol:         6,
		SrcPort:          41002,
		DstIP:            netip.MustParseAddr("193.176.179.1"),
		DstPort:          443,
		Choice:           forwarder.EgressChoiceProxy,
		Generation:       1,
		LastSeen:         now.Add(-time.Second),
		DecidedAt:        now.Add(-time.Minute),
		DecisionReason:   forwarder.EgressReasonAllocationCDNExcluded,
		PolicyGeneration: "gen-1",
		BackendTunnelID:  7,
		ForwardPackets:   1,
	}

	got := clientDiagnosisFlow(flow, nil, false, nil, now)
	if got.DecisionReason != string(forwarder.EgressReasonAllocationCDNExcluded) {
		t.Fatalf("decision reason = %q, want %q", got.DecisionReason, forwarder.EgressReasonAllocationCDNExcluded)
	}
	if got.BackendTunnelID == nil || *got.BackendTunnelID != 7 {
		t.Errorf("backend tunnel = %v, want the proxy backend that carried it", got.BackendTunnelID)
	}
	if got.Dispatch.State != forwarder.FlowForwardQueued {
		t.Errorf("dispatch state = %q, want %q", got.Dispatch.State, forwarder.FlowForwardQueued)
	}
}
