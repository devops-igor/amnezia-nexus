package forwarder

import (
	"errors"
	"reflect"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// The routing contract of issue #918, asserted row by row on the pure function
// that owns the order. Row 6 ("required egress unavailable -> DROP, no automatic
// switch") is decided where availability is known, so its test drives the packet
// path instead: TestAllocationClassifiedFlowWithoutEgressDrops in
// allocation_routing_test.go.
//
// The destination address is the whole input. The packet-path tests in
// allocation_routing_test.go prove that retained DNS evidence cannot change a
// decision either way; testEgressInputHasNoEvidenceField below keeps that property
// structural, so a later change cannot quietly reintroduce an evidence input
// without failing here.

// allocationDirect is the classifier's answer for a member with no CDN exclusion.
var allocationDirect = policy.DestinationClassification{
	InAllocation: true,
	Source:       policy.InventorySourceShipped,
	ASN:          64999,
}

// allocationCDN is the classifier's answer for a member on a multi-region CDN.
var allocationCDN = policy.DestinationClassification{
	InAllocation: true,
	Source:       policy.InventorySourceShipped,
	ASN:          16509,
	CDNProvider:  "Amazon",
}

func TestRoutingContractRows(t *testing.T) {
	tests := []struct {
		name       string
		in         egressInput
		wantChoice EgressChoice
		wantReason EgressReason
		wantDrop   string
	}{
		{
			name: "row 1: a prohibited destination is dropped even when the classifier matched it",
			in: egressInput{
				prohibitedErr:  ErrProhibitedDestination,
				classification: allocationDirect,
			},
			wantChoice: EgressChoiceNone,
			wantDrop:   DropReasonProhibitedDestination,
		},
		{
			name: "row 2: an explicit operator PROXY override wins over a matching allocation",
			in: egressInput{
				proxyOverride:  true,
				classification: allocationDirect,
			},
			wantChoice: EgressChoiceProxy,
			wantReason: EgressReasonProxyCIDRRule,
		},
		{
			name: "row 3: an allocation member on a known multi-region CDN stays proxied",
			in: egressInput{
				classification: allocationCDN,
			},
			wantChoice: EgressChoiceProxy,
			wantReason: EgressReasonAllocationCDNExcluded,
		},
		{
			name: "row 4: an allocation member with no CDN exclusion routes direct",
			in: egressInput{
				classification: allocationDirect,
			},
			wantChoice: EgressChoiceDirect,
			wantReason: EgressReasonAllocationDirect,
		},
		{
			name:       "row 5: an uncovered destination keeps the fail-safe proxy default",
			in:         egressInput{},
			wantChoice: EgressChoiceProxy,
			wantReason: EgressReasonNoTrustedEvidence,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideEgress(tt.in)
			if got.choice != tt.wantChoice {
				t.Fatalf("choice = %v, want %v", got.choice, tt.wantChoice)
			}
			if got.reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", got.reason, tt.wantReason)
			}
			if got.dropReason != tt.wantDrop {
				t.Errorf("dropReason = %q, want %q", got.dropReason, tt.wantDrop)
			}
			if tt.wantChoice == EgressChoiceNone {
				if got.dropErr == nil {
					t.Error("a DROP must carry the refusal its caller returns")
				}
				if !errors.Is(got.dropErr, ErrProhibitedDestination) {
					t.Errorf("dropErr = %v, want ErrProhibitedDestination", got.dropErr)
				}
			} else if got.dropErr != nil {
				t.Errorf("a routed decision must not carry a refusal, got %v", got.dropErr)
			}
		})
	}
}

// testEgressInputHasNoEvidenceField makes the removal of the DNS-evidence input
// structural rather than textual: the contract's inputs are the prohibited
// verdict, the operator override and the address classification, and nothing
// else. A reintroduced evidence field fails this control before it can decide a
// single packet.
func TestEgressInputHasNoEvidenceField(t *testing.T) {
	wantFields := []string{"prohibitedErr", "proxyOverride", "classification"}
	typ := reflect.TypeOf(egressInput{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	if !reflect.DeepEqual(got, wantFields) {
		t.Fatalf("egressInput fields = %v, want %v: the routing decision must take no DNS-evidence input", got, wantFields)
	}
}
