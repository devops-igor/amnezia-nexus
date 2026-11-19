package forwarder

import (
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// The routing contract of issue #918, asserted row by row on the pure function
// that owns the order. Row 6 ("required egress unavailable -> DROP, no automatic
// switch") is decided where availability is known, so its test drives the packet
// path instead: TestAllocationClassifiedFlowWithoutEgressDrops in
// allocation_routing_test.go.

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
			name: "row 1: a prohibited destination is dropped even when DNS evidence says DIRECT",
			in: egressInput{
				prohibitedErr:     ErrProhibitedDestination,
				migrationEvidence: policy.Direct,
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
			name: "row 2: an explicit operator PROXY override wins over DNS evidence",
			in: egressInput{
				proxyOverride:     true,
				migrationEvidence: policy.Direct,
				classification:    allocationDirect,
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

// TestMigrationRowIsConfined proves the migration row is one removable block
// rather than a scattering of evidence handling:
//
//   - rows 1 and 2 decide identically whatever the DNS evidence says, so removing
//     the migration row cannot change them;
//   - the migration row can only replace the classifier rows (3, 4 and 5);
//   - with no evidence present the contract is exactly the final one, row by row.
//
// The literal removal was exercised separately with `go test -overlay` against a
// variant without the block: every case below that has no evidence still passes,
// which is the definition of "the final contract remains".
func TestMigrationRowIsConfined(t *testing.T) {
	classifications := []struct {
		name  string
		value policy.DestinationClassification
	}{
		{"cdn", allocationCDN},
		{"direct", allocationDirect},
		{"uncovered", policy.DestinationClassification{}},
	}
	evidences := []policy.Decision{policy.Unknown, policy.Direct, policy.Proxy}

	for _, classification := range classifications {
		for _, evidence := range evidences {
			in := egressInput{classification: classification.value, migrationEvidence: evidence}
			got := decideEgress(in)

			// Without evidence the classifier's own row must decide.
			if evidence == policy.Unknown {
				wantChoice := EgressChoiceProxy
				wantReason := EgressReasonNoTrustedEvidence
				if classification.name == "cdn" {
					wantReason = EgressReasonAllocationCDNExcluded
				}
				if classification.name == "direct" {
					wantChoice = EgressChoiceDirect
					wantReason = EgressReasonAllocationDirect
				}
				if got.choice != wantChoice || got.reason != wantReason || got.dropped() {
					t.Fatalf("no evidence, %s classification: got %v/%q (dropped=%v), want %v/%q",
						classification.name, got.choice, got.reason, got.dropped(), wantChoice, wantReason)
				}
				continue
			}

			// With evidence present the evidence row decides, and says so.
			wantReason := EgressReasonEvidenceDirect
			wantChoice := EgressChoiceDirect
			if evidence == policy.Proxy {
				wantReason = EgressReasonProxyCachedEvidence
				wantChoice = EgressChoiceProxy
			}
			if got.choice != wantChoice || got.reason != wantReason {
				t.Fatalf("evidence %v, %s classification: got %v/%q, want %v/%q",
					evidence, classification.name, got.choice, got.reason, wantChoice, wantReason)
			}
		}
	}

	// Rows 1 and 2 are decided above the migration row and must ignore it.
	for _, evidence := range evidences {
		if got := decideEgress(egressInput{prohibitedErr: ErrProhibitedDestination, migrationEvidence: evidence}); !got.dropped() {
			t.Errorf("evidence %v overrode the prohibited-destination DROP: %+v", evidence, got)
		}
		if got := decideEgress(egressInput{proxyOverride: true, migrationEvidence: evidence}); got.reason != EgressReasonProxyCIDRRule {
			t.Errorf("evidence %v overrode the explicit PROXY override: %+v", evidence, got)
		}
	}
}

// TestProxyEvidenceAloneDecidesProxy keeps the retained-PROXY-evidence row
// meaningful on its own: a destination with no classification at all is still
// proxied by evidence, with the evidence token rather than the default one.
func TestProxyEvidenceAloneDecidesProxy(t *testing.T) {
	got := decideEgress(egressInput{migrationEvidence: policy.Proxy})
	if got.choice != EgressChoiceProxy || got.reason != EgressReasonProxyCachedEvidence {
		t.Fatalf("got %v/%q, want PROXY/%q", got.choice, got.reason, EgressReasonProxyCachedEvidence)
	}
}
