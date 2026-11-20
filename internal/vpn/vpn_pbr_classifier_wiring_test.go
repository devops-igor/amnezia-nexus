package vpn

import (
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// Production wiring of the address classifier (issue #918): activation installs
// it on the forwarder, and both ways of turning policy routing off remove it, so
// no classification outlives the data path that consults it.

func TestServicePBRInstallsAndRemovesTheAddressClassifier(t *testing.T) {
	svc, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	matcher := policy.NewMatcher()
	src := policy.NewMemorySource("test-src", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	snapshot, err := policy.CompileSnapshot(1, "gen-1", []policy.SourceParsedRules{src.ToSourceParsedRules()})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	matcher.Publish(snapshot)

	cfg := PBRConfig{
		Enabled:       true,
		HostWANIP:     netip.MustParseAddr("198.51.200.1"),
		WANDevice:     &mockPBRDevice{},
		RouteCache:    &mockRouteCache{},
		PolicyMatcher: matcher,
	}

	if svc.forwarder.DestinationClassifier() != nil {
		t.Fatal("a classifier is installed before policy routing is activated")
	}

	if err := svc.ConfigurePBR(cfg); err != nil {
		t.Fatalf("ConfigurePBR failed: %v", err)
	}

	installed := svc.forwarder.DestinationClassifier()
	if installed == nil {
		t.Fatal("activation did not install the address classifier")
	}
	// The installed classifier is the production join of both committed inputs.
	yandex := installed.Classify(netip.MustParseAddr("213.180.204.186"))
	if !yandex.AllocationRoutesDirect() {
		t.Fatalf("installed classifier did not classify the field-verified Yandex address direct: %+v", yandex)
	}
	cdn := installed.Classify(netip.MustParseAddr("193.176.179.1"))
	if cdn.CDNProvider == "" || cdn.AllocationRoutesDirect() {
		t.Fatalf("installed classifier did not exclude a multi-region CDN range inside the allocation: %+v", cdn)
	}

	if err := svc.TeardownPBR(); err != nil {
		t.Fatalf("TeardownPBR failed: %v", err)
	}
	if got := svc.forwarder.DestinationClassifier(); got != nil {
		t.Fatalf("teardown left a classifier installed: %T", got)
	}
}

// TestNewDestinationClassifierWithoutUsableInputsIsNil documents the fail-safe
// path: an unusable input means no classifier, which keeps the proxy default
// rather than routing on partial data.
func TestNewDestinationClassifierJoinsBothCommittedInputs(t *testing.T) {
	classifier := newDestinationClassifier(nil)
	if classifier == nil {
		t.Fatal("the committed inventory and embedded ASN table must produce a classifier")
	}
	if got := classifier.Classify(netip.MustParseAddr("185.73.194.82")); !got.AllocationRoutesDirect() {
		t.Fatalf("ozon.ru should classify direct, got %+v", got)
	}
	if got := classifier.Classify(netip.MustParseAddr("147.91.1.1")); got.InAllocation {
		t.Fatalf("the Serbian control must not be inside the allocation, got %+v", got)
	}
}
