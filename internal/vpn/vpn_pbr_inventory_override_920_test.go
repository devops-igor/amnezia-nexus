package vpn

import (
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// Operator visibility and activation for the persisted inventory override
// (issue #920).
//
// #919 delivered the override as a library type with precedence and attribution
// but nothing supplied it. These assertions cover the two halves the operator
// sees: the classifier the activated data path consults, and the status the
// policy section reports.
//
// 198.51.100.0/24 (TEST-NET-2) is used as the override body on purpose: it is a
// reserved documentation range, so it is outside the shipped Russian allocation
// and outside the embedded ASN table's CDN list. A destination inside it can only
// be classified direct because the override named it.

func overrideForTest(t *testing.T, body string) *policy.InventoryOverride {
	t.Helper()
	override, err := policy.ParseInventoryOverride([]byte(body))
	if err != nil {
		t.Fatalf("ParseInventoryOverride(%q): %v", body, err)
	}
	return override
}

func TestDestinationClassifierAppliesTheOperatorOverride(t *testing.T) {
	override := overrideForTest(t, "198.51.100.0/24\n")
	target := netip.MustParseAddr("198.51.100.7")

	shippedOnly := newDestinationClassifier(nil)
	if shippedOnly == nil {
		t.Fatal("the shipped inventory and ASN table must produce a classifier")
	}
	if got := shippedOnly.Classify(target); got.InAllocation {
		t.Fatalf("the shipped set alone already covers %s: %+v; the fixture cannot prove precedence", target, got)
	}

	withOverride := newDestinationClassifier(override)
	if withOverride == nil {
		t.Fatal("an override classifier was not built")
	}
	got := withOverride.Classify(target)
	if !got.InAllocation || !got.AllocationRoutesDirect() {
		t.Fatalf("override-covered destination classified as %+v, want allocation-matched direct", got)
	}
	if got.Source != policy.InventorySourceOverride {
		t.Fatalf("classifier reported source %q, want %q", got.Source, policy.InventorySourceOverride)
	}

	// An address the override does not name keeps the committed answer, so the
	// override layers over the shipped set rather than replacing it.
	yandex := netip.MustParseAddr("213.180.204.186")
	if got := withOverride.Classify(yandex); !got.InAllocation || got.Source != policy.InventorySourceShipped {
		t.Fatalf("address outside the override classified as %+v, want the shipped set to answer", got)
	}
}

func TestServiceRecordsTheInventoryOverrideForStatus(t *testing.T) {
	svc, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	t.Cleanup(svc.StopPolicyRouting)

	// Shipped set only: the field reports the committed inventory and no override.
	shipped := svc.PolicyStatusSnapshot().Inventory
	if shipped == nil {
		t.Fatal("status carries no inventory block")
	}
	if shipped.OverridePrefixCount != 0 || shipped.OverrideSHA256 != "" {
		t.Fatalf("shipped-only status reports an override: %+v", shipped)
	}
	if shipped.PrefixCount == 0 || shipped.Source == "" || shipped.RetrievedAt == "" {
		t.Fatalf("shipped-only status is missing provenance: %+v", shipped)
	}

	// Overridden: the override is reported beside the shipped set, not folded into
	// it, and its digest differs from the artifact's.
	override := overrideForTest(t, "198.51.100.0/24\n203.0.113.0/24\n")
	svc.SetInventoryOverride(override)
	live := svc.PolicyStatusSnapshot().Inventory
	if live == nil {
		t.Fatal("status carries no inventory block after an override was accepted")
	}
	if live.OverridePrefixCount != 2 {
		t.Fatalf("override prefix count = %d, want 2", live.OverridePrefixCount)
	}
	if live.OverrideSHA256 != override.Digest() || live.OverrideSHA256 == "" {
		t.Fatalf("override digest = %q, want the submitted body's %q", live.OverrideSHA256, override.Digest())
	}
	if live.PrefixCount != shipped.PrefixCount {
		t.Fatalf("shipped prefix count changed from %d to %d when an override was recorded", shipped.PrefixCount, live.PrefixCount)
	}
	if live.SHA256 != shipped.SHA256 {
		t.Fatalf("shipped digest changed from %q to %q when an override was recorded", shipped.SHA256, live.SHA256)
	}

	// Removing the override returns the status to the shipped set alone.
	svc.SetInventoryOverride(nil)
	cleared := svc.PolicyStatusSnapshot().Inventory
	if cleared.OverridePrefixCount != 0 || cleared.OverrideSHA256 != "" {
		t.Fatalf("a cleared override is still reported: %+v", cleared)
	}
}

func TestConfigurePBRInstallsTheOverrideClassifier(t *testing.T) {
	svc, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.TeardownPBR() })

	matcher := policy.NewMatcher()
	src := policy.NewMemorySource("test-src", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.128/25")},
	})
	snapshot, err := policy.CompileSnapshot(1, "gen-1", []policy.SourceParsedRules{src.ToSourceParsedRules()})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	matcher.Publish(snapshot)

	cfg := PBRConfig{
		Enabled:           true,
		HostWANIP:         netip.MustParseAddr("198.51.200.1"),
		GatewayDNSIP:      netip.MustParseAddr("10.100.0.1"),
		WANDevice:         &mockPBRDevice{},
		RouteCache:        &mockRouteCache{},
		PolicyMatcher:     matcher,
		InventoryOverride: overrideForTest(t, "198.51.100.0/24\n"),
	}
	if err := svc.ConfigurePBR(cfg); err != nil {
		t.Fatalf("ConfigurePBR failed: %v", err)
	}

	installed := svc.forwarder.DestinationClassifier()
	if installed == nil {
		t.Fatal("activation did not install the address classifier")
	}
	got := installed.Classify(netip.MustParseAddr("198.51.100.7"))
	if !got.AllocationRoutesDirect() || got.Source != policy.InventorySourceOverride {
		t.Fatalf("the installed classifier does not apply the operator override: %+v", got)
	}

	// The activation input is also what the status reports, so the two surfaces
	// cannot describe different sets.
	status := svc.PolicyStatusSnapshot().Inventory
	if status == nil || status.OverridePrefixCount != 1 {
		t.Fatalf("status after activation = %+v, want the activated override reported", status)
	}
}

// A live settings change must reach the classifier: the override is not part of
// the compiled policy snapshot, so a save that only changes it would otherwise
// leave the previous set in force until the next restart.
func TestSetInventoryOverrideReplacesTheLiveClassifier(t *testing.T) {
	svc, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.TeardownPBR() })

	matcher := policy.NewMatcher()
	src := policy.NewMemorySource("test-src", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.128/25")},
	})
	snapshot, err := policy.CompileSnapshot(1, "gen-1", []policy.SourceParsedRules{src.ToSourceParsedRules()})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	matcher.Publish(snapshot)

	if err := svc.ConfigurePBR(PBRConfig{
		Enabled:       true,
		HostWANIP:     netip.MustParseAddr("198.51.200.1"),
		GatewayDNSIP:  netip.MustParseAddr("10.100.0.1"),
		WANDevice:     &mockPBRDevice{},
		RouteCache:    &mockRouteCache{},
		PolicyMatcher: matcher,
	}); err != nil {
		t.Fatalf("ConfigurePBR failed: %v", err)
	}

	target := netip.MustParseAddr("198.51.100.7")
	if got := svc.forwarder.DestinationClassifier().Classify(target); got.InAllocation {
		t.Fatalf("the shipped set alone already covers %s: %+v", target, got)
	}

	svc.SetInventoryOverride(overrideForTest(t, "198.51.100.0/24\n"))
	if got := svc.forwarder.DestinationClassifier().Classify(target); !got.AllocationRoutesDirect() {
		t.Fatalf("an accepted live override did not reach the installed classifier: %+v", got)
	}

	svc.SetInventoryOverride(nil)
	if got := svc.forwarder.DestinationClassifier().Classify(target); got.InAllocation {
		t.Fatalf("a cleared override is still applied by the installed classifier: %+v", got)
	}
}
