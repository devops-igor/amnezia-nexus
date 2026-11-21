package vpn

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// A live save must reach the classifier (issue #920).
//
// The inventory override is not part of the compiled policy snapshot, so the
// repeated-enabled update path reuses the running data path and would otherwise
// leave the previous classifier installed until the next restart. This exercises
// the production save path (StartPolicyRouting on an already-active service, the
// call the admin PUT makes) with the offline list fixture of issue #864, so the
// sync really succeeds and the assertion is about the classifier, not the fetch.
func TestLiveSaveAppliesTheInventoryOverride(t *testing.T) {
	const pathA = "/policy.lst"
	fixture := newSavePathFixture(map[string][]string{pathA: domainList("override-live", 20)})
	server := httptest.NewTLSServer(fixture.handler())
	defer server.Close()

	active := policySettingsForURL(t, "https://override-live.example"+pathA)
	saved := active
	// The scenario's own precondition requires the save to change a setting the
	// compiled snapshot does not carry; the refresh interval and the inventory
	// override are both of that kind.
	saved.SyncInterval = active.SyncInterval + 600
	saved.InventoryOverride = []string{"198.51.100.0/24"}
	if err := saved.Validate(); err != nil {
		t.Fatalf("saved fixture settings are invalid: %v", err)
	}

	sc := newSavePathScenario(t, fixture, server, active, saved)

	target := netip.MustParseAddr("198.51.100.7")
	classifier := sc.svc.forwarder.DestinationClassifier()
	if classifier == nil {
		t.Fatal("activation installed no classifier")
	}
	if got := classifier.Classify(target); got.InAllocation {
		t.Fatalf("the shipped set alone already covers %s: %+v", target, got)
	}

	// The supported save path: the admin PUT persists the settings and calls this.
	if err := sc.svc.StartPolicyRouting(sc.ctx, saved, sc.store, string(saved.Preset)); err != nil {
		t.Fatalf("live save with an inventory override: %v", err)
	}

	updated := sc.svc.forwarder.DestinationClassifier()
	if updated == nil {
		t.Fatal("the live save removed the classifier")
	}
	if got := updated.Classify(target); !got.AllocationRoutesDirect() || got.Source != policy.InventorySourceOverride {
		t.Fatalf("the live save did not apply the override to the installed classifier: %+v", got)
	}
	if status := sc.svc.PolicyStatusSnapshot().Inventory; status == nil || status.OverridePrefixCount != 1 {
		t.Fatalf("status after the live save = %+v, want the override reported", status)
	}

	// Clearing the field through the same path returns the classifier to the
	// shipped set: the removal is a save like any other, not a restart.
	cleared := saved
	cleared.InventoryOverride = nil
	if err := cleared.Validate(); err != nil {
		t.Fatalf("cleared fixture settings are invalid: %v", err)
	}
	if err := sc.svc.StartPolicyRouting(sc.ctx, cleared, sc.store, string(cleared.Preset)); err != nil {
		t.Fatalf("live save clearing the inventory override: %v", err)
	}
	if got := sc.svc.forwarder.DestinationClassifier().Classify(target); got.InAllocation {
		t.Fatalf("a cleared override is still applied by the installed classifier: %+v", got)
	}
	if status := sc.svc.PolicyStatusSnapshot().Inventory; status == nil || status.OverridePrefixCount != 0 {
		t.Fatalf("status after clearing the override = %+v, want no override reported", status)
	}
}
