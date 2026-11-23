package vpn

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// A live save must reach the classifier (issue #920).
//
// The inventory override is not part of the compiled policy snapshot, so the
// repeated-enabled update path reuses the running data path and would otherwise
// leave the previous classifier installed until the next restart. This exercises
// the production save path — StartPolicyRouting on an already-active service, the
// call the admin PUT makes — and asserts on the classifier, not on any fetch.
func TestLiveSaveAppliesTheInventoryOverride(t *testing.T) {
	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)

	active := policy.DefaultSettings()
	active.Enabled = true
	active.ProxyExceptions = []string{"203.0.113.0/24"}

	store := lkgStoreFor(t, active)
	// Registered after the store: cleanup runs LIFO, so the loop must stop before
	// the directory it may still write to is removed.
	t.Cleanup(svc.StopPolicyRouting)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := svc.StartPolicyRouting(ctx, active, store); err != nil {
		t.Fatalf("activation: %v", err)
	}

	// The scenario's precondition: the override must name an address the committed
	// allocation does not already cover, so a direct answer can only come from it.
	target := netip.MustParseAddr("198.51.100.7")
	classifier := svc.DestinationClassifierForTest()
	if classifier == nil {
		t.Fatal("activation installed no classifier")
	}
	if got := classifier.Classify(target); got.InAllocation {
		t.Fatalf("the shipped set alone already covers %s: %+v", target, got)
	}

	// The supported save path: the admin PUT persists the settings and calls this.
	// The save changes only the override and the interval, neither of which the
	// compiled snapshot carries, so the running data path is reused.
	saved := active
	saved.SyncInterval = active.SyncInterval + 600
	saved.InventoryOverride = []string{"198.51.100.0/24"}
	if err := saved.Validate(); err != nil {
		t.Fatalf("saved fixture settings are invalid: %v", err)
	}
	if err := svc.StartPolicyRouting(ctx, saved, store); err != nil {
		t.Fatalf("live save with an inventory override: %v", err)
	}

	updated := svc.DestinationClassifierForTest()
	if updated == nil {
		t.Fatal("the live save removed the classifier")
	}
	if got := updated.Classify(target); !got.AllocationRoutesDirect() || got.Source != policy.InventorySourceOverride {
		t.Fatalf("the live save did not apply the override to the installed classifier: %+v", got)
	}
	if status := svc.PolicyStatusSnapshot().Inventory; status == nil || status.OverridePrefixCount != 1 {
		t.Fatalf("status after the live save = %+v, want the override reported", status)
	}

	// Clearing the field through the same path returns the classifier to the
	// shipped set: the removal is a save like any other, not a restart.
	cleared := saved
	cleared.InventoryOverride = nil
	if err := cleared.Validate(); err != nil {
		t.Fatalf("cleared fixture settings are invalid: %v", err)
	}
	if err := svc.StartPolicyRouting(ctx, cleared, store); err != nil {
		t.Fatalf("live save clearing the inventory override: %v", err)
	}
	if got := svc.DestinationClassifierForTest().Classify(target); got.InAllocation {
		t.Fatalf("a cleared override is still applied by the installed classifier: %+v", got)
	}
	if status := svc.PolicyStatusSnapshot().Inventory; status == nil || status.OverridePrefixCount != 0 {
		t.Fatalf("status after clearing the override = %+v, want no override reported", status)
	}
}
