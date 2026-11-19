package policy

import (
	"testing"
	"time"
)

// Status reporting for the served inventory, resolved exactly as the classifier
// resolves it (issue #920).
//
// The three cases the surface has to distinguish are the shipped set, the
// overridden set and a stale artifact. They are asserted against the real
// committed provenance and the real age arithmetic with the instant injected, so
// "stale" is computed rather than assumed.
func TestResolvedInventoryStatusCoversShippedOverriddenAndStale(t *testing.T) {
	shipped, err := ShippedInventory()
	if err != nil {
		t.Fatalf("ShippedInventory: %v", err)
	}
	prov := shipped.Provenance()
	retrieved, err := time.Parse(time.DateOnly, prov.RetrievedAt)
	if err != nil {
		t.Fatalf("parse the recorded retrieval date: %v", err)
	}

	shippedStatus := shipped.WithOverride(nil).Status(retrieved.Add(24*time.Hour), DefaultInventoryMaxAge)
	if shippedStatus.OverridePrefixCount != 0 || shippedStatus.OverrideSHA256 != "" {
		t.Fatalf("shipped-only status reports an override: %+v", shippedStatus)
	}
	if shippedStatus.PrefixCount != shipped.PrefixCount() || shippedStatus.Source == "" || shippedStatus.RetrievedAt != prov.RetrievedAt {
		t.Fatalf("shipped-only status is missing provenance: %+v", shippedStatus)
	}

	override, err := ParseInventoryOverride([]byte("203.0.113.0/24\n198.51.100.0/24\n"))
	if err != nil {
		t.Fatalf("ParseInventoryOverride: %v", err)
	}
	resolved := shipped.WithOverride(override)

	overridden := resolved.Status(retrieved.Add(24*time.Hour), DefaultInventoryMaxAge)
	if overridden.OverridePrefixCount != 2 || overridden.OverrideSHA256 != override.Digest() {
		t.Fatalf("overridden status = %+v, want the override's count and digest", overridden)
	}
	if overridden.PrefixCount != shippedStatus.PrefixCount || overridden.SHA256 != shippedStatus.SHA256 {
		t.Fatalf("the override changed the shipped set's own facts: %+v vs %+v", overridden, shippedStatus)
	}

	// The stale case: the same resolved set, read past the threshold. The stale
	// marker must not cost the override attribution, or an operator would lose
	// sight of their own correction exactly when the artifact needs attention.
	stale := resolved.Status(retrieved.Add(200*24*time.Hour), DefaultInventoryMaxAge)
	if !stale.Stale || stale.AgeDays != 200 {
		t.Fatalf("status 200 days after retrieval = %+v, want age 200 and stale", stale)
	}
	if stale.OverridePrefixCount != 2 || stale.OverrideSHA256 != override.Digest() {
		t.Fatalf("a stale artifact dropped the override attribution: %+v", stale)
	}
	if stale.PrefixCount != shipped.PrefixCount() {
		t.Fatalf("a stale artifact changed the shipped prefix count to %d, want %d", stale.PrefixCount, shipped.PrefixCount())
	}
}
