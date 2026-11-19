package vpn

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// The committed Russian inventory ships with the build, so the policy status
// view must report its provenance and age in the same response the admin API
// already returns. Without this an operator cannot tell a stale artifact from a
// fresh one, nor a shipped set from an overridden one.
func TestPolicyStatusReportsCommittedInventory(t *testing.T) {
	svc := serviceForActivation(t)

	shipped, err := policy.ShippedInventory()
	if err != nil {
		t.Fatalf("ShippedInventory: %v", err)
	}
	provenance := shipped.Provenance()

	status := svc.PolicyStatusSnapshot()
	if status.Inventory == nil {
		t.Fatal("PolicyStatus.Inventory is nil; the committed inventory is not reported")
	}
	got := status.Inventory

	if got.Error != "" {
		t.Fatalf("Inventory.Error = %q, want empty for the committed artifact", got.Error)
	}
	if got.Source != provenance.Source || got.SourceURL != provenance.SourceURL {
		t.Fatalf("Inventory source = %q/%q, want %q/%q", got.Source, got.SourceURL, provenance.Source, provenance.SourceURL)
	}
	if got.RetrievedAt != provenance.RetrievedAt {
		t.Fatalf("Inventory.RetrievedAt = %q, want %q", got.RetrievedAt, provenance.RetrievedAt)
	}
	if got.PrefixCount != shipped.PrefixCount() || got.SHA256 != provenance.SHA256 {
		t.Fatalf("Inventory counts = %+v, want the shipped set's %d/%s", got, shipped.PrefixCount(), provenance.SHA256)
	}
	if got.OverridePrefixCount != 0 || got.OverrideSHA256 != "" {
		t.Fatalf("Inventory reports an override (%d prefixes), but none is configured", got.OverridePrefixCount)
	}
	if got.MaxAgeDays != int(policy.DefaultInventoryMaxAge/(24*time.Hour)) {
		t.Fatalf("MaxAgeDays = %d, want %d", got.MaxAgeDays, int(policy.DefaultInventoryMaxAge/(24*time.Hour)))
	}

	// Age and staleness must agree with each other and with the recorded date.
	retrieved, err := time.Parse(time.DateOnly, provenance.RetrievedAt)
	if err != nil {
		t.Fatalf("parse retrieval date: %v", err)
	}
	age := time.Now().UTC().Sub(retrieved)
	if got.AgeDays != int(age/(24*time.Hour)) {
		t.Fatalf("AgeDays = %d, want %d from the recorded date", got.AgeDays, int(age/(24*time.Hour)))
	}
	if got.Stale != (got.AgeDays > got.MaxAgeDays) {
		t.Fatalf("Stale = %v with age %d and max age %d", got.Stale, got.AgeDays, got.MaxAgeDays)
	}

	// The admin API serializes the status struct directly, so the field must be
	// present there rather than only reachable from Go.
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal policy status: %v", err)
	}
	for _, key := range []string{`"inventory"`, `"source":"ipdeny"`, `"retrieved_at"`, `"stale"`} {
		if !bytes.Contains(encoded, []byte(key)) {
			t.Fatalf("serialized policy status does not contain %s: %s", key, encoded)
		}
	}
}
