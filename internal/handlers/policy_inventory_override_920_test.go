package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// The operator inventory override at the settings boundary (issue #920).
//
// The record is validated before anything is persisted, so a body the classifier
// could not apply must be refused with the stored record untouched. That is what
// makes the field safe to expose on the existing settings page: a typo is
// reported to the operator instead of replacing a working configuration with an
// override that routes nothing.

func putPolicyForTest(t *testing.T, h *Handlers, record map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal policy request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", bytes.NewBuffer(payload))
	w := httptest.NewRecorder()
	h.PutPolicyHandler(w, req)
	return w
}

func storedPolicyForTest(t *testing.T, h *Handlers) policy.Settings {
	t.Helper()
	var stored policy.Settings
	raw, found, err := h.db.GetSettingRaw(context.Background(), policy.SettingsKey)
	if err != nil {
		t.Fatalf("read stored policy record: %v", err)
	}
	if !found || !raw.Valid || raw.String == "" {
		return stored
	}
	if err := json.Unmarshal([]byte(raw.String), &stored); err != nil {
		t.Fatalf("decode stored policy record: %v", err)
	}
	return stored
}

func TestPolicyOverrideSavePersistsAndReportsStatus(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	w := putPolicyForTest(t, h, map[string]any{
		"enabled":               false,
		"preset":                string(policy.PresetAggregate),
		"sync_interval_seconds": 3600,
		"inventory_override":    []string{"203.0.113.0/24", "198.51.100.0/24"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("saving a valid override answered %d: %s", w.Code, w.Body.String())
	}

	stored := storedPolicyForTest(t, h)
	if len(stored.InventoryOverride) != 2 || stored.InventoryOverride[0] != "203.0.113.0/24" {
		t.Fatalf("stored override = %v, want the submitted entries", stored.InventoryOverride)
	}

	// The read path returns the same list, so the form can show what is stored
	// rather than an empty textarea over a live override.
	req := httptest.NewRequest(http.MethodGet, "/api/vpn/policy", nil)
	rec := httptest.NewRecorder()
	h.GetPolicyHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET policy answered %d: %s", rec.Code, rec.Body.String())
	}
	var answer struct {
		InventoryOverride []string `json:"inventory_override"`
		Status            struct {
			Inventory *policy.InventoryStatus `json:"inventory"`
		} `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode GET answer: %v", err)
	}
	if len(answer.InventoryOverride) != 2 {
		t.Fatalf("GET returned inventory_override = %v, want both entries", answer.InventoryOverride)
	}

	// Policy routing is disabled here, which is exactly the case an operator
	// reads the status in: the stored override must still be distinguishable from
	// the shipped set rather than silently absent.
	if answer.Status.Inventory == nil {
		t.Fatal("status carries no inventory block")
	}
	if answer.Status.Inventory.OverridePrefixCount != 2 {
		t.Fatalf("status override prefix count = %d, want 2", answer.Status.Inventory.OverridePrefixCount)
	}
	if answer.Status.Inventory.OverrideSHA256 == "" {
		t.Fatal("status reports an override count with no digest")
	}
	if answer.Status.Inventory.PrefixCount == 0 {
		t.Fatal("status dropped the shipped prefix count while an override is configured")
	}
	if answer.Status.Inventory.SHA256 == answer.Status.Inventory.OverrideSHA256 {
		t.Fatal("status reports the override digest as the shipped digest")
	}
}

func TestPolicyOverrideRefusedAtTheBoundaryLeavesTheRecordUnchanged(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	accepted := putPolicyForTest(t, h, map[string]any{
		"enabled":               false,
		"preset":                string(policy.PresetAggregate),
		"sync_interval_seconds": 3600,
		"inventory_override":    []string{"203.0.113.0/24"},
	})
	if accepted.Code != http.StatusOK {
		t.Fatalf("seed save answered %d: %s", accepted.Code, accepted.Body.String())
	}
	before := storedPolicyForTest(t, h)

	for name, override := range map[string][]string{
		"mistyped_prefix":   {"203.0.113.999"},
		"domains_only":      {"example.com"},
		"prefix_and_domain": {"203.0.113.0/24", "example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			w := putPolicyForTest(t, h, map[string]any{
				"enabled":               false,
				"preset":                string(policy.PresetAggregate),
				"sync_interval_seconds": 3600,
				"inventory_override":    override,
			})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("invalid override answered %d, want 400: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "inventory override") {
				t.Fatalf("refusal does not name the inventory override: %s", w.Body.String())
			}
			after := storedPolicyForTest(t, h)
			if len(after.InventoryOverride) != len(before.InventoryOverride) || after.InventoryOverride[0] != before.InventoryOverride[0] {
				t.Fatalf("a refused override changed the stored record: before %v, after %v",
					before.InventoryOverride, after.InventoryOverride)
			}
		})
	}
}

// A save that omits the field must not erase the stored override, and an
// explicitly empty list must clear it. Both cases exist in practice: an API
// client that predates the field, and an operator clearing the textarea.
func TestPolicyOverrideMergePreservesAbsentAndClearsExplicitEmpty(t *testing.T) {
	previous := previousPolicyRecord{present: true, settings: policy.Settings{
		Preset:            policy.PresetAggregate,
		SyncInterval:      3600,
		InventoryOverride: []string{"203.0.113.0/24"},
	}}

	absent, err := mergeStoredInventoryOverride(policy.Settings{Preset: policy.PresetAggregate, SyncInterval: 3600}, previous)
	if err != nil {
		t.Fatalf("merge absent override: %v", err)
	}
	if len(absent.InventoryOverride) != 1 || absent.InventoryOverride[0] != "203.0.113.0/24" {
		t.Fatalf("absent override merged to %v, want the stored one preserved", absent.InventoryOverride)
	}

	cleared, err := mergeStoredInventoryOverride(policy.Settings{
		Preset: policy.PresetAggregate, SyncInterval: 3600, InventoryOverride: []string{},
	}, previous)
	if err != nil {
		t.Fatalf("merge explicit empty override: %v", err)
	}
	if len(cleared.InventoryOverride) != 0 {
		t.Fatalf("explicit empty override merged to %v, want it cleared", cleared.InventoryOverride)
	}
}

func TestPolicySettingsEqualIncludesInventoryOverride(t *testing.T) {
	base := policy.Settings{Preset: policy.PresetAggregate, InventoryOverride: []string{"203.0.113.0/24"}}
	changed := policy.Settings{Preset: policy.PresetAggregate, InventoryOverride: []string{"198.51.100.0/24"}}
	if policySettingsEqual(base, changed) {
		t.Fatal("override changes compared equal, so a compensating write could skip the rollback")
	}
}
