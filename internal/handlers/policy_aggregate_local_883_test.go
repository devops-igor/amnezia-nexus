package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

func TestMergeStoredLocalEntriesPreservesAbsentAndClearsExplicitEmpty(t *testing.T) {
	previous := previousPolicyRecord{present: true, settings: policy.Settings{LocalEntries: []string{"kept.example"}}}

	absent, err := mergeStoredLocalEntries(policy.Settings{Preset: policy.PresetAggregate, SyncInterval: 3600}, previous)
	if err != nil {
		t.Fatalf("merge absent: %v", err)
	}
	if len(absent.LocalEntries) != 1 || absent.LocalEntries[0] != "kept.example" {
		t.Fatalf("absent local entries = %v, want preserved", absent.LocalEntries)
	}

	cleared, err := mergeStoredLocalEntries(policy.Settings{Preset: policy.PresetAggregate, LocalEntries: []string{}}, previous)
	if err != nil {
		t.Fatalf("merge explicit empty: %v", err)
	}
	if len(cleared.LocalEntries) != 0 {
		t.Fatalf("explicit empty local entries = %v, want cleared", cleared.LocalEntries)
	}
}

func TestPolicySettingsEqualIncludesLocalEntries(t *testing.T) {
	base := policy.Settings{Preset: policy.PresetAggregate, LocalEntries: []string{"a.example"}}
	changed := policy.Settings{Preset: policy.PresetAggregate, LocalEntries: []string{"b.example"}}
	if policySettingsEqual(base, changed) {
		t.Fatal("local entry changes compared equal")
	}
}

func TestDecodePolicyPutAcceptsAggregateAndLocalEntries(t *testing.T) {
	h := &Handlers{}
	body := `{"enabled":false,"preset":"aggregate","local_entries":["local.example","198.51.100.0/24"],"sync_interval_seconds":3600}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	settings, ok := h.decodePolicyPut(w, req)
	if !ok {
		t.Fatalf("decode rejected: %s", w.Body.String())
	}
	if settings.Preset != policy.PresetAggregate || len(settings.LocalEntries) != 2 {
		t.Fatalf("decoded settings = %+v", settings)
	}
}

func TestDecodePolicyPutRefusesGuardedLocalEntry(t *testing.T) {
	h := &Handlers{}
	body := `{"enabled":false,"preset":"aggregate","local_entries":["ozon.ru"],"sync_interval_seconds":3600}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	if _, ok := h.decodePolicyPut(w, req); ok {
		t.Fatal("guarded local entry was accepted")
	}
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "never-proxy guard") {
		t.Fatalf("refusal = %d %s, want named never-proxy reason", w.Code, w.Body.String())
	}
}
