package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

func TestMergeStoredExcludedDomainsPreservesAbsentAndClearsExplicitEmpty(t *testing.T) {
	previous := previousPolicyRecord{present: true, settings: policy.Settings{
		Preset:          policy.PresetAggregate,
		SyncInterval:    3600,
		ExcludedDomains: []string{"kept.example"},
	}}

	absent, err := mergeStoredExcludedDomains(policy.Settings{Preset: policy.PresetAggregate, SyncInterval: 3600}, previous)
	if err != nil {
		t.Fatalf("merge absent: %v", err)
	}
	if len(absent.ExcludedDomains) != 1 || absent.ExcludedDomains[0] != "kept.example" {
		t.Fatalf("absent exclusions = %v, want preserved", absent.ExcludedDomains)
	}

	cleared, err := mergeStoredExcludedDomains(policy.Settings{
		Preset: policy.PresetAggregate, SyncInterval: 3600, ExcludedDomains: []string{},
	}, previous)
	if err != nil {
		t.Fatalf("merge explicit empty: %v", err)
	}
	if len(cleared.ExcludedDomains) != 0 {
		t.Fatalf("explicit empty exclusions = %v, want cleared", cleared.ExcludedDomains)
	}
}

func TestPolicySettingsEqualIncludesExcludedDomains(t *testing.T) {
	base := policy.Settings{Preset: policy.PresetAggregate, ExcludedDomains: []string{"a.example"}}
	changed := policy.Settings{Preset: policy.PresetAggregate, ExcludedDomains: []string{"b.example"}}
	if policySettingsEqual(base, changed) {
		t.Fatal("exclusion changes compared equal")
	}
}

func TestDecodePolicyPutAcceptsExcludedDomains(t *testing.T) {
	h := &Handlers{}
	body := `{"enabled":false,"preset":"aggregate","excluded_domains":["internal.api.example.com","*.corp.example"],"sync_interval_seconds":3600}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	settings, ok := h.decodePolicyPut(w, req)
	if !ok {
		t.Fatalf("decode rejected: %s", w.Body.String())
	}
	if len(settings.ExcludedDomains) != 2 || settings.ExcludedDomains[0] != "internal.api.example.com" {
		t.Fatalf("decoded exclusions = %v", settings.ExcludedDomains)
	}
}

func TestDecodePolicyPutRefusesLocalEntryOverlappingExclusion(t *testing.T) {
	h := &Handlers{}
	body := `{"enabled":false,"preset":"aggregate","local_entries":["api.example.com"],"excluded_domains":["example.com"],"sync_interval_seconds":3600}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	if _, ok := h.decodePolicyPut(w, req); ok {
		t.Fatal("local entry overlapping an exclusion was accepted")
	}
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "excluded_domains") {
		t.Fatalf("refusal = %d %s, want a named excluded_domains reason", w.Code, w.Body.String())
	}
}
