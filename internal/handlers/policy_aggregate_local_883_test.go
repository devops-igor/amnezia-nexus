package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// The operator's IPv4 PROXY exception list is the section's one input, so its
// decode, merge and comparison contracts are pinned here at the API boundary.

func TestMergeStoredProxyExceptionsPreservesAbsentAndClearsExplicitEmpty(t *testing.T) {
	previous := previousPolicyRecord{present: true, settings: policy.Settings{
		ProxyExceptions: []string{"203.0.113.0/24"},
	}}

	absent, err := mergeStoredProxyExceptions(policy.Settings{SyncInterval: 3600}, previous)
	if err != nil {
		t.Fatalf("merge absent: %v", err)
	}
	if len(absent.ProxyExceptions) != 1 || absent.ProxyExceptions[0] != "203.0.113.0/24" {
		t.Fatalf("absent proxy exceptions = %v, want preserved", absent.ProxyExceptions)
	}

	cleared, err := mergeStoredProxyExceptions(policy.Settings{
		SyncInterval:    3600,
		ProxyExceptions: []string{},
	}, previous)
	if err != nil {
		t.Fatalf("merge explicit empty: %v", err)
	}
	if len(cleared.ProxyExceptions) != 0 {
		t.Fatalf("explicit empty proxy exceptions = %v, want cleared", cleared.ProxyExceptions)
	}
}

func TestPolicySettingsEqualIncludesProxyExceptions(t *testing.T) {
	base := policy.Settings{ProxyExceptions: []string{"203.0.113.0/24"}}
	changed := policy.Settings{ProxyExceptions: []string{"198.51.100.0/24"}}
	if policySettingsEqual(base, changed) {
		t.Fatal("proxy exception changes compared equal")
	}
}

func TestDecodePolicyPutAcceptsAProxyExceptionList(t *testing.T) {
	h := &Handlers{}
	body := `{"enabled":false,"proxy_exceptions":["198.51.100.7","192.0.2.0/24"],"sync_interval_seconds":3600}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	settings, ok := h.decodePolicyPut(w, req)
	if !ok {
		t.Fatalf("decode rejected: %s", w.Body.String())
	}
	if len(settings.ProxyExceptions) != 2 {
		t.Fatalf("decoded settings = %+v", settings)
	}
}

// A stored record written by an earlier build carries the operator's addresses under
// the old local_entries key. The rename must not drop them, so the wire field keeps
// the old name and the decode below is the proof.
func TestDecodePolicyPutReadsStoredLocalEntriesKey(t *testing.T) {
	h := &Handlers{}
	body := `{"enabled":true,"local_entries":["203.0.113.0/24"],"sync_interval_seconds":3600}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	settings, ok := h.decodePolicyPut(w, req)
	if !ok {
		t.Fatalf("decode rejected: %s", w.Body.String())
	}
	if len(settings.ProxyExceptions) != 1 || settings.ProxyExceptions[0] != "203.0.113.0/24" {
		t.Fatalf("decoded exceptions = %v; a stored record's addresses must survive the load", settings.ProxyExceptions)
	}
}

// A domain line would be saved and never applied, because the packet path matches
// addresses only. The API refuses it with the list's own reason.
func TestDecodePolicyPutRefusesADomainInTheExceptionList(t *testing.T) {
	h := &Handlers{}
	body := `{"enabled":false,"proxy_exceptions":["example.com"],"sync_interval_seconds":3600}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	if _, ok := h.decodePolicyPut(w, req); ok {
		t.Fatal("a domain line in the exception list was accepted")
	}
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "proxy exception rejected") {
		t.Fatalf("refusal = %d %s, want the exception-list reason", w.Code, w.Body.String())
	}
}
