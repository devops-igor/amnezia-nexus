package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Handler-level coverage for the read-only policy dry run (issue #825):
// request validation, the answer shape on a service that has no live policy
// data path, and the counter/cache invariance of a request.
//
// Authorization is asserted where it is enforced — through the real router, in
// internal/router/policy_explain_825_test.go — not by mocking a middleware here.

func postPolicyExplain(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/vpn/policy/explain", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ExplainPolicyHandler(w, req)
	return w
}

func decodeExplainResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode explain response (status %d): %v; body=%s", w.Code, err, w.Body.String())
	}
	return out
}

// TestExplainPolicyHandlerWithoutADataPath pins the one answer a service with no
// live policy runtime can truthfully give: policy routing is off, so everything
// takes the legacy proxy route.
func TestExplainPolicyHandlerWithoutADataPath(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	w := postPolicyExplain(t, h, `{"domain":"www.example"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("explain = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeExplainResponse(t, w)
	if got := out["decision"]; got != "PROXY" {
		t.Errorf("decision = %v, want PROXY", got)
	}
	if got := out["reason"]; got != "policy_disabled" {
		t.Errorf("reason = %v, want policy_disabled", got)
	}
	if got, _ := out["read_only"].(bool); !got {
		t.Error("the answer must declare that it is read-only")
	}
	policyState, ok := out["policy"].(map[string]any)
	if !ok {
		t.Fatalf("policy state missing: %v", out)
	}
	if enabled, _ := policyState["enabled"].(bool); enabled {
		t.Error("the fixture has no live policy runtime, yet the answer reports it enabled")
	}
	resolution, ok := out["resolution"].(map[string]any)
	if !ok || resolution["method"] != "not_attempted" {
		t.Errorf("resolution = %v, want an un-attempted lookup", out["resolution"])
	}
}

// TestExplainPolicyHandlerAcceptsAddresses covers the "either an address or a
// name" contract and proves a caller-supplied address needs no DNS traffic.
func TestExplainPolicyHandlerAcceptsAddresses(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	for _, body := range []string{
		`{"ip":"198.51.200.9"}`,
		`{"ips":["198.51.200.9","198.51.200.10"]}`,
	} {
		w := postPolicyExplain(t, h, body)
		if w.Code != http.StatusOK {
			t.Fatalf("explain %s = %d, want 200; body=%s", body, w.Code, w.Body.String())
		}
		out := decodeExplainResponse(t, w)
		input, ok := out["input"].(map[string]any)
		if !ok || input["kind"] != "address" {
			t.Errorf("input = %v, want kind=address", out["input"])
		}
		resolution, ok := out["resolution"].(map[string]any)
		if !ok || resolution["method"] != "caller_supplied" {
			t.Errorf("resolution = %v, want caller_supplied", out["resolution"])
		}
	}
}

// TestParsePolicyExplainAddresses pins the address-list rules on the pure
// parser: deduplication keeps the request's work proportional to the number of
// distinct destinations, and each rejection names its reason.
func TestParsePolicyExplainAddresses(t *testing.T) {
	addrs, msg := parsePolicyExplainAddresses("198.51.200.9", []string{"198.51.200.9", "198.51.200.10"})
	if msg != "" {
		t.Fatalf("unexpected rejection: %s", msg)
	}
	if len(addrs) != 2 || addrs[0].String() != "198.51.200.9" || addrs[1].String() != "198.51.200.10" {
		t.Fatalf("addresses = %v, want the two distinct addresses in input order", addrs)
	}

	if addrs, msg := parsePolicyExplainAddresses("", nil); len(addrs) != 0 || msg != "" {
		t.Fatalf("empty input = %v/%q, want no addresses and no rejection", addrs, msg)
	}
	if _, msg := parsePolicyExplainAddresses("2001:db8::1", nil); !strings.Contains(msg, "IPv4 only") {
		t.Fatalf("IPv6 rejection = %q, want an IPv4-only reason", msg)
	}
	if _, msg := parsePolicyExplainAddresses("nope", nil); !strings.Contains(msg, "not a valid address") {
		t.Fatalf("malformed rejection = %q", msg)
	}
	nine := []string{"198.51.200.1", "198.51.200.2", "198.51.200.3", "198.51.200.4",
		"198.51.200.5", "198.51.200.6", "198.51.200.7", "198.51.200.8", "198.51.200.9"}
	if _, msg := parsePolicyExplainAddresses("", nine); !strings.Contains(msg, "at most 8 addresses") {
		t.Fatalf("excess rejection = %q", msg)
	}
}

// TestExplainPolicyHandlerRejectsInvalidInput pins that every rejection names
// the offending field instead of collapsing into one generic message.
func TestExplainPolicyHandlerRejectsInvalidInput(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	longLabel := strings.Repeat("a", 64)
	cases := []struct {
		name string
		body string
		want string
	}{
		{"empty body", ``, "empty"},
		{"malformed json", `{"domain":`, "Invalid request body"},
		{"no name and no address", `{}`, "domain name or at least one address is required"},
		{"scheme in name", `{"domain":"https://www.example"}`, "domain:"},
		{"empty label", `{"domain":"a..b"}`, "domain:"},
		{"overlong label", `{"domain":"` + longLabel + `.example"}`, "domain:"},
		{"non-IDNA name", `{"domain":"xn--a.example"}`, "domain:"},
		{"ipv6 address", `{"ips":["2001:db8::1"]}`, "IPv4 only"},
		{"malformed address", `{"ip":"not-an-address"}`, "is not a valid address"},
		{"too many addresses", `{"ips":["198.51.200.1","198.51.200.2","198.51.200.3","198.51.200.4","198.51.200.5","198.51.200.6","198.51.200.7","198.51.200.8","198.51.200.9"]}`, "at most 8 addresses"},
		{"overlong session", `{"domain":"www.example","session_id":"` + strings.Repeat("s", 130) + `"}`, "session_id"},
		{"oversized body", `{"domain":"` + strings.Repeat("a", policyExplainMaxBodyBytes) + `.example"}`, "too large"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postPolicyExplain(t, h, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("body = %s, want it to contain %q", w.Body.String(), tc.want)
			}
		})
	}
}

// TestExplainPolicyHandlerLeavesCountersAndCacheUntouched is the handler-level
// no-side-effect proof: the dispatch counters and the route-cache size read from
// the service are identical before and after a request.
func TestExplainPolicyHandlerLeavesCountersAndCacheUntouched(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	if h.vpnSvc == nil {
		t.Fatal("fixture has no VPN service")
	}

	proxyBefore, directBefore, dropsBefore := h.vpnSvc.PolicyDispatchCounters()
	directDropsBefore := h.vpnSvc.PolicyDirectDrops()
	entriesBefore, sessionsBefore := h.vpnSvc.PolicyRouteCacheSize()

	for _, body := range []string{`{"domain":"www.example"}`, `{"ip":"198.51.200.9"}`} {
		if w := postPolicyExplain(t, h, body); w.Code != http.StatusOK {
			t.Fatalf("explain = %d, want 200; body=%s", w.Code, w.Body.String())
		}
	}

	if got, _, _ := h.vpnSvc.PolicyDispatchCounters(); got != proxyBefore {
		t.Errorf("proxy bytes moved: %d → %d", proxyBefore, got)
	}
	if _, got, _ := h.vpnSvc.PolicyDispatchCounters(); got != directBefore {
		t.Errorf("direct bytes moved: %d → %d", directBefore, got)
	}
	if _, _, got := h.vpnSvc.PolicyDispatchCounters(); got != dropsBefore {
		t.Errorf("proxy drops moved: %d → %d", dropsBefore, got)
	}
	if got := h.vpnSvc.PolicyDirectDrops(); got != directDropsBefore {
		t.Errorf("direct drops moved: %d → %d", directDropsBefore, got)
	}
	if entries, sessions := h.vpnSvc.PolicyRouteCacheSize(); entries != entriesBefore || sessions != sessionsBefore {
		t.Errorf("route-cache size moved: %d/%d → %d/%d", entriesBefore, sessionsBefore, entries, sessions)
	}
}

// TestExplainPolicyHandlerWithoutDataPlane pins the 503 behavior shared with
// the sync endpoint when this deployment has no VPN service.
func TestExplainPolicyHandlerWithoutDataPlane(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	h.vpnSvc = nil

	w := postPolicyExplain(t, h, `{"domain":"www.example"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("explain without a data plane = %d, want 503; body=%s", w.Code, w.Body.String())
	}
}
