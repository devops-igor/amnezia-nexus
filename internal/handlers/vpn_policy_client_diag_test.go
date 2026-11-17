package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Transport-level coverage for the per-client diagnosis endpoints (issue #861).
//
// Authorization is asserted where it is enforced — through the real router, in
// internal/router/client_diag_861_test.go. These cases cover the HTTP contract:
// body bounds, the specific refusals, and the exact wire shape the shipped UI
// consumes. The record-producing chain (DNS answer -> cache, client packet ->
// flow) is exercised in internal/vpn/vpn_pbr_client_diag_test.go, because it
// needs the real data path; this fixture has no VPN data plane, so the truthful
// answer here is "policy routing is off".

func postClientDiagnosis(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/vpn/policy/client-diagnosis", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClientDiagnosisHandler(w, req)
	return w
}

func getClientDiagnosisClients(t *testing.T, h *Handlers) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/vpn/policy/clients", nil)
	w := httptest.NewRecorder()
	h.ClientDiagnosisClientsHandler(w, req)
	return w
}

func decodeClientDiagnosisBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode (status %d): %v; body=%s", w.Code, err, w.Body.String())
	}
	return out
}

// TestClientDiagnosisHandlerPolicyDisabledOnADataPathlessService pins the one
// answer this fixture can truthfully give, with every section present.
func TestClientDiagnosisHandlerPolicyDisabledOnADataPathlessService(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	w := postClientDiagnosis(t, h, `{"session_id":"sess-abc"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("client-diagnosis = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeClientDiagnosisBody(t, w)

	selection, ok := out["selection"].(map[string]any)
	if !ok {
		t.Fatalf("selection missing: %s", w.Body.String())
	}
	if selection["state"] != "policy_disabled" {
		t.Errorf("selection.state = %v, want policy_disabled", selection["state"])
	}
	if selection["session_id"] != "sess-abc" {
		t.Errorf("selection.session_id = %v, want the requested id echoed", selection["session_id"])
	}
	if readOnly, _ := out["read_only"].(bool); !readOnly {
		t.Error("the answer must declare that it is read-only")
	}
	for _, section := range []string{"coverage", "dns", "flows", "drops"} {
		if _, ok := out[section].(map[string]any); !ok {
			t.Errorf("section %q is missing from the answer", section)
		}
	}
	// Every list is an array, never null: the UI iterates unconditionally.
	for _, section := range []string{"dns", "flows", "drops"} {
		block := out[section].(map[string]any)
		if _, ok := block["entries"].([]any); !ok {
			t.Errorf("%s.entries is %T, want an array", section, block["entries"])
		}
	}
	if limitations, ok := out["limitations"].([]any); !ok || len(limitations) == 0 {
		t.Errorf("limitations = %v, want a non-empty list", out["limitations"])
	}
	// The DNS section carries both halves of the answer with final shapes: the
	// retained evidence and the observed-answer history.
	dns, ok := out["dns"].(map[string]any)
	if !ok {
		t.Fatalf("dns section missing: %s", w.Body.String())
	}
	for _, key := range []string{"entries", "records"} {
		if _, ok := dns[key].([]any); !ok {
			t.Errorf("dns.%s is %T, want an array", key, dns[key])
		}
	}
	if available, _ := dns["records_available"].(bool); available {
		t.Error("a service without a policy runtime cannot report an available DNS collector")
	}
	flows, ok := out["flows"].(map[string]any)
	if !ok {
		t.Fatalf("flows section missing: %s", w.Body.String())
	}
	if _, ok := flows["entries"].([]any); !ok {
		t.Errorf("flows.entries is %T, want an array", flows["entries"])
	}
	for _, key := range []string{"scanned", "scan_complete", "total", "truncated"} {
		if _, ok := flows[key]; !ok {
			t.Errorf("flows is missing %q", key)
		}
	}

	recordCoverage, ok := dns["record_coverage"].(map[string]any)
	if !ok {
		t.Fatalf("dns.record_coverage missing: %s", w.Body.String())
	}
	// The per-store gap list is an array and it is empty. The facts that used to be listed
	// here — a failed answer, a non-answer query, the transport, the query receipt instant —
	// are recorded by the query history of the same panel, so claiming them as gaps of this
	// store would be a claim the answer cannot keep.
	if gaps, ok := recordCoverage["not_recorded"].([]any); !ok {
		t.Errorf("record coverage not_recorded is %T, want an array", recordCoverage["not_recorded"])
	} else if len(gaps) != 0 {
		t.Errorf("record coverage claims gaps the query history records: %v", gaps)
	}
	// The unavailable half is stated explicitly, not only by an empty list.
	if state, _ := dns["state"].(string); state != "not_recorded" {
		t.Errorf("dns.state = %v, want the explicit not_recorded token", dns["state"])
	}
	// The global coverage still discloses what this build genuinely cannot state, so an
	// empty history is never read as "this client asked nothing".
	globalCoverage, ok := out["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("coverage section missing: %s", w.Body.String())
	}
	if notCovered, ok := globalCoverage["not_covered"].([]any); !ok || len(notCovered) == 0 {
		t.Errorf("coverage.not_covered = %v, want the facts no store retains", globalCoverage["not_covered"])
	}
	if notRecorded, ok := globalCoverage["not_recorded"].([]any); !ok || len(notRecorded) == 0 {
		t.Errorf("coverage.not_recorded = %v, want the remaining not-recorded fact", globalCoverage["not_recorded"])
	}
	if evaluated, _ := out["evaluated_at"].(string); evaluated == "" {
		t.Error("evaluated_at must be present")
	}
}

// TestClientDiagnosisHandlerRejectsBadBodies pins each refusal specifically:
// a generic message would hide which field the caller got wrong.
func TestClientDiagnosisHandlerRejectsBadBodies(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	cases := []struct {
		name    string
		body    string
		wantSub string
	}{
		{"EmptyBody", ``, "empty"},
		{"InvalidJSON", `{"session_id":`, "Invalid request body"},
		{"MissingSessionID", `{}`, "session_id is required"},
		{"BlankSessionID", `{"session_id":"   "}`, "session_id is required"},
		{"SessionIDTooLong", `{"session_id":"` + strings.Repeat("a", 129) + `"}`, "longer than 128"},
		{"BodyTooLarge", `{"session_id":"x","padding":"` + strings.Repeat("p", clientDiagnosisMaxBodyBytes) + `"}`, "too large"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postClientDiagnosis(t, h, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			out := decodeClientDiagnosisBody(t, w)
			if out["error"] != "validation_failed" {
				t.Errorf("error = %v, want validation_failed", out["error"])
			}
			detail, _ := out["detail"].(string)
			if !strings.Contains(detail, tc.wantSub) {
				t.Errorf("detail = %q, want it to contain %q", detail, tc.wantSub)
			}
		})
	}
}

// TestClientDiagnosisHandlerEchoesTheRequestedGeneration pins that an optional
// route generation travels through the transport as a pin rather than being
// dropped or coerced.
func TestClientDiagnosisHandlerEchoesTheRequestedGeneration(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	w := postClientDiagnosis(t, h, `{"session_id":"sess-abc","route_generation":7}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	selection := decodeClientDiagnosisBody(t, w)["selection"].(map[string]any)
	if got, ok := selection["requested_route_generation"].(float64); !ok || got != 7 {
		t.Errorf("requested_route_generation = %v, want 7", selection["requested_route_generation"])
	}
}

// TestClientDiagnosisClientsHandlerEmptyPicker pins the picker's empty state: it
// is an empty array with the coverage tokens, not an error and not null.
func TestClientDiagnosisClientsHandlerEmptyPicker(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	w := getClientDiagnosisClients(t, h)
	if w.Code != http.StatusOK {
		t.Fatalf("clients = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeClientDiagnosisBody(t, w)
	clients, ok := out["clients"].([]any)
	if !ok {
		t.Fatalf("clients = %T, want an array", out["clients"])
	}
	if len(clients) != 0 {
		t.Errorf("clients = %d, want none on a data-pathless service", len(clients))
	}
	if readOnly, _ := out["read_only"].(bool); !readOnly {
		t.Error("the picker must declare that it is read-only")
	}
	if sampled, _ := out["sampled_at"].(string); sampled == "" {
		t.Error("sampled_at must be present")
	}
	if covered, ok := out["not_covered"].([]any); !ok || len(covered) == 0 {
		t.Errorf("not_covered = %v, want the facts no store retains", out["not_covered"])
	}
}

// TestClientDiagnosisHandlersWithoutAService pins the 503 both endpoints return
// when the process has no VPN service at all.
func TestClientDiagnosisHandlersWithoutAService(t *testing.T) {
	h := &Handlers{}

	if w := postClientDiagnosis(t, h, `{"session_id":"sess-abc"}`); w.Code != http.StatusServiceUnavailable {
		t.Errorf("post without a service = %d, want 503", w.Code)
	}
	if w := getClientDiagnosisClients(t, h); w.Code != http.StatusServiceUnavailable {
		t.Errorf("clients without a service = %d, want 503", w.Code)
	}
}

// TestBuildClientDiagnosisRequest pins the pure validation rules, including the
// difference between an omitted generation and generation zero.
func TestBuildClientDiagnosisRequest(t *testing.T) {
	zero := uint64(0)
	got, rejection := buildClientDiagnosisRequest(clientDiagnosisBody{SessionID: " sess-1 ", RouteGeneration: &zero})
	if rejection != "" {
		t.Fatalf("unexpected rejection: %s", rejection)
	}
	if got.SessionID != "sess-1" {
		t.Errorf("session id = %q, want the trimmed value", got.SessionID)
	}
	if !got.HasRouteGeneration || got.RouteGeneration != 0 {
		t.Errorf("generation = %d/%v, want an explicit generation zero", got.RouteGeneration, got.HasRouteGeneration)
	}

	if got, rejection := buildClientDiagnosisRequest(clientDiagnosisBody{SessionID: "sess-1"}); rejection != "" || got.HasRouteGeneration {
		t.Errorf("omitted generation = %+v/%q, want no pin", got, rejection)
	}
	if _, rejection := buildClientDiagnosisRequest(clientDiagnosisBody{}); !strings.Contains(rejection, "session_id is required") {
		t.Errorf("missing session rejection = %q", rejection)
	}
}
