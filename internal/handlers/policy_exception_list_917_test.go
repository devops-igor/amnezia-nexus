package handlers

// Regressions for the persisted exception list and the predecessor record, driven
// through the real HTTP handlers over a real temporary SQLite database. Nothing
// here stubs the decode, the merge, the persistence or the runtime call, because
// every defect these cases pin lived in a seam a direct-helper test could not see:
//
//   - the decoder destroyed the difference between an empty list and an absent key
//     before the (correct) merge helper ever ran, so a helper test passed while the
//     API answered 200 and kept the old list;
//   - a predecessor record's mixed list was copied wholesale into an IPv4-only
//     field, so whole-record validation rejected it and the operator's working IPv4
//     policy was lost with the inert domain entry.
//
// The runtime data plane is a fixture device and the durable policy store is a
// temporary directory; the handler, SQLite row, settings decode, IPv4 validation
// and syncer are production code.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// policyListFixtureWAN is a packet device that carries no traffic, so a test can
// activate the real policy path without touching the host.
type policyListFixtureWAN struct{}

func (policyListFixtureWAN) Read([]byte) (int, error)    { return 0, fmt.Errorf("no traffic") }
func (policyListFixtureWAN) Write(b []byte) (int, error) { return len(b), nil }
func (policyListFixtureWAN) Close() error                { return nil }

// newPolicyListFixture builds a handler whose policy store and data plane are
// test-owned but whose settings path is production.
func newPolicyListFixture(t *testing.T) *Handlers {
	t.Helper()
	h, _, cfg := setupTestHandlers(t)
	cfg.DataDir = t.TempDir()
	t.Cleanup(vpn.SetWANDeviceFactoryForTest(func(string) (forwarder.PacketDevice, error) {
		return policyListFixtureWAN{}, nil
	}))
	t.Cleanup(h.vpnSvc.StopPolicyRouting)
	return h
}

// putPolicy sends one real PUT /api/vpn/policy request.
func putPolicy(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.PutPolicyHandler(w, httptest.NewRequest(http.MethodPut, "/api/vpn/policy", strings.NewReader(body)))
	return w
}

// getPolicyRecord sends one real GET /api/vpn/policy request and decodes it.
func getPolicyRecord(t *testing.T, h *Handlers) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	h.GetPolicyHandler(w, httptest.NewRequest(http.MethodGet, "/api/vpn/policy", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/vpn/policy = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode GET body: %v", err)
	}
	return out
}

// storedExceptions reads the durable record the API persists.
func storedExceptions(t *testing.T, h *Handlers) []string {
	t.Helper()
	settings, err := h.policySettingsOrDefault(context.Background())
	if err != nil {
		t.Fatalf("read the stored record: %v", err)
	}
	return settings.ProxyExceptions
}

// TestPutPolicyClearingTheListIsPersistedNotReplaced is the F957-02 regression at
// the API boundary. The shipped controller always sends proxy_exceptions, so the
// only way an operator empties the list is the explicit empty array.
//
// The assertion is on the durable row AND on a re-read through GET, because the
// defect produced a 200 with the old list still installed: a status-code assertion
// alone would have passed the broken build.
func TestPutPolicyClearingTheListIsPersistedNotReplaced(t *testing.T) {
	h := newPolicyListFixture(t)

	seed := putPolicy(t, h, `{"enabled":false,"proxy_exceptions":["203.0.113.0/24"],"sync_interval_seconds":3600}`)
	if seed.Code != http.StatusOK {
		t.Fatalf("seeding the list = %d, want 200; body=%s", seed.Code, seed.Body.String())
	}
	if got := storedExceptions(t, h); len(got) != 1 {
		t.Fatalf("seeded list = %v, want the one entry", got)
	}

	cleared := putPolicy(t, h, `{"enabled":false,"proxy_exceptions":[],"sync_interval_seconds":3600}`)
	if cleared.Code != http.StatusOK {
		t.Fatalf("clearing a disabled record = %d, want 200; body=%s", cleared.Code, cleared.Body.String())
	}
	if got := storedExceptions(t, h); len(got) != 0 {
		t.Fatalf("durable list after clearing = %v; the explicit empty array must persist as an empty list, "+
			"not be replaced by the stored entries", got)
	}

	// A second operator reads the record back: this is what must not show the old
	// entries as if the clear had been applied.
	record := getPolicyRecord(t, h)
	entries, _ := record["proxy_exceptions"].([]any)
	if len(entries) != 0 {
		t.Fatalf("GET after clearing reported %v; the stored record was not actually cleared", record["proxy_exceptions"])
	}

	// An omitted key still means "keep what is stored", so the additive contract a
	// client without the textarea relies on is unchanged.
	seedAgain := putPolicy(t, h, `{"enabled":false,"proxy_exceptions":["198.51.100.0/24"],"sync_interval_seconds":3600}`)
	if seedAgain.Code != http.StatusOK {
		t.Fatalf("re-seeding = %d, want 200; body=%s", seedAgain.Code, seedAgain.Body.String())
	}
	omitted := putPolicy(t, h, `{"enabled":false,"sync_interval_seconds":3600}`)
	if omitted.Code != http.StatusOK {
		t.Fatalf("a save omitting the list = %d, want 200; body=%s", omitted.Code, omitted.Body.String())
	}
	if got := storedExceptions(t, h); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("stored list after an omitting save = %v, want the preserved entry", got)
	}
}

// TestPutPolicyClearingWhileEnabledIsRefusedTruthfully is the enabled half of
// F957-02. Emptying the list while policy routing is on cannot publish a snapshot,
// so the runtime refuses enablement — and that refusal must reach the operator and
// roll the record back. What must never happen is the defect's outcome: HTTP 200
// with the predecessor entries silently reinstalled as if the clear had succeeded.
func TestPutPolicyClearingWhileEnabledIsRefusedTruthfully(t *testing.T) {
	h := newPolicyListFixture(t)

	activated := putPolicy(t, h, `{"enabled":true,"proxy_exceptions":["203.0.113.0/24"],"sync_interval_seconds":3600}`)
	if activated.Code != http.StatusOK {
		t.Fatalf("activating with one exception = %d, want 200; body=%s", activated.Code, activated.Body.String())
	}

	cleared := putPolicy(t, h, `{"enabled":true,"proxy_exceptions":[],"sync_interval_seconds":3600}`)
	if cleared.Code != http.StatusUnprocessableEntity {
		t.Fatalf("clearing while enabled = %d, want the runtime's 422 refusal; body=%s. "+
			"A success here means the old list was substituted for the one the operator submitted",
			cleared.Code, cleared.Body.String())
	}
	// The compensation must leave the previously accepted record in place: the
	// operator's earlier list is still what runs, and the refusal says so.
	if got := storedExceptions(t, h); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("durable list after the refused clear = %v, want the previously accepted entry restored", got)
	}
	if body := cleared.Body.String(); !strings.Contains(body, "activation_failed") {
		t.Fatalf("refusal body = %s, want the activation failure the operator can act on", body)
	}
}

// TestPutPolicyFromMixedPredecessorRowKeepsIPv4Policy is the F957-04 regression. A
// record written by an earlier build could hold domain lines beside prefixes; this
// build routes IPv4 only.
//
// The operator must keep the IPv4 policy that worked, and must be told what could
// not survive. Losing the whole list to a validation error — and thereby losing
// domestic-direct routing — is the defect.
func TestPutPolicyFromMixedPredecessorRowKeepsIPv4Policy(t *testing.T) {
	h := newPolicyListFixture(t)

	// Exactly the stored shape an earlier build wrote: enabled, a source selection,
	// and a mixed list.
	const predecessor = `{"enabled":true,"preset":"aggregate",` +
		`"local_entries":["198.51.100.0/24","example.com"],"sync_interval_seconds":3600}`
	if err := h.db.SetSetting(context.Background(), policy.SettingsKey, json.RawMessage(predecessor)); err != nil {
		t.Fatalf("seed the predecessor row: %v", err)
	}

	record := getPolicyRecord(t, h)
	entries, _ := record["proxy_exceptions"].([]any)
	if len(entries) != 1 {
		t.Fatalf("GET reported proxy_exceptions = %v, want only the surviving IPv4 prefix", record["proxy_exceptions"])
	}
	if got, _ := entries[0].(string); got != "198.51.100.0/24" {
		t.Fatalf("surviving exception = %q, want 198.51.100.0/24", got)
	}

	// The retirement is stated on the surface that shows the record, so the shorter
	// list is explained rather than looking like lost configuration.
	retired, ok := record["retired"].(map[string]any)
	if !ok {
		t.Fatalf("GET did not report what the upgrade could not carry: %v", record)
	}
	nonIPv4, _ := retired["non_ipv4_entries"].([]any)
	if len(nonIPv4) != 1 {
		t.Fatalf("reported non-IPv4 entries = %v, want the one retired line", retired["non_ipv4_entries"])
	}
	if got, _ := nonIPv4[0].(string); got != "example.com" {
		t.Fatalf("reported retired entry = %q, want the stored example.com", got)
	}

	// The record still activates from the surviving IPv4 prefix, which is the
	// behaviour the operator had before the upgrade and must not lose.
	activated := putPolicy(t, h, `{"enabled":true,"proxy_exceptions":["198.51.100.0/24"],"sync_interval_seconds":3600}`)
	if activated.Code != http.StatusOK {
		t.Fatalf("activating the surviving IPv4 policy = %d, want 200; body=%s", activated.Code, activated.Body.String())
	}
	if !h.vpnSvc.PBREnabled() {
		t.Fatal("PBR is off after activating the record's surviving IPv4 prefix")
	}

	// Mixed-row control: an ordinary disable that omits the list must be accepted,
	// not rejected because the stored record still contains a domain line.
	disabled := putPolicy(t, h, `{"enabled":false,"sync_interval_seconds":3600}`)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disabling while the stored row held a retired domain = %d, want 200; body=%s",
			disabled.Code, disabled.Body.String())
	}
}

// TestPutPolicyRefusesAnInvalidListUnderBothKeys is the F957-06 regression, and it
// is deliberately paired.
//
// The same body — one good prefix, one domestic exception with a /33 typo — is
// submitted under the current key and under the predecessor key. Both must be
// refused atomically with nothing persisted, because a request is a request
// whichever alias it uses. A single-sided test cannot show the asymmetry that
// produced the defect: under one key the typo was rejected, and under the other the
// decoder dropped it, so a truncated but valid-looking list was stored with a 200.
//
// The harm of that second outcome is asserted too, not just its cause. The
// destination the dropped entry protected kept matching PROXY before the request;
// after it, the operator's exception is gone while the classifier still calls the
// destination DIRECT, so the traffic leaves direct. The live matcher is therefore
// checked after each refusal, as is the durable row.
func TestPutPolicyRefusesAnInvalidListUnderBothKeys(t *testing.T) {
	const (
		// A documentation prefix plus the domestic exception an operator would add
		// to keep a domestic destination on the proxy path.
		protected = "213.180.192.0/19"
		probe     = "213.180.192.1"
	)

	for _, key := range []string{"proxy_exceptions", "local_entries"} {
		t.Run(key, func(t *testing.T) {
			h := newPolicyListFixture(t)

			seed := `{"enabled":true,"proxy_exceptions":["198.51.100.0/24","` + protected + `"],"sync_interval_seconds":3600}`
			seeded := putPolicy(t, h, seed)
			if seeded.Code != http.StatusOK {
				t.Fatalf("seeding = %d, want 200; body=%s", seeded.Code, seeded.Body.String())
			}
			if got := storedExceptions(t, h); len(got) != 2 {
				t.Fatalf("seeded list = %v, want both accepted prefixes", got)
			}
			if !policyMatcherCovers(t, h, probe) {
				t.Fatalf("the seeded record does not route %s through the exception list; the refusal below would prove nothing", probe)
			}

			// The typo is one ordinary prefix mistake: 192.0/33 does not exist.
			body := `{"enabled":true,"` + key + `":["198.51.100.0/24","213.180.192.0/33"],"sync_interval_seconds":3600}`
			refused := putPolicy(t, h, body)
			if refused.Code != http.StatusBadRequest {
				t.Fatalf("submitting an invalid entry under %q = %d, want 400; body=%s. "+
					"A success here means the decoder dropped the entry instead of the request being refused",
					key, refused.Code, refused.Body.String())
			}
			if got := storedExceptions(t, h); len(got) != 2 || !contains(got, protected) {
				t.Fatalf("durable list after the refused save = %v; the accepted record must survive untouched", got)
			}
			if !policyMatcherCovers(t, h, probe) {
				t.Fatalf("%s no longer matches a PROXY exception after the refused save, so it silently left the operator's proxy path", probe)
			}
			// The operator must learn what was wrong, not just that something was.
			if body := refused.Body.String(); !strings.Contains(body, "proxy exception rejected") {
				t.Fatalf("refusal body = %s, want the exception-list reason", body)
			}
		})
	}
}

// TestPutPolicyEmptyListClearsUnderBothKeys is the other half of the pairing: an
// explicit empty list is a deliberate clear whichever key carries it.
//
// Under the predecessor key the empty array used to decode to nil, which the merge
// step reads as "the save omitted the field" and answers 200 while the old list
// stays installed — a clear that silently did nothing. Asserting only the status
// code would pass the broken build, so the durable row and a re-read through GET
// are both asserted.
func TestPutPolicyEmptyListClearsUnderBothKeys(t *testing.T) {
	for _, key := range []string{"proxy_exceptions", "local_entries"} {
		t.Run(key, func(t *testing.T) {
			h := newPolicyListFixture(t)

			seed := `{"enabled":false,"proxy_exceptions":["203.0.113.0/24"],"sync_interval_seconds":3600}`
			if seeded := putPolicy(t, h, seed); seeded.Code != http.StatusOK {
				t.Fatalf("seeding = %d, want 200; body=%s", seeded.Code, seeded.Body.String())
			}

			cleared := putPolicy(t, h, `{"enabled":false,"`+key+`":[],"sync_interval_seconds":3600}`)
			if cleared.Code != http.StatusOK {
				t.Fatalf("clearing under %q = %d, want 200; body=%s", key, cleared.Code, cleared.Body.String())
			}
			if got := storedExceptions(t, h); len(got) != 0 {
				t.Fatalf("durable list after clearing under %q = %v; an explicit empty list must clear, "+
					"not be merged back from the stored record", key, got)
			}
			record := getPolicyRecord(t, h)
			if entries, _ := record["proxy_exceptions"].([]any); len(entries) != 0 {
				t.Fatalf("GET after clearing under %q reported %v; the record was not actually cleared", key, record["proxy_exceptions"])
			}
		})
	}
}

// contains reports whether list holds want.
func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// policyMatcherCovers reports whether the live policy matcher routes addr through
// the exception list. It reads the running runtime, not the stored record, so a
// save that persisted but failed to activate cannot look correct.
func policyMatcherCovers(t *testing.T, h *Handlers, addr string) bool {
	t.Helper()
	if h.vpnSvc == nil {
		t.Fatal("fixture has no VPN service; the live policy path cannot be observed")
	}
	matcher := h.vpnSvc.PolicyMatcher()
	if matcher == nil {
		return false
	}
	snapshot := matcher.Current()
	if snapshot == nil {
		return false
	}
	return snapshot.MatchIPv4(netip.MustParseAddr(addr))
}

// TestPutPolicyStillRejectsNewlySubmittedDomains is the unchanged half of the
// boundary: the retirement applies to bytes an earlier build already stored. A
// domain line submitted now is still refused, because the field is still IPv4 and
// a control that looks configured must decide something.
func TestPutPolicyStillRejectsNewlySubmittedDomains(t *testing.T) {
	h := newPolicyListFixture(t)

	seed := putPolicy(t, h, `{"enabled":false,"proxy_exceptions":["203.0.113.0/24"],"sync_interval_seconds":3600}`)
	if seed.Code != http.StatusOK {
		t.Fatalf("seeding = %d, want 200; body=%s", seed.Code, seed.Body.String())
	}

	for _, line := range []string{"example.com", "*.example.org", "198.51.100.7/33"} {
		t.Run(line, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"enabled":               false,
				"proxy_exceptions":      []string{line},
				"sync_interval_seconds": 3600,
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			w := putPolicy(t, h, string(body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("submitting %q = %d, want 400; body=%s", line, w.Code, w.Body.String())
			}
			if got := storedExceptions(t, h); len(got) != 1 || got[0] != "203.0.113.0/24" {
				t.Fatalf("a rejected submission changed the stored list to %v", got)
			}
		})
	}
}
