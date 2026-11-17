package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These tests cover the API half of the upstream resolver editor (#865): the
// editor reuses GET and PUT /api/vpn/policy, so what it sends must survive the
// real router, the real validation and the real persistence path unchanged.
//
// The editor echoes the four fields it does not edit from a fresh read, fills in
// nothing on the server's behalf except the transport default ports, and verifies
// the answer. The cases below are the ones the existing #824 matrix does not
// already cover: the field-preservation rule, the `null` versus `[]` versus
// omitted distinction for the list, the silently ignored unknown field that makes
// the answer check necessary, a duplicate entry, the compensation of a refused
// activation, and CSRF.
//
// Not covered here on purpose (already covered by the #824 tests this file does
// not repeat): `[]` resets the record, an omitted list is kept, DoT/DoH default
// ports round-trip, the rejection matrix for loopback/multicast/unspecified/
// malformed/missing-port/unknown-transport/DoH-URL/malformed-pin, non-admin
// roles, and the list surviving a restart.

// editorPayload builds the request body the editor sends: the fresh record's four
// preserved fields plus the edited list.
func editorPayload(t *testing.T, record map[string]any, upstreams any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"enabled":               record["enabled"],
		"preset":                record["preset"],
		"custom_urls":           record["custom_urls"],
		"sync_interval_seconds": record["sync_interval_seconds"],
		"upstream_dns":          upstreams,
	})
	if err != nil {
		t.Fatalf("marshal editor payload: %v", err)
	}
	return body
}

func readStoredPolicy(t *testing.T, db *database.DB) policy.Settings {
	t.Helper()
	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		t.Fatalf("read stored policy settings: %v", err)
	}
	return stored
}

// TestEditorShapedPutPreservesTheOtherRecordFields is the central editor
// contract: the PUT replaces the whole record, so the fields the editor does not
// edit must come back byte-equal from the fresh read it echoed them from.
func TestEditorShapedPutPreservesTheOtherRecordFields(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	seed := policy.DefaultSettings()
	seed.Preset = policy.PresetGeoblock
	seed.SyncInterval = 7200
	seed.UpstreamDNS = []policy.Upstream{{Address: "94.140.14.14", Port: 53, Transport: policy.TransportPlain}}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, seed); err != nil {
		t.Fatalf("seed the stored record: %v", err)
	}

	// What the editor does first: read the stored record.
	wGet := httptest.NewRecorder()
	r.ServeHTTP(wGet, adminRequest(t, http.MethodGet, "/api/vpn/policy", nil))
	if wGet.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200; body=%s", wGet.Code, wGet.Body.String())
	}
	fresh := decodeJSON(t, wGet)
	if enabled, _ := fresh["enabled"].(bool); enabled {
		t.Fatalf("seeded record unexpectedly reports enabled=true")
	}

	pin := "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
	body := editorPayload(t, fresh, []map[string]any{
		{"address": "dns.example.com", "transport": "dot", "spki_pin": pin},
		{"address": "dns.example.net", "transport": "doh"},
	})
	wPut := httptest.NewRecorder()
	r.ServeHTTP(wPut, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if wPut.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200; body=%s", wPut.Code, wPut.Body.String())
	}

	stored := readStoredPolicy(t, db)
	if stored.Enabled != seed.Enabled {
		t.Errorf("enabled = %v, want the echoed %v", stored.Enabled, seed.Enabled)
	}
	if stored.Preset != seed.Preset {
		t.Errorf("preset = %q, want the echoed %q", stored.Preset, seed.Preset)
	}
	if len(stored.CustomURLs) != len(seed.CustomURLs) {
		t.Errorf("custom_urls = %v, want the echoed %v", stored.CustomURLs, seed.CustomURLs)
	}
	if stored.SyncInterval != 7200 {
		t.Errorf("sync_interval_seconds = %d, want the echoed 7200", stored.SyncInterval)
	}

	want := []policy.Upstream{
		{Address: "dns.example.com", Port: policy.DefaultDoTPort, Transport: policy.TransportDoT, SPKIPin: pin},
		{Address: "dns.example.net", Port: policy.DefaultDoHPort, Transport: policy.TransportDoH},
	}
	if len(stored.UpstreamDNS) != len(want) {
		t.Fatalf("stored upstreams = %v, want %v", stored.UpstreamDNS, want)
	}
	for i := range want {
		if stored.UpstreamDNS[i] != want[i] {
			t.Errorf("stored upstream %d = %+v, want %+v", i, stored.UpstreamDNS[i], want[i])
		}
	}

	// The answer is a normalized record the editor verifies: explicit ports and the
	// pin it sent.
	answer := decodeJSON(t, wPut)
	if status, _ := answer["status"].(string); status != "ok" {
		t.Errorf("PUT answer status = %v, want \"ok\"", answer["status"])
	}
	rawUpstreams, ok := answer["upstream_dns"].([]any)
	if !ok || len(rawUpstreams) != len(want) {
		t.Fatalf("PUT answer upstream_dns = %v, want %d entries", answer["upstream_dns"], len(want))
	}
	first, _ := rawUpstreams[0].(map[string]any)
	if port, _ := first["port"].(float64); int(port) != policy.DefaultDoTPort {
		t.Errorf("PUT answer port = %v, want the filled default %d", first["port"], policy.DefaultDoTPort)
	}
	if gotPin, _ := first["spki_pin"].(string); gotPin != pin {
		t.Errorf("PUT answer spki_pin = %v, want the sent pin", first["spki_pin"])
	}
	if transport, _ := first["transport"].(string); transport != string(policy.TransportDoT) {
		t.Errorf("PUT answer transport = %v, want %q", first["transport"], policy.TransportDoT)
	}
}

// TestEditorSaveWithoutSelectedPresetIsRefused pins the editor's own precondition
// on the server side as well: a record with no list source cannot be saved, and
// the stored record is left alone.
func TestEditorSaveWithoutSelectedPresetIsRefused(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	seed := policy.DefaultSettings()
	seed.Preset = policy.PresetGeoblock
	seed.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, seed); err != nil {
		t.Fatalf("seed the stored record: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"enabled":               false,
		"preset":                "",
		"custom_urls":           []string{},
		"sync_interval_seconds": 21600,
		"upstream_dns":          []map[string]any{{"address": "8.8.8.8", "transport": "plain", "port": 53}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT without a preset = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	out := decodeJSON(t, w)
	if detail, _ := out["detail"].(string); !strings.Contains(detail, "preset must be selected") {
		t.Errorf("refusal detail = %q, want the preset rule", detail)
	}

	stored := readStoredPolicy(t, db)
	if stored.Preset != policy.PresetGeoblock {
		t.Errorf("a refused save changed the stored preset to %q", stored.Preset)
	}
	if len(stored.UpstreamDNS) != 1 || stored.UpstreamDNS[0].Address != "9.9.9.9" {
		t.Errorf("a refused save changed the stored upstreams: %v", stored.UpstreamDNS)
	}
}

// TestNullUpstreamListKeepsTheStoredList is the third value the editor must never
// send but the server must still handle: `null` is "keep the stored list", the same
// as omitting the field, and different from the explicit reset `[]`.
func TestNullUpstreamListKeepsTheStoredList(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	seed := policy.DefaultSettings()
	seed.Preset = policy.PresetGeoblock
	seed.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, seed); err != nil {
		t.Fatalf("seed the stored record: %v", err)
	}

	body := []byte(`{"enabled":false,"preset":"geoblock","custom_urls":[],"sync_interval_seconds":21600,"upstream_dns":null}`)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT with a null list = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	stored := readStoredPolicy(t, db)
	if len(stored.UpstreamDNS) != 1 || stored.UpstreamDNS[0].Address != "9.9.9.9" {
		t.Fatalf("a null list erased the stored upstreams: %v", stored.UpstreamDNS)
	}
}

// TestUnknownUpstreamFieldIsIgnoredSilently documents why the editor verifies the
// answer. The server decodes non-strictly, so a misspelled pin key is dropped
// without an error and the row is stored without its pin.
func TestUnknownUpstreamFieldIsIgnoredSilently(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	seed := policy.DefaultSettings()
	seed.Preset = policy.PresetGeoblock
	if err := db.SetSetting(context.Background(), policy.SettingsKey, seed); err != nil {
		t.Fatalf("seed the stored record: %v", err)
	}

	body := []byte(`{"enabled":false,"preset":"geoblock","custom_urls":[],"sync_interval_seconds":21600,` +
		`"upstream_dns":[{"address":"dns.example.com","transport":"dot","spki-pin":"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="}]}`)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT with a misspelled field = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	stored := readStoredPolicy(t, db)
	if len(stored.UpstreamDNS) != 1 {
		t.Fatalf("stored upstreams = %v, want the one row", stored.UpstreamDNS)
	}
	if stored.UpstreamDNS[0].SPKIPin != "" {
		t.Fatalf("the misspelled pin was somehow stored: %q", stored.UpstreamDNS[0].SPKIPin)
	}
	// The response therefore differs from what a naive client sent, which is exactly
	// what the editor's field-by-field answer check catches.
	answer := decodeJSON(t, w)
	rawUpstreams, _ := answer["upstream_dns"].([]any)
	first, _ := rawUpstreams[0].(map[string]any)
	if _, present := first["spki_pin"]; present {
		t.Errorf("the answer reports a pin the server did not store: %v", first["spki_pin"])
	}
}

// TestDuplicateUpstreamEntriesRefused fills the one gap in the #824 rejection
// matrix the editor's own duplicate check mirrors.
func TestDuplicateUpstreamEntriesRefused(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	seed := policy.DefaultSettings()
	seed.Preset = policy.PresetGeoblock
	seed.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, seed); err != nil {
		t.Fatalf("seed the stored record: %v", err)
	}

	body := []byte(`{"enabled":false,"preset":"geoblock","custom_urls":[],"sync_interval_seconds":21600,` +
		`"upstream_dns":[{"address":"dns.example.com","transport":"dot"},{"address":"DNS.example.com","transport":"dot"}]}`)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT with a duplicate entry = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	out := decodeJSON(t, w)
	if detail, _ := out["detail"].(string); !strings.Contains(detail, "duplicates an earlier entry") {
		t.Errorf("refusal detail = %q, want the duplicate rule", detail)
	}

	stored := readStoredPolicy(t, db)
	if len(stored.UpstreamDNS) != 1 || stored.UpstreamDNS[0].Address != "9.9.9.9" {
		t.Errorf("a refused save changed the stored upstreams: %v", stored.UpstreamDNS)
	}
}

// TestEditorSaveRollsBackRefusedActivation is the effect the editor warns about:
// on a deployment without a data plane, a save that would enable policy routing is
// refused and the previous record is restored, upstream list included.
func TestEditorSaveRollsBackRefusedActivation(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	// No VPN service: NewRouter's third argument stays nil, which is the
	// panel-management deployment this contract is written for.
	r := NewRouter(cfg, db, nil)

	seed := policy.DefaultSettings()
	seed.Preset = policy.PresetGeoblock
	seed.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, seed); err != nil {
		t.Fatalf("seed the stored record: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"enabled":               true,
		"preset":                string(policy.PresetGeoblock),
		"custom_urls":           []string{},
		"sync_interval_seconds": 21600,
		"upstream_dns":          []map[string]any{{"address": "dns.example.com", "transport": "dot"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("PUT enablement without a data plane = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	out := decodeJSON(t, w)
	if detail, _ := out["detail"].(string); !strings.Contains(detail, "data plane") {
		t.Errorf("refusal detail = %q, want the data-plane reason", detail)
	}

	stored := readStoredPolicy(t, db)
	if stored.Enabled {
		t.Error("a refused activation left enabled=true in the stored record")
	}
	if len(stored.UpstreamDNS) != 1 || stored.UpstreamDNS[0].Address != "9.9.9.9" {
		t.Errorf("the compensation did not restore the previous upstream list: %v", stored.UpstreamDNS)
	}
}

// TestEditorPutRequiresCSRF keeps the editor's write path behind the same CSRF
// rule as the rest of the admin API: the shared client adds the header, so a
// request without it must not mutate the record.
func TestEditorPutRequiresCSRF(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	seed := policy.DefaultSettings()
	seed.Preset = policy.PresetGeoblock
	seed.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, seed); err != nil {
		t.Fatalf("seed the stored record: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"enabled":               false,
		"preset":                string(policy.PresetGeoblock),
		"custom_urls":           []string{},
		"sync_interval_seconds": 21600,
		"upstream_dns":          []map[string]any{{"address": "8.8.8.8", "transport": "plain", "port": 53}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// An admin session, but no CSRF cookie/header pair.
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/policy", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := middleware.WithSession(req.Context(), &models.SessionData{UserID: "policy-admin", Role: models.RoleAdmin})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("PUT without CSRF = %d, want 403; body=%s", w.Code, w.Body.String())
	}

	stored := readStoredPolicy(t, db)
	if len(stored.UpstreamDNS) != 1 || stored.UpstreamDNS[0].Address != "9.9.9.9" {
		t.Errorf("a CSRF-less request changed the stored upstreams: %v", stored.UpstreamDNS)
	}
}

// TestEditorFourthUpstreamIsRefused pins the API bound the editor mirrors. The
// stored list holds at most three entries (policy.MaxUpstreams) while the
// resolver queries only the first two, so the editor admits all three and a
// fourth is refused by the server with the stored record left alone.
func TestEditorFourthUpstreamIsRefused(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	seed := policy.DefaultSettings()
	seed.Preset = policy.PresetGeoblock
	seed.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, seed); err != nil {
		t.Fatalf("seed the stored record: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"enabled":               false,
		"preset":                string(policy.PresetGeoblock),
		"custom_urls":           []string{},
		"sync_interval_seconds": 21600,
		"upstream_dns": []map[string]any{
			{"address": "dns.example.com", "transport": "dot"},
			{"address": "dns.example.net", "transport": "doh"},
			{"address": "8.8.8.8", "transport": "plain", "port": 53},
			{"address": "1.1.1.1", "transport": "plain", "port": 53},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT with four upstreams = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	out := decodeJSON(t, w)
	if detail, _ := out["detail"].(string); !strings.Contains(detail, "exceed the maximum") {
		t.Errorf("refusal detail = %q, want the maximum-entries rule", detail)
	}

	stored := readStoredPolicy(t, db)
	if len(stored.UpstreamDNS) != 1 || stored.UpstreamDNS[0].Address != "9.9.9.9" {
		t.Errorf("a refused save changed the stored upstreams: %v", stored.UpstreamDNS)
	}
}
