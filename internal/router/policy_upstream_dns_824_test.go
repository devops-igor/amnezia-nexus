package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These tests cover the #824 slice-1 API contract: the upstream list travels
// through the existing policy settings endpoints, an invalid entry is refused
// with a specific error and nothing is persisted, and the stored list survives a
// restart.

// TestPolicyUpstreamDNSRoundTripSurvivesRestart saves a list through the API and
// reads it back from a fresh router over the same database.
func TestPolicyUpstreamDNSRoundTripSurvivesRestart(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	saved := policy.DefaultSettings()
	saved.Preset = policy.PresetGeoblock
	saved.UpstreamDNS = []policy.Upstream{
		{Address: "94.140.14.14", Port: 53, Transport: policy.TransportPlain},
		{Address: "2001:4860:4860::8888", Port: 53},
		{Address: "dns.example.com", Port: 5353},
	}
	body, err := json.Marshal(saved)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wSave := httptest.NewRecorder()
	r.ServeHTTP(wSave, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if wSave.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200; body=%s", wSave.Code, wSave.Body.String())
	}

	// The durable row carries the list.
	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		t.Fatalf("read stored settings: %v", err)
	}
	if len(stored.UpstreamDNS) != len(saved.UpstreamDNS) {
		t.Fatalf("stored upstreams = %v, want %v", stored.UpstreamDNS, saved.UpstreamDNS)
	}
	for i := range saved.UpstreamDNS {
		if stored.UpstreamDNS[i] != saved.UpstreamDNS[i] {
			t.Fatalf("stored upstream %d = %+v, want %+v", i, stored.UpstreamDNS[i], saved.UpstreamDNS[i])
		}
	}

	// "Restart": a new router over the same database, as a process restart gives.
	r2 := NewRouter(cfg, db, nil)
	wGet := httptest.NewRecorder()
	r2.ServeHTTP(wGet, adminRequest(t, http.MethodGet, "/api/vpn/policy", nil))
	if wGet.Code != http.StatusOK {
		t.Fatalf("GET after restart = %d, want 200", wGet.Code)
	}
	out := decodeJSON(t, wGet)
	rawUpstreams, ok := out["upstream_dns"].([]any)
	if !ok {
		t.Fatalf("GET after restart has no upstream_dns array: %s", wGet.Body.String())
	}
	if len(rawUpstreams) != len(saved.UpstreamDNS) {
		t.Fatalf("upstream_dns after restart = %v, want %d entries", rawUpstreams, len(saved.UpstreamDNS))
	}
	for i, raw := range rawUpstreams {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("upstream_dns[%d] = %v, want an object", i, raw)
		}
		if address, _ := entry["address"].(string); address != saved.UpstreamDNS[i].Address {
			t.Fatalf("upstream_dns[%d].address = %v, want %q", i, entry["address"], saved.UpstreamDNS[i].Address)
		}
		if port, _ := entry["port"].(float64); int(port) != saved.UpstreamDNS[i].Port {
			t.Fatalf("upstream_dns[%d].port = %v, want %d", i, entry["port"], saved.UpstreamDNS[i].Port)
		}
	}
}

// TestPolicyUpstreamDNSRejectedEntriesAreNotPersisted walks every rejection rule
// through the API and checks the stored record is untouched.
func TestPolicyUpstreamDNSRejectedEntriesAreNotPersisted(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	// Store a known-good record with one upstream first.
	good := policy.DefaultSettings()
	good.Preset = policy.PresetGeoblock
	good.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	goodBody, err := json.Marshal(good)
	if err != nil {
		t.Fatalf("marshal good settings: %v", err)
	}
	wGood := httptest.NewRecorder()
	r.ServeHTTP(wGood, adminRequest(t, http.MethodPut, "/api/vpn/policy", goodBody))
	if wGood.Code != http.StatusOK {
		t.Fatalf("PUT valid settings = %d, want 200; body=%s", wGood.Code, wGood.Body.String())
	}

	invalid := []struct {
		name       string
		upstreams  []policy.Upstream
		wantSubstr string
	}{
		{
			name:       "loopback",
			upstreams:  []policy.Upstream{{Address: "127.0.0.1", Port: 53}},
			wantSubstr: "loopback",
		},
		{
			name:       "multicast",
			upstreams:  []policy.Upstream{{Address: "224.0.0.1", Port: 53}},
			wantSubstr: "multicast",
		},
		{
			name:       "unspecified",
			upstreams:  []policy.Upstream{{Address: "0.0.0.0", Port: 53}},
			wantSubstr: "unspecified",
		},
		{
			name:       "malformed address",
			upstreams:  []policy.Upstream{{Address: "300.1.1.1", Port: 53}},
			wantSubstr: "not a valid IP literal",
		},
		{
			name:       "malformed hostname",
			upstreams:  []policy.Upstream{{Address: "bad host.example.com", Port: 53}},
			wantSubstr: "not a valid hostname",
		},
		{
			name:       "missing port",
			upstreams:  []policy.Upstream{{Address: "9.9.9.9"}},
			wantSubstr: "explicit port",
		},
		{
			name: "too many entries",
			upstreams: []policy.Upstream{
				{Address: "9.9.9.9", Port: 53},
				{Address: "8.8.8.8", Port: 53},
				{Address: "1.1.1.1", Port: 53},
				{Address: "8.8.4.4", Port: 53},
			},
			wantSubstr: "exceed the maximum",
		},
		{
			name:       "unknown transport",
			upstreams:  []policy.Upstream{{Address: "9.9.9.9", Port: 53, Transport: "tls"}},
			wantSubstr: "unknown transport",
		},
		{
			name:       "doh url instead of a host",
			upstreams:  []policy.Upstream{{Address: "https://dns.example.com/dns-query", Port: 443, Transport: policy.TransportDoH}},
			wantSubstr: "not a bare host",
		},
		{
			name:       "doh loopback",
			upstreams:  []policy.Upstream{{Address: "127.0.0.1", Port: 443, Transport: policy.TransportDoH}},
			wantSubstr: "loopback",
		},
		{
			name:       "pin on a plaintext entry",
			upstreams:  []policy.Upstream{{Address: "9.9.9.9", Port: 53, SPKIPin: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
			wantSubstr: "only honored by the encrypted transports",
		},
		{
			name:       "malformed pin",
			upstreams:  []policy.Upstream{{Address: "9.9.9.9", Transport: policy.TransportDoT, SPKIPin: "not a pin"}},
			wantSubstr: "not valid standard base64",
		},
	}

	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"enabled":               false,
				"preset":                string(policy.PresetGeoblock),
				"sync_interval_seconds": good.SyncInterval,
				"upstream_dns":          tc.upstreams,
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("PUT invalid upstreams (%s) = %d, want 400; body=%s", tc.name, w.Code, w.Body.String())
			}
			out := decodeJSON(t, w)
			detail, _ := out["detail"].(string)
			if detail == "" {
				detail = w.Body.String()
			}
			if !strings.Contains(detail, tc.wantSubstr) {
				t.Fatalf("rejection detail %q does not mention %q", detail, tc.wantSubstr)
			}

			// Nothing was persisted: the good list is still the stored one.
			var stored policy.Settings
			if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
				t.Fatalf("read stored settings: %v", err)
			}
			if len(stored.UpstreamDNS) != 1 || stored.UpstreamDNS[0] != good.UpstreamDNS[0] {
				t.Fatalf("rejected request changed the stored upstreams: %+v", stored.UpstreamDNS)
			}
		})
	}
}

// TestPolicyUpstreamDoTSavedWithDefaultPort is the DoT API contract: the entry
// is accepted, its transport and pin survive the round trip, and the default
// port is written out explicitly rather than left implicit in the record.
func TestPolicyUpstreamDoTSavedWithDefaultPort(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	pin := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("*", 32)))
	body, err := json.Marshal(map[string]any{
		"enabled":               false,
		"preset":                string(policy.PresetGeoblock),
		"sync_interval_seconds": 3600,
		"upstream_dns": []map[string]any{
			{"address": "94.140.14.14", "transport": "dot", "spki_pin": pin},
			{"address": "94.140.15.15", "port": 8853, "transport": "dot"},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT DoT settings = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		t.Fatalf("read stored settings: %v", err)
	}
	want := []policy.Upstream{
		{Address: "94.140.14.14", Port: policy.DefaultDoTPort, Transport: policy.TransportDoT, SPKIPin: pin},
		{Address: "94.140.15.15", Port: 8853, Transport: policy.TransportDoT},
	}
	if len(stored.UpstreamDNS) != len(want) {
		t.Fatalf("stored upstreams = %v, want %v", stored.UpstreamDNS, want)
	}
	for i := range want {
		if stored.UpstreamDNS[i] != want[i] {
			t.Fatalf("stored upstream %d = %+v, want %+v", i, stored.UpstreamDNS[i], want[i])
		}
	}
	if err := stored.Validate(); err != nil {
		t.Fatalf("stored DoT record does not validate: %v", err)
	}

	// The read path reports the same explicit list.
	wGet := httptest.NewRecorder()
	r.ServeHTTP(wGet, adminRequest(t, http.MethodGet, "/api/vpn/policy", nil))
	out := decodeJSON(t, wGet)
	rawUpstreams, ok := out["upstream_dns"].([]any)
	if !ok || len(rawUpstreams) != len(want) {
		t.Fatalf("GET upstream_dns = %v, want %d entries", out["upstream_dns"], len(want))
	}
	entry, ok := rawUpstreams[0].(map[string]any)
	if !ok {
		t.Fatalf("GET upstream_dns[0] = %v, want an object", rawUpstreams[0])
	}
	if transport, _ := entry["transport"].(string); transport != string(policy.TransportDoT) {
		t.Fatalf("GET upstream_dns[0].transport = %v, want %q", entry["transport"], policy.TransportDoT)
	}
	if port, _ := entry["port"].(float64); int(port) != policy.DefaultDoTPort {
		t.Fatalf("GET upstream_dns[0].port = %v, want %d", entry["port"], policy.DefaultDoTPort)
	}
	if gotPin, _ := entry["spki_pin"].(string); gotPin != pin {
		t.Fatalf("GET upstream_dns[0].spki_pin = %v, want %q", entry["spki_pin"], pin)
	}
}

// TestPolicyUpstreamDNSDefaultsWhenFieldAbsent keeps an existing record working:
// a stored record without the field reports an empty array and the effective
// default pair, not a broken resolver.
func TestPolicyUpstreamDNSDefaultsWhenFieldAbsent(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	legacy := `{"enabled":false,"preset":"geoblock","custom_urls":[],"sync_interval_seconds":3600}`
	if err := db.SetSetting(context.Background(), policy.SettingsKey, json.RawMessage(legacy)); err != nil {
		t.Fatalf("store legacy record: %v", err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodGet, "/api/vpn/policy", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeJSON(t, w)
	rawUpstreams, ok := out["upstream_dns"].([]any)
	if !ok {
		t.Fatalf("GET has no upstream_dns array: %s", w.Body.String())
	}
	if len(rawUpstreams) != 0 {
		t.Fatalf("legacy record reported %d upstreams, want an empty list", len(rawUpstreams))
	}
}

// TestPolicyUpstreamDNSSurvivesFormSaveWithoutField is F824-02: the existing
// policy form posts only enabled, preset, custom_urls and sync_interval_seconds.
// Such a save must keep the stored upstream list instead of erasing it.
func TestPolicyUpstreamDNSSurvivesFormSaveWithoutField(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	chosen := policy.DefaultSettings()
	chosen.Preset = policy.PresetGeoblock
	chosen.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	seed, err := json.Marshal(chosen)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wSeed := httptest.NewRecorder()
	r.ServeHTTP(wSeed, adminRequest(t, http.MethodPut, "/api/vpn/policy", seed))
	if wSeed.Code != http.StatusOK {
		t.Fatalf("seed PUT = %d, want 200; body=%s", wSeed.Code, wSeed.Body.String())
	}

	// The exact payload shape the current policy form sends: no upstream_dns.
	form := []byte(`{"enabled":false,"preset":"geoblock","custom_urls":[],"sync_interval_seconds":7200}`)
	wForm := httptest.NewRecorder()
	r.ServeHTTP(wForm, adminRequest(t, http.MethodPut, "/api/vpn/policy", form))
	if wForm.Code != http.StatusOK {
		t.Fatalf("form PUT = %d, want 200; body=%s", wForm.Code, wForm.Body.String())
	}

	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		t.Fatalf("reload the stored record: %v", err)
	}
	if len(stored.UpstreamDNS) != 1 || stored.UpstreamDNS[0].Address != "9.9.9.9" {
		t.Fatalf("an ordinary form save erased the custom upstreams: stored %v (effective %v), want [9.9.9.9:53]",
			stored.UpstreamDNS, stored.EffectiveUpstreams())
	}
	if stored.SyncInterval != 7200 {
		t.Fatalf("the form save did not apply its own fields: sync_interval_seconds = %d, want 7200", stored.SyncInterval)
	}
}

// The positive control for the compatibility rule: an explicit empty list is a
// deliberate reset to the effective defaults, not an omission.
func TestPolicyUpstreamDNSExplicitEmptyListResetsDefaults(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	chosen := policy.DefaultSettings()
	chosen.Preset = policy.PresetGeoblock
	chosen.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, chosen); err != nil {
		t.Fatalf("seed the stored record: %v", err)
	}

	reset := []byte(`{"enabled":false,"preset":"geoblock","sync_interval_seconds":3600,"upstream_dns":[]}`)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", reset))
	if w.Code != http.StatusOK {
		t.Fatalf("reset PUT = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		t.Fatalf("reload the stored record: %v", err)
	}
	if len(stored.UpstreamDNS) != 0 {
		t.Fatalf("an explicit empty list did not reset the record: %+v", stored.UpstreamDNS)
	}
	defaults := policy.DefaultUpstreams()
	effective := stored.EffectiveUpstreams()
	if len(effective) != len(defaults) || effective[0] != defaults[0] {
		t.Fatalf("effective upstreams after an explicit reset = %v, want the default pair %v", effective, defaults)
	}
}
