package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/handlers"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// This is the permanent regression oracle for the owner finding P2-A: two
// concurrent PUTs could commit their settings in one order and activate in the
// other, leaving the durable record disabled while the live runtime routed as
// enabled and both requests answering 200.
//
// The interleaving is forced, not timed: request A is parked inside its own
// activation by the activation-entry hook (which runs at the start of
// StartPolicyRouting, i.e. after A's durable write), request B is issued while A is
// parked, and only then is A released. With the settings-mutation boundary in place
// B cannot even read the record until A's whole mutation finished, so the durable
// value and the runtime decision belong to the same request; without it B's disable
// lands between A's save and A's activation and the state ends up split.

// policyMutationDevice is a minimal packet device so activation can proceed without
// a TUN capability. Only the WAN device constructor is substituted.
type policyMutationDevice struct{}

func (policyMutationDevice) Read([]byte) (int, error)      { return 0, nil }
func (policyMutationDevice) Write(p []byte) (int, error)   { return len(p), nil }
func (policyMutationDevice) Close() error                  { return nil }
func (policyMutationDevice) SetHostWANIP(netip.Addr) error { return nil }

// seedMatchingPolicyStore writes a last-known-good generation whose configuration
// hash matches these settings, so activation succeeds offline: the baseline is
// primed and the (unreachable) first sync is tolerated on the verified policy.
func seedMatchingPolicyStore(t *testing.T, dataDir string, settings policy.Settings) {
	t.Helper()
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	store := policy.NewFileStore(filepath.Join(dataDir, "policy"))
	probe, err := policy.NewSyncer(policy.NewMatcher(), store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	// The seeded generation must be the record's own rules, so activation publishes
	// the accepted configuration rather than falling back to something foreign.
	prefixes := make([]string, 0, len(cfg.LocalRules.CIDRs))
	for _, prefix := range cfg.LocalRules.CIDRs {
		prefixes = append(prefixes, prefix.String())
	}
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-mutation-seed",
		Version:       1,
		ConfigHash:    probe.ConfigHash(),
		CIDRs:         prefixes,
		CIDRCount:     len(prefixes),
	}
	if err := store.Commit(context.Background(), gen); err != nil {
		t.Fatalf("seed last-known-good generation: %v", err)
	}
}

// TestConcurrentPolicyPutsKeepSettingsAndRuntimeConsistent is the P2-A regression.
func TestConcurrentPolicyPutsKeepSettingsAndRuntimeConsistent(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	// The handler resolves its durable policy store under DataDir, so give the test
	// its own directory instead of the relative fallback.
	cfg.DataDir = t.TempDir()

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { vpnSvc.StopPolicyRouting() })
	t.Cleanup(vpn.SetWANDeviceFactoryForTest(func(string) (forwarder.PacketDevice, error) {
		return policyMutationDevice{}, nil
	}))

	enabled := policy.DefaultSettings()
	enabled.Enabled = true
	enabled.ProxyExceptions = []string{"203.0.113.0/24"}
	if err := enabled.Validate(); err != nil {
		t.Fatalf("fixture settings are invalid: %v", err)
	}
	disabled := enabled
	disabled.Enabled = false

	seedMatchingPolicyStore(t, cfg.DataDir, enabled)

	// Park the first request inside its activation.
	entered := make(chan struct{})
	released := make(chan struct{})
	var enteredOnce sync.Once
	t.Cleanup(vpn.SetPolicyActivationHookForTest(func() {
		enteredOnce.Do(func() { close(entered) })
		<-released
	}))

	r := NewRouterWithDeps(handlers.Dependencies{Config: cfg, DB: db, VPNService: vpnSvc})

	type result struct {
		code int
		body string
	}
	put := func(settings policy.Settings, done chan<- result) {
		payload, err := json.Marshal(settings)
		if err != nil {
			done <- result{code: -1, body: err.Error()}
			return
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", payload))
		done <- result{code: w.Code, body: w.Body.String()}
	}

	firstDone := make(chan result, 1)
	go put(enabled, firstDone)

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the enabling request never entered activation; the concurrent schedule did not run")
	}

	secondDone := make(chan result, 1)
	go put(disabled, secondDone)

	// Whether the disabling request can complete while the first request is parked
	// is exactly the property under test: with the boundary it cannot (its response
	// only arrives after the first mutation ends), without it, it does.
	var second result
	secondFinishedWhileParked := false
	select {
	case second = <-secondDone:
		if second.code != http.StatusOK {
			t.Fatalf("the disabling request answered %d: %s", second.code, second.body)
		}
		secondFinishedWhileParked = true
	case <-time.After(time.Second):
	}

	close(released)

	var first result
	select {
	case first = <-firstDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the enabling request never returned after it was released")
	}
	if first.code != http.StatusOK {
		t.Fatalf("the enabling request answered %d, want 200: %s", first.code, first.body)
	}

	if !secondFinishedWhileParked {
		select {
		case second = <-secondDone:
		case <-time.After(30 * time.Second):
			t.Fatal("the disabling request never returned")
		}
	}
	if second.code != http.StatusOK {
		t.Fatalf("the disabling request answered %d, want 200: %s", second.code, second.body)
	}

	// The last accepted change disabled policy routing, so both the durable record
	// and the live runtime must say disabled. A split here is the P2-A defect.
	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		t.Fatalf("read the persisted policy record: %v", err)
	}
	status := vpnSvc.PolicyStatusSnapshot()
	if stored.Enabled {
		t.Fatalf("the durable record is still enabled after the last accepted save disabled it: %+v", stored)
	}
	if vpnSvc.PBREnabled() || status.Enabled {
		t.Fatalf("the persisted record says disabled but the live runtime routes as enabled (P2-A): pbr_enabled=%t status=%+v",
			vpnSvc.PBREnabled(), status)
	}
	if vpnSvc.PolicyMatcher() != nil {
		t.Fatal("a live matcher survives after the disable was the accepted final state")
	}

	// Both responses must describe their own request: the serialized outcome is
	// "enable applied, then disable applied", so the last response carries the
	// disabled record and neither is an error.
	var finalResponse map[string]any
	if err := json.Unmarshal([]byte(second.body), &finalResponse); err != nil {
		t.Fatalf("decode the final response: %v (%s)", err, second.body)
	}
	if got, _ := finalResponse["enabled"].(bool); got {
		t.Fatalf("the final response reports enabled=true, contradicting the accepted disable: %s", second.body)
	}
}
