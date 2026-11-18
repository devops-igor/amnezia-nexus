package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// These are the permanent regression oracles for the owner finding P2-B: a refused
// activation of the persisted policy record used to be returned from the startup
// helper and propagated out of run, so the panel exited and the administrator could
// not reach the API to repair the configuration.
//
// They exercise the real startup function (startPersistedPolicyRouting), the real
// SQLite settings table, the real service activation path and the real policy
// status surface. Only the WAN device constructor is substituted where a successful
// activation is required.

const policyStartupTestSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// policyStartupDevice is a minimal packet device so a successful activation does
// not need a TUN capability.
type policyStartupDevice struct{}

func (policyStartupDevice) Read([]byte) (int, error)      { return 0, nil }
func (policyStartupDevice) Write(p []byte) (int, error)   { return len(p), nil }
func (policyStartupDevice) Close() error                  { return nil }
func (policyStartupDevice) SetHostWANIP(netip.Addr) error { return nil }

func newPolicyStartupFixture(t *testing.T) (*database.DB, *config.Config, policy.Settings) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "panel.db"), policyStartupTestSecret)
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.Preset = policy.PresetCustom
	settings.CustomURLs = []string{"https://lists.example/policy.lst"}
	if err := settings.Validate(); err != nil {
		t.Fatalf("fixture settings are invalid: %v", err)
	}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, settings); err != nil {
		t.Fatalf("persist fixture settings: %v", err)
	}

	cfg := &config.Config{DataDir: dir, VPNEnabled: true}
	return db, cfg, settings
}

// TestPersistedPolicyActivationFailureKeepsPanelUp is the P2-B regression: an
// enabled record whose activation is refused (no usable policy snapshot, source
// unreachable) must not stop startup, must leave PBR off, must leave the stored
// intent untouched, and must be visible through the policy status.
func TestPersistedPolicyActivationFailureKeepsPanelUp(t *testing.T) {
	db, cfg, settings := newPolicyStartupFixture(t)

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { vpnSvc.StopPolicyRouting() })

	// No last-known-good generation is seeded and the source cannot be reached, so
	// activation is refused by the existing guards. Nothing is weakened for this.
	if err := startPersistedPolicyRouting(context.Background(), db, vpnSvc, cfg); err != nil {
		t.Fatalf("startup refused to continue after a policy activation failure, so the panel would exit (P2-B): %v", err)
	}

	// Data plane fail-closed: policy routing is off and nothing is owned.
	if vpnSvc.PBREnabled() {
		t.Fatal("PBR is enabled although activation was refused (P2-B)")
	}
	if vpnSvc.PolicyMatcher() != nil {
		t.Fatal("a policy matcher survived a refused activation")
	}

	// The operator's persisted intent is untouched, so it can be repaired through
	// the API instead of being silently rewritten or cleared.
	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		t.Fatalf("re-read the persisted policy record: %v", err)
	}
	if !stored.Enabled || stored.Preset != settings.Preset ||
		len(stored.CustomURLs) != len(settings.CustomURLs) || stored.CustomURLs[0] != settings.CustomURLs[0] {
		t.Fatalf("the persisted record changed during a refused activation: %+v", stored)
	}

	// The failure is diagnosable from the status surface the API exposes.
	status := vpnSvc.PolicyStatusSnapshot()
	if status.Enabled {
		t.Fatalf("status reports policy routing enabled after a refused activation: %+v", status)
	}
	if status.LastError == "" {
		t.Fatal("status carries no reason after a refused startup activation, so the operator cannot diagnose it (P2-B)")
	}
	if !strings.Contains(status.LastError, "policy routing") || !strings.Contains(status.LastError, "activation") {
		t.Fatalf("status reason does not name the failed policy activation: %q", status.LastError)
	}
	if status.SyncState != "error" {
		t.Fatalf("status sync_state = %q, want \"error\" for a refused activation", status.SyncState)
	}
}

// TestPersistedPolicyActivationRecoversAfterRepair is the control: once the
// prerequisite exists, the same startup path activates and the recorded failure is
// cleared, so the status is not sticky.
func TestPersistedPolicyActivationRecoversAfterRepair(t *testing.T) {
	db, cfg, settings := newPolicyStartupFixture(t)

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { vpnSvc.StopPolicyRouting() })

	if err := startPersistedPolicyRouting(context.Background(), db, vpnSvc, cfg); err != nil {
		t.Fatalf("the refused startup returned an error: %v", err)
	}
	if status := vpnSvc.PolicyStatusSnapshot(); status.LastError == "" {
		t.Fatal("fixture did not reach the refused-activation state")
	}

	// Repair the prerequisite the operator would repair: a usable policy snapshot.
	syncCfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	store := policy.NewFileStore(filepath.Join(cfg.DataDir, "policy"))
	probe, err := policy.NewSyncer(policy.NewMatcher(), nil, store, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	meta := make(map[string]policy.SourceMeta, len(syncCfg.Sources))
	for _, src := range syncCfg.Sources {
		meta[src.ID] = policy.SourceMeta{ID: src.ID, URL: src.URL, RuleCount: 1}
	}
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-startup-repair",
		Version:       1,
		ConfigHash:    probe.ConfigHash(),
		SourcesMeta:   meta,
		Domains:       map[string]uint32{"seed.example.com": 1},
		DomainCount:   1,
	}
	if err := store.Commit(context.Background(), gen); err != nil {
		t.Fatalf("seed the repaired policy snapshot: %v", err)
	}
	t.Cleanup(vpn.SetWANDeviceFactoryForTest(func(string) (forwarder.PacketDevice, error) {
		return policyStartupDevice{}, nil
	}))

	if err := startPersistedPolicyRouting(context.Background(), db, vpnSvc, cfg); err != nil {
		t.Fatalf("the repaired startup returned an error: %v", err)
	}
	if !vpnSvc.PBREnabled() {
		t.Fatal("policy routing did not activate after the prerequisite was repaired")
	}
	status := vpnSvc.PolicyStatusSnapshot()
	if !status.Enabled || !status.Ready {
		t.Fatalf("status does not report the activated policy routing: %+v", status)
	}
	// The recorded activation failure must be gone. A syncer-level last-sync error is
	// legitimate here and is not what this asserts: activation succeeded from the
	// verified baseline while the (deliberately unreachable) source refresh failed,
	// which the status reports honestly.
	if strings.Contains(status.LastError, "persisted policy routing could not be activated") {
		t.Fatalf("the refused-activation reason is still advertised after a successful activation: %q", status.LastError)
	}
}
