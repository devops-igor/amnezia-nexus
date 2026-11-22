package main

import (
	"context"
	"encoding/json"
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
	settings.ProxyExceptions = []string{"203.0.113.0/24"}
	if err := settings.Validate(); err != nil {
		t.Fatalf("fixture settings are invalid: %v", err)
	}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, settings); err != nil {
		t.Fatalf("persist fixture settings: %v", err)
	}

	cfg := &config.Config{DataDir: dir, VPNEnabled: true}
	return db, cfg, settings
}

// TestStartupLoadsPredecessorRowAndKeepsItsIPv4Policy is the migration positive
// control for the reader split.
//
// A row an earlier build wrote may hold domain lines beside prefixes, and it must
// still load: refusing it would take the operator's working IPv4 policy down with an
// inert entry, and could leave the panel unable to start. That leniency is now
// confined to policy.DecodeStoredRecord, which is what this startup path calls, so
// it is asserted here rather than inferred from the request path.
//
// The row is left byte-identical, and the decoded record still activates through the
// real startup function: a forgiving load that published nothing would not be an
// upgrade, only a different failure.
func TestStartupLoadsPredecessorRowAndKeepsItsIPv4Policy(t *testing.T) {
	dir := t.TempDir()
	db, err := database.New(filepath.Join(dir, "panel.db"), policyStartupTestSecret)
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const predecessor = `{"enabled":true,"preset":"aggregate",` +
		`"local_entries":["203.0.113.0/24","example.com"],"sync_interval_seconds":3600}`
	if err := db.SetSetting(context.Background(), policy.SettingsKey, json.RawMessage(predecessor)); err != nil {
		t.Fatalf("seed the predecessor row: %v", err)
	}

	loaded, err := loadPolicySettings(context.Background(), db)
	if err != nil {
		t.Fatalf("a predecessor row must load; failing here is the F957-04 defect: %v", err)
	}
	if !loaded.Enabled {
		t.Error("the stored enabled flag did not survive the load")
	}
	if len(loaded.ProxyExceptions) != 1 || loaded.ProxyExceptions[0] != "203.0.113.0/24" {
		t.Fatalf("loaded exceptions = %v, want only the usable IPv4 prefix", loaded.ProxyExceptions)
	}

	// Reading the row is not a migration of the row: the operator's stored bytes are
	// untouched, so nothing was silently destroyed on the way in.
	raw, found, err := db.GetSettingRaw(context.Background(), policy.SettingsKey)
	if err != nil || !found || !raw.Valid {
		t.Fatalf("re-read the raw row: found=%v err=%v", found, err)
	}
	if raw.String != predecessor {
		t.Fatalf("the stored row changed during the load:\n got %s\nwant %s", raw.String, predecessor)
	}

	// The upgrade path completes: the prefix this build kept still activates.
	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { vpnSvc.StopPolicyRouting() })

	syncCfg, err := loaded.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	store := policy.NewFileStore(filepath.Join(dir, "policy"))
	probe, err := policy.NewSyncer(policy.NewMatcher(), store, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	prefixes := make([]string, 0, len(syncCfg.LocalRules.CIDRs))
	for _, prefix := range syncCfg.LocalRules.CIDRs {
		prefixes = append(prefixes, prefix.String())
	}
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-predecessor-row",
		Version:       1,
		ConfigHash:    probe.ConfigHash(),
		CIDRs:         prefixes,
		CIDRCount:     len(prefixes),
	}
	if err := store.Commit(context.Background(), gen); err != nil {
		t.Fatalf("seed the policy snapshot: %v", err)
	}
	t.Cleanup(vpn.SetWANDeviceFactoryForTest(func(string) (forwarder.PacketDevice, error) {
		return policyStartupDevice{}, nil
	}))

	cfg := &config.Config{DataDir: dir, VPNEnabled: true}
	if err := startPersistedPolicyRouting(context.Background(), db, vpnSvc, cfg); err != nil {
		t.Fatalf("startup returned an error: %v", err)
	}
	if !vpnSvc.PBREnabled() {
		t.Fatalf("policy routing did not activate from the predecessor row's surviving prefix; status=%+v",
			vpnSvc.PolicyStatusSnapshot())
	}
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

	// No last-known-good generation is seeded, so activation has nothing to publish
	// and is refused by the existing guards. Nothing is weakened for this.
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
	if !stored.Enabled || len(stored.ProxyExceptions) != len(settings.ProxyExceptions) ||
		stored.ProxyExceptions[0] != settings.ProxyExceptions[0] {
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
	// The reason must name the activation and carry the producer's own detail, so
	// the operator can act on it. Which prerequisite refused depends on the host, so
	// the assertion is on the framing plus a non-empty cause rather than on one
	// kernel message.
	if !strings.Contains(status.LastError, "persisted policy routing could not be activated") {
		t.Fatalf("status reason does not name the failed policy activation: %q", status.LastError)
	}
	if !strings.Contains(status.LastError, "activate policy routing") {
		t.Fatalf("status reason does not carry the activation cause: %q", status.LastError)
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
	probe, err := policy.NewSyncer(policy.NewMatcher(), store, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	prefixes := make([]string, 0, len(syncCfg.LocalRules.CIDRs))
	for _, prefix := range syncCfg.LocalRules.CIDRs {
		prefixes = append(prefixes, prefix.String())
	}
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-startup-repair",
		Version:       1,
		ConfigHash:    probe.ConfigHash(),
		CIDRs:         prefixes,
		CIDRCount:     len(prefixes),
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
