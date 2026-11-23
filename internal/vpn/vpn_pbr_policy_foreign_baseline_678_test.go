package vpn

import (
	"context"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These are the regression oracles for issue #678 finding F678-05, restated for the
// configuration model this slice ships: a durable last-known-good generation that
// belongs to a DIFFERENT configuration must never be published as the selected
// one's rules.
//
// The original finding was a failed first fetch of a newly selected source falling
// back to the previous source's rules. There is no fetch any more, so the surviving
// form of the same defect is a selected configuration that cannot produce a snapshot
// of its own falling back to another configuration's stored rules. The executed
// subject is still ensureInitialSnapshot, the activation handshake itself:
// prime baseline → one synchronous cycle → settle → require rules.

// TestForeignBaselineIsNotAcceptedWhenThisConfigurationHasNoRules is the core
// F678-05 regression in its shipped form.
//
// The foreign-baseline guard is not a rule-count guard: it refuses a stored
// generation that belongs to a different configuration. Configuration B here has
// zero exceptions, which is a valid policy, but its cycle cannot publish because
// the store it is handed cannot be read — so A's generation is the only candidate
// and publishing it would authorize traffic with rules B never selected.
func TestForeignBaselineIsNotAcceptedWhenThisConfigurationHasNoRules(t *testing.T) {
	// A has produced a valid durable generation.
	settingsA := policy.DefaultSettings()
	settingsA.Enabled = true
	settingsA.ProxyExceptions = []string{"203.0.113.0/24"}
	store := lkgStoreFor(t, settingsA)

	// The selected configuration B carries no rules, so its own cycle cannot publish
	// anything and the only stored generation belongs to A.
	settingsB := policy.DefaultSettings()
	settingsB.Enabled = true
	cfgB, err := settingsB.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig B: %v", err)
	}
	matcher := policy.NewMatcher()
	// The store refuses to commit B's (empty) cycle, which is what leaves A's
	// generation as the only thing activation could fall back to.
	unwritable := &memoryStore{loadErr: errors.New("no cached generation"), commitErr: errors.New("durable store unwritable")}
	syncerB, err := policy.NewSyncer(matcher, unwritable, cfgB)
	if err != nil {
		t.Fatalf("NewSyncer (B): %v", err)
	}
	if syncerB.ConfigHash() == lkgHashFor(t, settingsA) {
		t.Fatal("fixture is invalid: the two configurations share a hash, so this is not a foreign baseline")
	}

	err = ensureInitialSnapshot(context.Background(), syncerB, store, matcher, newDestinationClassifier(nil))
	if err == nil {
		t.Fatal("activation succeeded although the selected configuration published nothing and the only stored generation was foreign (F678-05)")
	}

	// No foreign snapshot may reach the live policy.
	if snap := matcher.Current(); snap != nil {
		t.Fatalf("a foreign cached policy was published into the matcher (F678-05): %d prefixes, contains A = %v",
			snap.CIDRCount(), snap.MatchIPv4(mustAddr(t, "203.0.113.7")))
	}

	// A's durable bytes are kept, untouched, for recovery.
	gen, loadErr := store.Load(context.Background())
	if loadErr != nil {
		t.Fatalf("reload durable generation: %v", loadErr)
	}
	if gen == nil {
		t.Fatal("the foreign durable generation was removed instead of retained")
	}
	if gen.ConfigHash != lkgHashFor(t, settingsA) {
		t.Fatalf("durable generation now belongs to %s, want A's retained hash", gen.ConfigHash)
	}
	found := false
	for _, prefix := range gen.CIDRs {
		if prefix == "203.0.113.0/24" {
			found = true
		}
	}
	if !found {
		t.Fatal("A's stored rules were lost while refusing the foreign baseline")
	}
}

// TestMatchingBaselineActivatesWithoutAnyCycleNeedingToPublish keeps the
// last-known-good control: a configuration whose stored generation matches it
// activates on that verified baseline, so a working deployment is never refused.
func TestMatchingBaselineActivatesWithoutAnyCycleNeedingToPublish(t *testing.T) {
	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = []string{"203.0.113.0/24"}
	store := lkgStoreFor(t, settings)

	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}

	if err := ensureInitialSnapshot(context.Background(), syncer, store, matcher, newDestinationClassifier(nil)); err != nil {
		t.Fatalf("activation refused the verified matching last-known-good policy: %v", err)
	}
	snap := matcher.Current()
	if snap == nil || !snap.MatchIPv4(mustAddr(t, "203.0.113.7")) {
		t.Fatal("the verified last-known-good policy was not published")
	}
}

// TestChangedConfigurationActivatesOnItsOwnRules is the positive control that keeps
// the F678-05 fix from refusing a genuine configuration change: a foreign stored
// generation plus a selected configuration that can publish its own rules must
// activate that configuration and commit it.
func TestChangedConfigurationActivatesOnItsOwnRules(t *testing.T) {
	settingsA := policy.DefaultSettings()
	settingsA.Enabled = true
	settingsA.ProxyExceptions = []string{"203.0.113.0/24"}
	store := lkgStoreFor(t, settingsA)

	settingsB := policy.DefaultSettings()
	settingsB.Enabled = true
	settingsB.ProxyExceptions = []string{"198.51.100.0/24", "192.0.2.0/24"}
	cfgB, err := settingsB.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig B: %v", err)
	}
	matcher := policy.NewMatcher()
	syncerB, err := policy.NewSyncer(matcher, store, cfgB)
	if err != nil {
		t.Fatalf("NewSyncer (B): %v", err)
	}
	if syncerB.ConfigHash() == lkgHashFor(t, settingsA) {
		t.Fatal("fixture is invalid: the two configurations share a configuration hash")
	}

	if err := ensureInitialSnapshot(context.Background(), syncerB, store, matcher, newDestinationClassifier(nil)); err != nil {
		t.Fatalf("activation of a configuration with its own rules was refused: %v", err)
	}
	snap := matcher.Current()
	if snap == nil || !snap.MatchIPv4(mustAddr(t, "198.51.100.7")) {
		t.Fatal("the new configuration's rules were not published")
	}
	if snap.MatchIPv4(mustAddr(t, "203.0.113.7")) {
		t.Fatal("the previous configuration's rules are still live after a successful change")
	}
	gen, err := store.Load(context.Background())
	if err != nil || gen == nil {
		t.Fatalf("reload durable generation: %v", err)
	}
	if gen.ConfigHash != syncerB.ConfigHash() {
		t.Fatalf("durable generation belongs to %s, want the new configuration %s", gen.ConfigHash, syncerB.ConfigHash())
	}
	found := false
	for _, prefix := range gen.CIDRs {
		if prefix == "198.51.100.0/24" {
			found = true
		}
	}
	if !found {
		t.Fatal("the new configuration's rules were not committed durably")
	}
}

// lkgHashFor reports the configuration hash a syncer derives for a record, so a
// fixture compares against the production definition instead of restating it.
func lkgHashFor(t *testing.T, settings policy.Settings) string {
	t.Helper()
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	probe, err := policy.NewSyncer(policy.NewMatcher(), policy.NewFileStore(t.TempDir()), cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	return probe.ConfigHash()
}
