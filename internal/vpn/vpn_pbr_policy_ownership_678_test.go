package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These are the regression oracles for issue #678 finding F678-04: a sync that is
// still in flight when the operator saves a different configuration must not commit
// or publish after the replacement has been accepted, or settings and runtime status
// would name the new configuration while the durable and live policy held the old
// one's rules.
//
// The property lives in policy.WriteOwner and the service wires every syncer to it,
// so the boundary is the subject here: these tests drive it with the production
// ticket semantics and assert on the durable store and the live matcher, which is
// where the defect was observable. They deliberately do not race a scheduling loop,
// because a fixture that blocks a shared store ends up freezing the replacement too
// — a property of the fixture, not of the product.

func mustAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return addr
}

// ownershipConfigs returns two records that differ only in their exception
// prefixes, so replacing one with the other is a genuine configuration change with
// distinguishable content.
func ownershipConfigs() (policy.Settings, policy.Settings) {
	a := policy.DefaultSettings()
	a.Enabled = true
	a.ProxyExceptions = []string{"203.0.113.0/24"}

	b := policy.DefaultSettings()
	b.Enabled = true
	b.ProxyExceptions = []string{"198.51.100.0/24", "192.0.2.0/24"}
	return a, b
}

// lkgStoreFor writes a configuration-matching durable generation so activation can
// publish real rules without any network access, and so the shrink-guard baseline
// is genuine rather than absent.
//
// The config hash comes from a throwaway syncer, so the fixture cannot drift from
// the production hash definition.
func lkgStoreFor(t *testing.T, settings policy.Settings) *policy.FileStore {
	t.Helper()
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	probe, err := policy.NewSyncer(policy.NewMatcher(), policy.NewFileStore(t.TempDir()), cfg)
	if err != nil {
		t.Fatalf("NewSyncer for the config hash: %v", err)
	}
	prefixes := make([]string, 0, len(cfg.LocalRules.CIDRs))
	for _, prefix := range cfg.LocalRules.CIDRs {
		prefixes = append(prefixes, prefix.String())
	}
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-audit-seed",
		Version:       1,
		CreatedAt:     time.Now().UTC(),
		ConfigHash:    probe.ConfigHash(),
		CIDRs:         prefixes,
		CIDRCount:     len(prefixes),
	}
	store := policy.NewFileStore(t.TempDir())
	if err := store.Commit(context.Background(), gen); err != nil {
		t.Fatalf("seed durable generation: %v", err)
	}
	return store
}

// TestSupersededWriterCannotCommitOrPublish is the F678-04 core, driven through the
// production write boundary with the two tickets a replacement produces.
//
// The incumbent establishes its policy first, as a live runtime has. The operator
// then saves a different configuration, whose replacement takes ownership by writing
// its own generation. The incumbent's next write must be refused, and neither record
// may name the retired configuration afterwards.
func TestSupersededWriterCannotCommitOrPublish(t *testing.T) {
	settingsA, settingsB := ownershipConfigs()

	owner := policy.NewWriteOwner()

	store := lkgStoreFor(t, settingsA)
	cfgA, err := settingsA.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig A: %v", err)
	}
	cfgB, err := settingsB.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig B: %v", err)
	}
	// The two configurations must be distinguishable by the identity the boundary and
	// the durable store both key on, or the scenario proves nothing.
	if lkgHashFor(t, settingsA) == lkgHashFor(t, settingsB) {
		t.Fatal("fixture is invalid: the two configurations share a configuration hash")
	}

	matcher := policy.NewMatcher()
	incumbent, err := policy.NewSyncer(matcher, store, cfgA)
	if err != nil {
		t.Fatalf("NewSyncer (incumbent): %v", err)
	}
	incumbent.AttachOwnership(owner)

	if _, err := incumbent.SyncOnce(context.Background()); err != nil {
		t.Fatalf("incumbent sync: %v", err)
	}
	if snap := matcher.Current(); snap == nil || !snap.MatchIPv4(mustAddr(t, "203.0.113.7")) {
		t.Fatal("the incumbent's own policy is not live before the replacement")
	}

	// The operator saves configuration B. The replacement takes ownership by writing
	// its own generation, exactly as the service does.
	replacement, err := policy.NewSyncer(matcher, store, cfgB)
	if err != nil {
		t.Fatalf("NewSyncer (replacement): %v", err)
	}
	replacement.AttachOwnership(owner)
	if _, err := replacement.SyncOnce(context.Background()); err != nil {
		t.Fatalf("replacement sync: %v", err)
	}
	if snap := matcher.Current(); snap == nil || !snap.MatchIPv4(mustAddr(t, "198.51.100.7")) {
		t.Fatal("the accepted configuration's policy is not live after the replacement")
	}

	// The incumbent's pending write is now stale. It must be refused and must leave
	// both records naming the accepted configuration.
	_, staleErr := incumbent.SyncOnce(context.Background())
	if staleErr == nil {
		t.Fatal("a superseded runtime published its stale generation (F678-04)")
	}
	if !errors.Is(staleErr, policy.ErrSyncSuperseded) {
		t.Fatalf("the superseded write failed for an unrelated reason: %v", staleErr)
	}

	live := matcher.Current()
	if live == nil {
		t.Fatal("no live snapshot after the refused stale write")
	}
	if !live.MatchIPv4(mustAddr(t, "198.51.100.7")) {
		t.Fatal("the accepted configuration's prefix is gone from the live policy (F678-04)")
	}
	if live.MatchIPv4(mustAddr(t, "203.0.113.7")) {
		t.Fatal("the retired configuration's prefix is live again (F678-04)")
	}

	gen, err := store.Load(context.Background())
	if err != nil || gen == nil {
		t.Fatalf("reload the durable generation: %v", err)
	}
	if gen.ConfigHash != lkgHashFor(t, settingsB) {
		t.Fatalf("durable generation belongs to %s, want the accepted configuration (F678-04: the stale sync committed)", gen.ConfigHash)
	}
	for _, prefix := range gen.CIDRs {
		if prefix == "203.0.113.0/24" {
			t.Fatal("the durable generation contains the retired configuration's prefix (F678-04)")
		}
	}
}

// TestRetiredOwnerCannotWriteOrPublishAfterDisable is the disable half: once the
// operator turns policy routing off, the boundary is retired and a prepared write
// must be refused rather than resurrect the policy.
func TestRetiredOwnerCannotWriteOrPublishAfterDisable(t *testing.T) {
	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = []string{"203.0.113.0/24"}

	owner := policy.NewWriteOwner()
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	store := lkgStoreFor(t, settings)
	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	syncer.AttachOwnership(owner)

	// The disable retires the boundary, as StopPolicyRouting does.
	owner.Retire()

	_, err = syncer.SyncOnce(context.Background())
	if err == nil {
		t.Fatal("a sync prepared before the disable published afterwards (F678-04)")
	}
	if !errors.Is(err, policy.ErrSyncSuperseded) {
		t.Fatalf("the retired sync failed for an unrelated reason: %v", err)
	}
	if matcher.Current() != nil {
		t.Fatal("a retired runtime published a snapshot after the disable")
	}
}

// TestReplacementFailureLeavesTheIncumbentInCharge is the adjacent control: a
// replacement whose own candidate is refused must not take ownership, so the
// incumbent can still write. Without this the boundary would be a one-shot fence
// that breaks a working runtime on any failed save.
func TestReplacementFailureLeavesTheIncumbentInCharge(t *testing.T) {
	settingsA := policy.DefaultSettings()
	settingsA.Enabled = true
	settingsA.ProxyExceptions = []string{"203.0.113.0/24"}

	owner := policy.NewWriteOwner()
	store := lkgStoreFor(t, settingsA)
	cfgA, err := settingsA.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	matcher := policy.NewMatcher()
	incumbent, err := policy.NewSyncer(matcher, store, cfgA)
	if err != nil {
		t.Fatalf("NewSyncer (incumbent): %v", err)
	}
	incumbent.AttachOwnership(owner)
	if _, err := incumbent.SyncOnce(context.Background()); err != nil {
		t.Fatalf("incumbent sync: %v", err)
	}

	// A replacement for a record with no rules cannot publish anything, so its write
	// is refused by the publication guard while it holds a newer ticket.
	empty := policy.DefaultSettings()
	emptyCfg, err := empty.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig (empty): %v", err)
	}
	replacement, err := policy.NewSyncer(matcher, store, emptyCfg)
	if err != nil {
		t.Fatalf("NewSyncer (replacement): %v", err)
	}
	replacement.AttachOwnership(owner)
	if _, err := replacement.SyncOnce(context.Background()); err == nil {
		t.Fatal("the replacement published despite having no rules")
	}

	// The incumbent still owns the boundary, so it can still publish.
	if _, err := incumbent.SyncOnce(context.Background()); err != nil {
		t.Fatalf("the refused replacement stranded the incumbent (F678-04 control): %v", err)
	}
	if snap := matcher.Current(); snap == nil || !snap.MatchIPv4(mustAddr(t, "203.0.113.7")) {
		t.Fatal("the incumbent's policy is not live after a refused replacement")
	}
}
