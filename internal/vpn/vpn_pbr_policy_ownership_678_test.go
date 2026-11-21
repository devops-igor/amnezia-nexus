package vpn

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These are the permanent regression oracles for issue #678 finding F678-04: a
// sync that is still in flight when the operator saves a different configuration
// used to commit and publish its old generation after the replacement had already
// been accepted. Settings and runtime status then named the new configuration
// while both the live matcher and the durable generation held the old one's rules.
//
// The policy content a save changes is the operator's IPv4 exception list, so the
// two configurations below differ in exactly that. The decisive condition is a
// durable write held open across a replacement, not a timing window: the fixture
// store blocks the incumbent's next commit until the test releases it, so the stale
// commit is attempted strictly after the replacement published.
//
// Everything in the path — the service entry points, the write-ownership boundary,
// the real syncer, the file store beneath the fixture wrapper and the matcher — is
// production code. Only the packet device is substituted, so no /dev/net/tun is
// required.

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

// holdNthCommitStore forwards to a production FileStore but holds the commit
// numbered `hold` open until the test releases it. Every other commit passes
// straight through.
//
// It exists because the durable commit and the live publication are one critical
// section inside the write-ownership boundary: holding the commit open is the only
// way to create "the incumbent has prepared a candidate but has not written it yet"
// without touching production code.
type holdNthCommitStore struct {
	inner policy.Store
	hold  int

	mu       sync.Mutex
	commits  int
	reached  chan struct{}
	release  chan struct{}
	reachedN int
}

func newHoldNthCommitStore(inner policy.Store, hold int) *holdNthCommitStore {
	return &holdNthCommitStore{
		inner:   inner,
		hold:    hold,
		reached: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
}

// waitForHold reports the channel that fires when the held commit has arrived.
func (s *holdNthCommitStore) waitForHold() <-chan struct{} { return s.reached }

// releaseHold lets the held commit proceed.
func (s *holdNthCommitStore) releaseHold() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reachedN != 0 {
		return
	}
	s.reachedN = 1
	close(s.release)
}

func (s *holdNthCommitStore) Commit(ctx context.Context, gen *policy.Generation) error {
	s.mu.Lock()
	s.commits++
	mine := s.commits
	s.mu.Unlock()

	if mine == s.hold {
		select {
		case s.reached <- struct{}{}:
		default:
		}
		<-s.release
	}
	return s.inner.Commit(ctx, gen)
}

func (s *holdNthCommitStore) Load(ctx context.Context) (*policy.Generation, error) {
	return s.inner.Load(ctx)
}

// TestReplacedRuntimeCannotOverwriteAcceptedPolicy is the core F678-04 regression.
//
// Configuration A becomes the live runtime. A manual sync on it is started and the
// fixture holds its durable commit open. The operator then saves configuration B,
// which publishes and takes write ownership. Releasing A's commit must be refused
// inside the boundary.
func TestReplacedRuntimeCannotOverwriteAcceptedPolicy(t *testing.T) {
	settingsA, settingsB := ownershipConfigs()

	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	inner := lkgStoreFor(t, settingsA)
	// Commit 1 is the seeded generation above; commit 2 is activation's own sync;
	// commit 3 is the manual sync under test.
	store := newHoldNthCommitStore(inner, 3)
	t.Cleanup(store.releaseHold)

	if err := svc.StartPolicyRouting(context.Background(), settingsA, store); err != nil {
		t.Fatalf("activation of configuration A failed: %v", err)
	}
	hashA := svc.policyRuntime().syncer.ConfigHash()

	type syncOutcome struct {
		res policy.SyncResult
		err error
	}
	manual := make(chan syncOutcome, 1)
	manualCtx, cancelManual := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelManual()
	go func() {
		// The activation handshake may still be finishing its own update, in which
		// case the single-flight guard answers ErrSyncInProgress. That is not the
		// scenario under test, so retry until an attempt is accepted.
		for {
			res, err := svc.SyncPolicyNow(manualCtx)
			if errors.Is(err, policy.ErrSyncInProgress) && manualCtx.Err() == nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			manual <- syncOutcome{res: res, err: err}
			return
		}
	}()

	select {
	case <-store.waitForHold():
	case outcome := <-manual:
		t.Fatalf("the manual sync finished before its commit was held (err=%v); the scenario did not run", outcome.err)
	case <-time.After(30 * time.Second):
		t.Fatal("the manual sync never reached its durable commit; the held-write scenario did not run")
	}

	// The operator now saves a different configuration. This publishes B and takes
	// write ownership.
	if err := svc.StartPolicyRouting(context.Background(), settingsB, store); err != nil {
		t.Fatalf("replacement with configuration B failed: %v", err)
	}

	// Release A's held commit: its stale generation must not land.
	store.releaseHold()
	var outcome syncOutcome
	select {
	case outcome = <-manual:
	case <-time.After(30 * time.Second):
		t.Fatal("the manual sync never returned after its commit was released")
	}
	if outcome.err == nil {
		t.Fatal("the superseded manual sync reported success (F678-04: a retired runtime published its stale generation)")
	}
	if !errors.Is(outcome.err, policy.ErrSyncSuperseded) {
		t.Fatalf("the superseded manual sync failed for an unrelated reason: %v", outcome.err)
	}

	// Live policy: B's prefixes are present and A's is gone.
	live := svc.PolicyMatcher()
	if live == nil {
		t.Fatal("no live matcher after the replacement")
	}
	snap := live.Current()
	if snap == nil {
		t.Fatal("no live snapshot after the replacement")
	}
	if !snap.MatchIPv4(mustAddr(t, "198.51.100.7")) {
		t.Fatal("the accepted configuration's prefix is gone from the live policy after the stale sync (F678-04)")
	}
	if !snap.MatchIPv4(mustAddr(t, "192.0.2.7")) {
		t.Fatal("the accepted configuration's second prefix is missing from the live policy")
	}
	if snap.MatchIPv4(mustAddr(t, "203.0.113.7")) {
		t.Fatal("the retired configuration's prefix is live again: the superseded sync published its generation (F678-04)")
	}

	// Durable policy: reload from the store, not from memory.
	gen, err := inner.Load(context.Background())
	if err != nil {
		t.Fatalf("reload the durable generation: %v", err)
	}
	if gen == nil {
		t.Fatal("no durable generation after the replacement")
	}
	hashB := svc.policyRuntime().syncer.ConfigHash()
	if hashA == hashB {
		t.Fatal("fixture is invalid: the two configurations share a configuration hash")
	}
	if gen.ConfigHash != hashB {
		t.Fatalf("durable generation belongs to %s, want the accepted configuration %s (F678-04: the stale sync committed)", gen.ConfigHash, hashB)
	}
	for _, prefix := range gen.CIDRs {
		if prefix == "203.0.113.0/24" {
			t.Fatal("the durable generation contains the retired configuration's prefix (F678-04)")
		}
	}

	// Runtime settings and status still identify the accepted configuration.
	runtimeSettings := svc.policyRuntime().settings
	if len(runtimeSettings.ProxyExceptions) != len(settingsB.ProxyExceptions) {
		t.Fatalf("runtime settings identify %v, want the accepted configuration %v",
			runtimeSettings.ProxyExceptions, settingsB.ProxyExceptions)
	}
	status := svc.PolicyStatusSnapshot()
	if status.CIDRCount != len(settingsB.ProxyExceptions) {
		t.Fatalf("runtime status reports %d prefixes, want the accepted configuration's %d (F678-04)",
			status.CIDRCount, len(settingsB.ProxyExceptions))
	}
	if status.LastError != "" {
		t.Fatalf("runtime status reports an error after a successful replacement: %q", status.LastError)
	}
	if !status.Enabled || !status.Ready {
		t.Fatalf("runtime status is not enabled/ready after the replacement: %+v", status)
	}
}

// TestSuccessfulManualSyncStillPublishesOnCurrentSource keeps the F678-04 boundary
// from turning every manual sync into a refusal: the current runtime must still be
// able to publish on demand.
func TestSuccessfulManualSyncStillPublishesOnCurrentSource(t *testing.T) {
	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = []string{"203.0.113.0/24"}

	store := lkgStoreFor(t, settings)
	if err := svc.StartPolicyRouting(context.Background(), settings, store); err != nil {
		t.Fatalf("activation failed: %v", err)
	}

	res, err := svc.SyncPolicyNow(context.Background())
	if err != nil {
		t.Fatalf("manual sync on the current configuration failed: %v", err)
	}
	if res.GenerationID == "" {
		t.Fatal("the manual sync published no generation identity")
	}
	snap := svc.PolicyMatcher().Current()
	if snap == nil || !snap.MatchIPv4(mustAddr(t, "203.0.113.7")) {
		t.Fatal("the manual sync left no rule-bearing snapshot live: a working manual sync was refused")
	}
	gen, err := store.Load(context.Background())
	if err != nil || gen == nil {
		t.Fatalf("the durable generation is unreadable after a successful manual sync: %v", err)
	}
	if gen.GenerationID != res.GenerationID {
		t.Fatalf("durable generation = %s, want the published %s", gen.GenerationID, res.GenerationID)
	}
}

// TestRetiredRuntimeCannotPublishAfterDisable is the disable half of the same
// boundary: once the operator turns policy routing off, a sync that was already
// prepared must be refused rather than resurrect the retired policy.
func TestRetiredRuntimeCannotPublishAfterDisable(t *testing.T) {
	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = []string{"203.0.113.0/24"}

	inner := lkgStoreFor(t, settings)
	store := newHoldNthCommitStore(inner, 2)
	t.Cleanup(store.releaseHold)

	if err := svc.StartPolicyRouting(context.Background(), settings, store); err != nil {
		t.Fatalf("activation failed: %v", err)
	}

	type syncOutcome struct {
		err error
	}
	manual := make(chan syncOutcome, 1)
	manualCtx, cancelManual := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelManual()
	go func() {
		_, err := svc.SyncPolicyNow(manualCtx)
		manual <- syncOutcome{err: err}
	}()

	select {
	case <-store.waitForHold():
	case <-time.After(30 * time.Second):
		t.Fatal("the manual sync never reached its durable commit")
	}

	// The operator disables policy routing: the data path goes away and the write
	// boundary is retired.
	svc.StopPolicyRouting()
	if svc.PBREnabled() {
		t.Fatal("PBR is still enabled after disable")
	}

	store.releaseHold()
	select {
	case outcome := <-manual:
		if outcome.err == nil {
			t.Fatal("a sync prepared before the disable published afterwards (F678-04: retired runtime resurrected the policy)")
		}
		if !errors.Is(outcome.err, policy.ErrSyncSuperseded) {
			t.Fatalf("the retired sync failed for an unrelated reason: %v", outcome.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the manual sync never returned after its commit was released")
	}

	// The live policy must be the disabled one: no matcher, nothing published.
	if svc.PolicyMatcher() != nil {
		t.Fatal("a policy runtime is still registered after disable")
	}
	if svc.DestinationClassifierForTest() != nil {
		t.Fatal("a destination classifier is still installed after disable")
	}
}
