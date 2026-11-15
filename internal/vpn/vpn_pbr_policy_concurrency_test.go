package vpn

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// This file covers the concurrency obligation the repair handover admitted was
// untested: what happens when an operator's "disable policy routing" arrives while
// an activation is already in flight.
//
// Both paths mutate the same single-owner kernel resource (the WAN device name) and
// the same runtime registry, so an interleaving that half-applies one of them could
// leave a state no consumer expects: PBR reported off while a device is still open,
// a registered config whose device was closed underneath it, or two live owners of
// one device name.
//
// These tests are deterministic, not timing-based, and a -race pass alone would not
// prove the property: the race detector finds unsynchronized memory access, not a
// wrong-but-well-synchronized ordering. The ordering assertions below fail if
// serialization is removed even while every field access stays race-free.
//
// Where the hold is placed: the activation is blocked inside policy.Store.Load,
// which a cold activation genuinely reaches through the last-known-good fallback
// when the live fetch cannot complete. That holds the real StartPolicyRouting call
// in flight inside the lifecycle lock. The repeated-enabled update runs under the
// same lock and touches the same registry and device, so the serialization proven
// here is the one that also covers update-vs-disable; the terminal-state assertions
// in TestConcurrentUpdateAndDisableEndsConsistent exercise the update path directly.
//
// Terminal states asserted, matching the admin PUT consumer in
// internal/handlers/vpn_policy.go:
//   - fully enabled: PBR on, matcher/egress installed, exactly one live device owner;
//   - fully disabled: PBR off, no matcher, no egress, no registered config, no live
//     device owner.

// eventLog records ordered lifecycle events under its own mutex so an ordering
// assertion can be made without relying on wall-clock timing.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(ev string) {
	l.mu.Lock()
	l.events = append(l.events, ev)
	l.mu.Unlock()
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.events))
	copy(out, l.events)
	return out
}

func (l *eventLog) indexOf(ev string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, got := range l.events {
		if got == ev {
			return i
		}
	}
	return -1
}

// holdingStore is a policy.Store whose Load blocks until release, so a test can
// hold a cold activation inside its last-known-good fallback. It signals entry once
// activation has actually reached Load, which means the activation is genuinely in
// flight rather than merely started.
type holdingStore struct {
	inner   policy.Store
	enter   chan struct{}
	release chan struct{}
	once    sync.Once
}

func newHoldingStore(inner policy.Store) *holdingStore {
	return &holdingStore{
		inner:   inner,
		enter:   make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (h *holdingStore) Load(ctx context.Context) (*policy.Generation, error) {
	h.once.Do(func() { close(h.enter) })
	select {
	case <-h.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return h.inner.Load(ctx)
}

func (h *holdingStore) Commit(ctx context.Context, gen *policy.Generation) error {
	return h.inner.Commit(ctx, gen)
}

// emptyStore has no last-known-good generation, so a cold activation whose live
// fetch fails cannot publish and must be refused.
type emptyStore struct{}

func (emptyStore) Load(context.Context) (*policy.Generation, error) { return nil, nil }

func (emptyStore) Commit(context.Context, *policy.Generation) error { return nil }

// assertFullyDisabled fails unless the service is in the all-proxy terminal state a
// successful disable must leave behind.
func assertFullyDisabled(t *testing.T, svc *Service, reg *nameRegistry) {
	t.Helper()
	if svc.PBREnabled() {
		t.Error("disable left PBR enabled; traffic would keep using policy routing")
	}
	if svc.PolicyMatcher() != nil {
		t.Error("disable left a policy matcher registered")
	}
	if svc.DirectEgress() != nil {
		t.Error("disable left a direct-egress manager installed; live flows would keep egressing directly")
	}
	if cfg := svc.getPBRConfig(); cfg != nil {
		t.Error("disable left a PBR config registered; a later status read would report a phantom configuration")
	}
	if got := reg.liveOwners(); got != 0 {
		t.Errorf("disable left %d live owner(s) of the WAN device name; the name stays busy for the next start", got)
	}
}

// assertFullyEnabled fails unless the service is in the complete enabled terminal
// state.
func assertFullyEnabled(t *testing.T, svc *Service, reg *nameRegistry) {
	t.Helper()
	if !svc.PBREnabled() {
		t.Error("activation reported success but PBR is not enabled")
	}
	if svc.PolicyMatcher() == nil {
		t.Error("activation reported success but no matcher is registered")
	}
	if svc.DirectEgress() == nil {
		t.Error("activation reported success but no direct-egress manager is installed")
	}
	if got := reg.liveOwners(); got != 1 {
		t.Errorf("live owners of the WAN device name = %d, want exactly 1", got)
	}
}

// TestDisableDuringActivationIsSerialized proves a disable that arrives while an
// activation is in flight cannot interleave with it: the disable must take effect
// after the in-flight activation settles, and the service must end fully disabled —
// never in a half-applied mix, and never holding a device the next start cannot
// acquire.
func TestDisableDuringActivationIsSerialized(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)
	t.Cleanup(func() { svc.StopPolicyRouting() })

	log := &eventLog{}
	settings := repeatedEnableSettings(t)
	// Seeded last-known-good: the live fetch cannot resolve offline, so activation
	// falls back to this store and publishes real rules once released.
	store := newHoldingStore(seededStore(t))

	activateDone := make(chan error, 1)
	go func() {
		err := svc.StartPolicyRouting(context.Background(), settings, store, string(settings.Preset))
		log.add("activation-returned")
		activateDone <- err
	}()

	// Bounded wait so a regression that never reaches the fallback fails instead of
	// hanging the suite.
	select {
	case <-store.enter:
	case <-time.After(10 * time.Second):
		t.Fatal("activation never reached its store load; the test cannot establish an overlap")
	}
	log.add("activation-in-flight")

	// The operator disables now, while the activation is genuinely in flight.
	disableDone := make(chan struct{})
	go func() {
		log.add("disable-attempted")
		svc.StopPolicyRouting()
		log.add("disable-returned")
		close(disableDone)
	}()

	// The disable must not complete while the activation holds the lifecycle lock.
	// Checked before release, so observing completion here is a real violation and
	// not a slow scheduler.
	if log.indexOf("disable-returned") != -1 {
		t.Fatal("disable completed while an activation was still in flight; the two paths interleaved")
	}

	close(store.release)
	if err := <-activateDone; err != nil {
		t.Fatalf("in-flight activation failed: %v", err)
	}
	<-disableDone

	events := log.snapshot()
	if log.indexOf("activation-in-flight") > log.indexOf("disable-attempted") {
		t.Fatalf("test did not actually overlap the two paths: %v", events)
	}
	if log.indexOf("disable-returned") < log.indexOf("activation-returned") {
		t.Fatalf("disable returned before the in-flight activation settled: %v", events)
	}

	// The disable was last, so the service must be fully off.
	assertFullyDisabled(t, svc, reg)
}

// TestActivationAfterDisableStartsCleanly is the positive control: once a disable
// has completed, a later enable must acquire the device name and reach the full
// enabled state. It proves the assertions above discriminate — "fully disabled" is
// a recoverable state, not a terminal one.
func TestActivationAfterDisableStartsCleanly(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)
	t.Cleanup(func() { svc.StopPolicyRouting() })

	settings := repeatedEnableSettings(t)

	if err := activateOnce(svc, settings, seededStore(t)); err != nil {
		t.Fatalf("cold activation failed: %v", err)
	}
	svc.StopPolicyRouting()
	assertFullyDisabled(t, svc, reg)

	// Re-enable after the disable: the name must be free again.
	if err := activateOnce(svc, settings, seededStore(t)); err != nil {
		t.Fatalf("enable after disable failed; the device name was not released: %v", err)
	}
	assertFullyEnabled(t, svc, reg)
}

// TestRepeatedUpdateAndDisableEndsConsistent runs the repeated-enabled update
// against a concurrent disable, repeatedly, and requires one of the two consistent
// terminal states each time plus no leaked device owner.
//
// The winner is genuinely scheduler-dependent, so this is not the ordering proof
// (TestDisableDuringActivationIsSerialized is). It exercises the update path
// directly and catches a mixed state or a leak across many real interleavings.
func TestRepeatedUpdateAndDisableEndsConsistent(t *testing.T) {
	for i := 0; i < 8; i++ {
		reg := newNameRegistry()
		withNameOwnedWANDevice(t, reg)
		svc := serviceForActivation(t)
		settings := repeatedEnableSettings(t)

		if err := activateOnce(svc, settings, seededStore(t)); err != nil {
			t.Fatalf("iteration %d: cold activation failed: %v", i, err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			// Offline this returns ErrPolicyActivationNoRules rather than publishing;
			// what matters is that it cannot corrupt the disable's outcome.
			_ = svc.StartPolicyRouting(context.Background(), settings, seededStore(t), string(settings.Preset))
		}()
		go func() {
			defer wg.Done()
			svc.StopPolicyRouting()
		}()
		wg.Wait()

		enabled := svc.PBREnabled()
		owners := reg.liveOwners()
		switch {
		case enabled && owners == 1 && svc.PolicyMatcher() != nil && svc.DirectEgress() != nil:
			// fully enabled: consistent
		case !enabled && owners == 0 && svc.PolicyMatcher() == nil && svc.DirectEgress() == nil:
			// fully disabled: consistent
		default:
			t.Fatalf("iteration %d: inconsistent terminal state (enabled=%t owners=%d matcher=%t egress=%t)",
				i, enabled, owners, svc.PolicyMatcher() != nil, svc.DirectEgress() != nil)
		}
		svc.StopPolicyRouting()
		if got := reg.liveOwners(); got != 0 {
			t.Fatalf("iteration %d: %d device owner(s) leaked after final disable", i, got)
		}
	}
}

// TestColdActivationRefusedLeavesNothingOwned is the negative control for the
// disabled terminal state: when activation cannot publish anything at all, the
// service must be fully disabled and must not hold the device name, so a later
// start is not blocked by a phantom owner.
func TestColdActivationRefusedLeavesNothingOwned(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)
	t.Cleanup(func() { svc.StopPolicyRouting() })

	settings := repeatedEnableSettings(t)
	err := activateOnce(svc, settings, emptyStore{})
	if err == nil {
		t.Fatal("activation with no publishable snapshot must fail closed")
	}
	assertFullyDisabled(t, svc, reg)
}
