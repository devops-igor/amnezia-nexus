package vpn

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// This file proves, offline and without a TUN capability or any kernel write, the
// repeated-enabled update defect diagnosed in DEV_RESTART_DIAGNOSIS.md §2b and the
// ownership contract that corrects it.
//
// The kernel gives a TUN device name to exactly one open file descriptor at a
// time: a second TUNSETIFF on the same name while the owning fd is open fails with
// EBUSY. nameRegistry models exactly that contract (one live owner per name, a
// closed fd releases it), so a repeated activation that tries to create the same
// device while the first is still installed reproduces the production failure
// without needing /dev/net/tun.
//
// The tests drive the real production entry point, Service.StartPolicyRouting,
// because that is where the defect lives: it registers a config before initPBR, so
// a re-entrant activation on the same Service previously built a fresh nexus-wan0
// while the installed device was still open. The admin PUT path reaches this
// whenever an operator saves settings while policy routing is already enabled
// (internal/handlers/vpn_policy.go calls StopPolicyRouting only when disabling).
// A test that called initPBR directly would bypass the defect and prove nothing,
// so it is deliberately not used here.
//
// Why the assertions are about ownership rather than about a successful refetch:
// an offline test has no reachable policy source, so a live sync legitimately
// fails on content. The defect under test is not "the fetch failed" — it is
// "activation rebuilt a single-owner kernel device it should have reused". Asserting
// constructor-call counts and instance identity states exactly that, and does not
// fake a successful fetch to manufacture a green.

// nameOwnerDevice is a forwarder.PacketDevice that claims a name exclusively for
// the lifetime of the value, mirroring TUNSETIFF's name ownership.
type nameOwnerDevice struct {
	name  string
	owner *nameRegistry
	mu    sync.Mutex
	gone  bool
}

// nameRegistry is the shared name table standing in for the kernel's, and also
// counts how many device constructions were attempted.
type nameRegistry struct {
	mu       sync.Mutex
	owner    map[string]*nameOwnerDevice
	acquires int
}

func newNameRegistry() *nameRegistry {
	return &nameRegistry{owner: make(map[string]*nameOwnerDevice)}
}

// errDeviceBusy is the EBUSY equivalent the real ioctl returns.
var errDeviceBusy = errors.New("device or resource busy")

// acquire mirrors TUNSETIFF: it fails with errDeviceBusy when the name is already
// held by a live owner.
func (r *nameRegistry) acquire(name string) (*nameOwnerDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.acquires++
	if cur := r.owner[name]; cur != nil && !cur.isGone() {
		return nil, errDeviceBusy
	}
	dev := &nameOwnerDevice{name: name, owner: r}
	r.owner[name] = dev
	return dev, nil
}

func (r *nameRegistry) release(name string, dev *nameOwnerDevice) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.owner[name] == dev {
		delete(r.owner, name)
	}
}

func (r *nameRegistry) liveOwners() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, dev := range r.owner {
		if !dev.isGone() {
			n++
		}
	}
	return n
}

func (r *nameRegistry) acquireCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.acquires
}

func (d *nameOwnerDevice) isGone() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gone
}

func (d *nameOwnerDevice) SetHostWANIP(netip.Addr) error { return nil }

func (d *nameOwnerDevice) Read([]byte) (int, error) { return 0, nil }

func (d *nameOwnerDevice) Write(p []byte) (int, error) { return len(p), nil }

func (d *nameOwnerDevice) Close() error {
	d.mu.Lock()
	already := d.gone
	d.gone = true
	d.mu.Unlock()
	if !already {
		d.owner.release(d.name, d)
	}
	return nil
}

// withNameOwnedWANDevice swaps the device constructor for one backed by reg and
// restores the production constructor when the test ends.
func withNameOwnedWANDevice(t *testing.T, reg *nameRegistry) {
	t.Helper()
	prev := newProductionWANDevice
	newProductionWANDevice = func(name string) (forwarder.PacketDevice, error) {
		return reg.acquire(name)
	}
	t.Cleanup(func() { newProductionWANDevice = prev })
}

// seededStore is a policy.Store preloaded with a usable last-known-good
// generation, so a first activation can publish real rules without any network
// fetch. That keeps the test offline while still exercising the true activation
// path.
func seededStore(t *testing.T) policy.Store {
	t.Helper()
	m := &memoryStore{}
	gen := &policy.Generation{
		SchemaVersion: 1,
		GenerationID:  "gen-seed",
		Version:       1,
		Domains:       map[string]uint8{"example.com": 1},
	}
	gen.ContentHash = policy.ComputeContentHash(gen.Domains, gen.CIDRs)
	m.committed = gen
	return m
}

// repeatedEnableSettings returns valid settings representing what an operator
// re-saves: the source list and interval.
func repeatedEnableSettings(t *testing.T) policy.Settings {
	t.Helper()
	s := policy.DefaultSettings()
	s.Enabled = true
	s.Preset = policy.PresetCustom
	s.CustomURLs = []string{"https://lists.example/policy.lst"}
	s.SyncInterval = int64(policy.MinSyncInterval.Seconds())
	if err := s.Validate(); err != nil {
		t.Fatalf("fixture settings invalid: %v", err)
	}
	return s
}

// activateOnce starts policy routing through the production entry point.
func activateOnce(svc *Service, settings policy.Settings, store policy.Store) error {
	return svc.StartPolicyRouting(context.Background(), settings, store, string(settings.Preset))
}

// TestRepeatedEnableDoesNotRebuildWANDevice is the reproduction oracle for
// DEV_RESTART_DIAGNOSIS §2b.
//
// RED on the unfixed lifecycle: the second activation constructed a second device
// for the same name, got EBUSY, and surfaced
// `create production wan device: device or resource busy`, which the admin PUT
// answers with 422 and a silent rollback of the operator's settings.
//
// GREEN once re-activation owns exactly one device: no second construction is
// attempted, and the failure that remains is a content failure, never a device
// conflict.
func TestRepeatedEnableDoesNotRebuildWANDevice(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)
	t.Cleanup(func() { svc.StopPolicyRouting() })

	settings := repeatedEnableSettings(t)
	store := seededStore(t)

	if err := activateOnce(svc, settings, store); err != nil {
		t.Fatalf("first activation failed: %v", err)
	}
	if !svc.PBREnabled() {
		t.Fatal("PBR not enabled after the first activation")
	}
	firstAcquires := reg.acquireCount()
	if firstAcquires < 1 {
		t.Fatalf("first activation constructed %d devices, want at least 1", firstAcquires)
	}

	// Second enable on the same Service with policy already on.
	err := activateOnce(svc, settings, store)

	// The defect's signature must be gone.
	if errors.Is(err, errDeviceBusy) {
		t.Fatalf("re-saving enabled settings tried to rebuild the WAN device and hit EBUSY "+
			"(the admin PUT would answer 422 and roll the record back): %v", err)
	}
	if after := reg.acquireCount(); after != firstAcquires {
		t.Fatalf("repeated update constructed %d extra device(s); the installed single-owner "+
			"device must be reused, not rebuilt", after-firstAcquires)
	}

	// Offline there is no reachable source, so a live update legitimately fails on
	// content. That failure must be the documented activation error so the API can
	// explain it, not a device or lifetime error.
	if err != nil && !errors.Is(err, ErrPolicyActivationNoRules) {
		t.Fatalf("repeated update failed with an unexpected class: %v", err)
	}

	// The healthy data path is still installed and still owns the name.
	if !svc.PBREnabled() {
		t.Error("repeated update disabled the working data path")
	}
	if got := reg.liveOwners(); got != 1 {
		t.Fatalf("live owners of the WAN device name = %d, want exactly 1", got)
	}
}

// TestRepeatedUpdateDoesNotTearDownHealthyDataPath proves the correction keeps the
// installed data path instead of rebuilding it. Rebuilding would drop live flows
// for a change that does not affect the device at all, and the assignment
// explicitly forbids blindly tearing down a healthy data path.
func TestRepeatedUpdateDoesNotTearDownHealthyDataPath(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)
	t.Cleanup(func() { svc.StopPolicyRouting() })

	settings := repeatedEnableSettings(t)
	store := seededStore(t)

	if err := activateOnce(svc, settings, store); err != nil {
		t.Fatalf("first activation failed: %v", err)
	}
	firstMatcher := svc.PolicyMatcher()
	firstEgress := svc.DirectEgress()
	if firstMatcher == nil || firstEgress == nil {
		t.Fatal("first activation did not install a matcher and direct-egress manager")
	}

	_ = activateOnce(svc, settings, store)

	if svc.PolicyMatcher() != firstMatcher {
		t.Error("repeated update replaced the live matcher; the data path is being rebuilt for a settings-only change")
	}
	if svc.DirectEgress() != firstEgress {
		t.Error("repeated update replaced the live direct-egress manager; live flows would be dropped")
	}
}

// TestRepeatedEnableFailureKeepsPreviousConfiguration proves the failure path keeps
// the existing rollback contract: when an update cannot publish a usable snapshot,
// the previous working configuration stays live and stays registered. The admin
// PUT rolls the persisted record back on error, so the record and the live rules
// must agree afterwards.
func TestRepeatedEnableFailureKeepsPreviousConfiguration(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)
	t.Cleanup(func() { svc.StopPolicyRouting() })

	settings := repeatedEnableSettings(t)
	if err := activateOnce(svc, settings, seededStore(t)); err != nil {
		t.Fatalf("first activation failed: %v", err)
	}
	firstMatcher := svc.PolicyMatcher()
	firstEgress := svc.DirectEgress()

	// A store that cannot load and a source that cannot resolve: the update has no
	// usable snapshot to publish.
	broken := &memoryStore{loadErr: errors.New("durable store unavailable")}
	unresolvable := repeatedEnableSettings(t)
	unresolvable.CustomURLs = []string{"https://unreachable.example.invalid/x.lst"}

	err := activateOnce(svc, unresolvable, broken)
	if err == nil {
		t.Fatal("an update with no publishable snapshot must fail closed")
	}
	if !errors.Is(err, ErrPolicyActivationNoRules) {
		t.Fatalf("update failure = %v, want ErrPolicyActivationNoRules so the API can explain it", err)
	}
	if errors.Is(err, errDeviceBusy) {
		t.Fatal("a refused update must not fail with a device conflict")
	}

	// Rollback consistency: the previous configuration remains live and registered.
	if !svc.PBREnabled() {
		t.Error("a refused update disabled the working data path")
	}
	if svc.PolicyMatcher() != firstMatcher {
		t.Error("a refused update swapped out the working matcher")
	}
	if svc.DirectEgress() != firstEgress {
		t.Error("a refused update replaced the working direct-egress manager")
	}
	if cfg := svc.getPBRConfig(); cfg == nil {
		t.Error("a refused update removed the working PBR config; disable/status would see nothing")
	}
	if got := reg.liveOwners(); got != 1 {
		t.Fatalf("live device owners after a refused update = %d, want the original 1", got)
	}
}
