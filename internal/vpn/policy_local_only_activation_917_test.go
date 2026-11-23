package vpn

// Behavioural coverage for the local-only activation change (#917): a policy
// record whose only rules are operator-supplied IPv4 exceptions must activate,
// and so must a record with no rules at all — the destination classifier is the
// routing authority and the exception list is an optional override.
//
// The point of these cases is that they never configure a source. Before this
// slice, activation needed a fetched list because a preset was mandatory, so a
// local-only record could not activate at all. The positive cases prove the
// fetch-free path really installs the classifier over a published snapshot, and
// the negative case proves activation still refuses when that classifier is
// genuinely unavailable — with PBR left off.

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// localOnlySettings is a record with no source selection at all: what an
// operator who only wants address exceptions saves.
func localOnlySettings(entries []string) policy.Settings {
	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = entries
	return settings
}

// noopWANDevice satisfies forwarder.PacketDevice without touching the host, so
// a test exercises the policy configuration while the production activation
// ordering stays intact.
type noopWANDevice struct{}

func (noopWANDevice) Read([]byte) (int, error)  { return 0, errors.New("no traffic") }
func (noopWANDevice) Write([]byte) (int, error) { return 0, errors.New("no traffic") }
func (noopWANDevice) Close() error              { return nil }

type localActivationOutcome struct {
	err           error
	pbrEnabled    bool
	classifierSet bool
	snapshotCIDRs int
}

func runLocalOnlyActivation(t *testing.T, settings policy.Settings) localActivationOutcome {
	t.Helper()
	return runLocalOnlyActivationWith(t, settings, nil)
}

// runLocalOnlyActivationWithoutClassifier models a host whose committed routing
// authority is unusable: the classifier constructor returns nil, exactly as it
// does when the shipped inventory or the embedded ASN table cannot be read.
//
// This is the control that keeps the zero-exception fix from becoming "always
// allow". An empty override list is only a valid policy when something else
// classifies the destination; with no classifier, every destination answers
// "uncovered", so nothing can route DIRECT and the policy would be inert while
// the panel reported it enabled.
func runLocalOnlyActivationWithoutClassifier(t *testing.T, settings policy.Settings) localActivationOutcome {
	t.Helper()
	return runLocalOnlyActivationWith(t, settings,
		func(*policy.InventoryOverride) forwarder.DestinationClassifier { return nil })
}

// runLocalOnlyActivationWith drives the real StartPolicyRouting path with the
// classifier constructor under test control. A nil factory leaves the production
// constructor in place. The substitution is installed for the duration of the
// activation and restored afterwards, so a failing case cannot leak it.
func runLocalOnlyActivationWith(t *testing.T, settings policy.Settings, classifierFactory func(*policy.InventoryOverride) forwarder.DestinationClassifier) localActivationOutcome {
	t.Helper()
	if classifierFactory != nil {
		t.Cleanup(SetDestinationClassifierFactoryForTest(classifierFactory))
	}

	svc := serviceForActivation(t)
	t.Cleanup(func() { svc.StopPolicyRouting() })
	t.Cleanup(SetWANDeviceFactoryForTest(func(string) (forwarder.PacketDevice, error) {
		return noopWANDevice{}, nil
	}))

	// No stored generation, so the synchronous cycle is the only possible
	// publisher. That is what makes "activation needs no external source"
	// observable rather than inferred. fs.ErrNotExist is what a genuine fresh
	// install's FileStore returns; any other error would be an unusable store,
	// which the activation handshake is right to refuse.
	store := &memoryStore{loadErr: fs.ErrNotExist}
	err := svc.StartPolicyRouting(context.Background(), settings, store)

	out := localActivationOutcome{err: err, pbrEnabled: svc.PBREnabled()}
	if matcher := svc.PolicyMatcher(); matcher != nil {
		if snap := matcher.Current(); snap != nil {
			out.snapshotCIDRs = snap.CIDRCount()
		}
	}
	out.classifierSet = svc.DestinationClassifierForTest() != nil
	return out
}

// TestLocalOnlyPolicyActivatesWithoutAnySource is the positive direction: no
// preset, no custom URLs, no fetch, and the operator's prefixes are published.
func TestLocalOnlyPolicyActivatesWithoutAnySource(t *testing.T) {
	settings := localOnlySettings([]string{
		"# operator PROXY exceptions",
		"203.0.113.0/24",
		"198.51.100.7",
	})
	if err := settings.Validate(); err != nil {
		t.Fatalf("a local-only record must be valid: %v", err)
	}
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	if len(cfg.LocalRules.CIDRs) != 2 {
		t.Fatalf("derived rules = %d prefixes, want the 2 operator entries", len(cfg.LocalRules.CIDRs))
	}

	out := runLocalOnlyActivation(t, settings)
	if out.err != nil {
		t.Fatalf("a non-empty local exception list must activate policy routing: %v", out.err)
	}
	if !out.pbrEnabled {
		t.Fatal("PBR is off after a successful activation")
	}
	if !out.classifierSet {
		t.Fatal("no destination classifier installed after activation")
	}
	if out.snapshotCIDRs != 2 {
		t.Fatalf("snapshot prefixes = %d, want the 2 operator entries", out.snapshotCIDRs)
	}
}

// TestEmptyLocalPolicyRefusesAndLeavesPBROff used to assert that zero rules
// refuse activation. That was the conflation this round corrects: an empty
// operator override list and an unavailable routing authority are different
// states, and only the second may refuse.
//
// The replacement is paired, because one direction alone cannot show the
// difference. With the classifier installed, an empty list activates — every
// destination takes the classifier's answer. With the classifier unavailable,
// activation still refuses, which is the control that stops this from becoming
// "always allow". Both run through the real StartPolicyRouting path.
func TestEmptyLocalPolicyRefusesAndLeavesPBROff(t *testing.T) {
	t.Run("authority present activates with zero overrides", func(t *testing.T) {
		out := runLocalOnlyActivation(t, localOnlySettings(nil))
		if out.err != nil {
			t.Fatalf("activation with zero exceptions must succeed when the classifier is installed, "+
				"because the classifier is the routing authority and the list is an optional override: %v", out.err)
		}
		if !out.pbrEnabled {
			t.Fatal("PBR is off after activating a zero-exception policy")
		}
		if !out.classifierSet {
			t.Fatal("no destination classifier installed, so nothing would classify a destination")
		}
		// The published snapshot holds the operator's rules and nothing else. A
		// sentinel CIDR here would be a rule the dataplane acts on that the
		// operator never supplied.
		if out.snapshotCIDRs != 0 {
			t.Fatalf("snapshot prefixes = %d, want 0: zero exceptions must publish an empty rule set, "+
				"not a placeholder that the dataplane would route on", out.snapshotCIDRs)
		}
	})

	t.Run("authority absent still refuses", func(t *testing.T) {
		out := runLocalOnlyActivationWithoutClassifier(t, localOnlySettings(nil))
		if out.err == nil {
			t.Fatal("activation succeeded with no routing authority installed; every destination would " +
				"answer uncovered, so nothing could route DIRECT and the policy would be inert")
		}
		if !errors.Is(out.err, ErrPolicyActivationNoRules) {
			t.Fatalf("expected ErrPolicyActivationNoRules, got: %v", out.err)
		}
		if out.pbrEnabled {
			t.Fatal("PBR is enabled after a refused activation")
		}
		if out.classifierSet {
			t.Fatal("a classifier was installed despite a refused activation")
		}
	})

	// The refusal must not be about the rule count. The same absent authority with
	// a configured exception list must refuse too, or the guard would be a rule-count
	// check in disguise that a non-empty list silently satisfies.
	t.Run("authority absent refuses even with exceptions configured", func(t *testing.T) {
		out := runLocalOnlyActivationWithoutClassifier(t, localOnlySettings([]string{"203.0.113.0/24"}))
		if !errors.Is(out.err, ErrPolicyActivationNoRules) {
			t.Fatalf("expected ErrPolicyActivationNoRules with no classifier, got: %v", out.err)
		}
		if out.pbrEnabled {
			t.Fatal("PBR is enabled after a refused activation")
		}
	})
}

// TestZeroExceptionPolicySurvivesDisableAndReEnable covers the toggle half of the
// owner's upgrade scenario, which the restart tests do not: an operator who
// disables policy routing and turns it back on while the exception list is empty
// must get an active data path, not a refusal.
//
// The second activation is a cold start against the durable store the first one
// wrote, so it primes the empty generation as last-known-good — the same state an
// upgraded installation is in after clearing its final exception.
func TestZeroExceptionPolicySurvivesDisableAndReEnable(t *testing.T) {
	settings := localOnlySettings(nil)
	svc := serviceForActivation(t)
	t.Cleanup(func() { svc.StopPolicyRouting() })
	t.Cleanup(SetWANDeviceFactoryForTest(func(string) (forwarder.PacketDevice, error) {
		return noopWANDevice{}, nil
	}))

	// No load error: the store starts empty and then holds what the first
	// activation commits, so the second activation reads a real durable record.
	store := &memoryStore{}

	if err := svc.StartPolicyRouting(context.Background(), settings, store); err != nil {
		t.Fatalf("first activation with zero exceptions: %v", err)
	}
	if store.commitCount() == 0 {
		t.Fatal("the first activation committed no generation, so there would be nothing to re-activate from")
	}

	svc.StopPolicyRouting()
	if svc.PBREnabled() {
		t.Fatal("policy routing is still active after the operator disabled it")
	}

	if err := svc.StartPolicyRouting(context.Background(), settings, store); err != nil {
		t.Fatalf("re-enabling with zero exceptions must activate, not refuse: %v", err)
	}
	if !svc.PBREnabled() {
		t.Fatal("policy routing is off after re-enabling a zero-exception record")
	}
	if svc.DestinationClassifierForTest() == nil {
		t.Fatal("no destination classifier installed, so nothing would classify a destination")
	}
	snap := svc.PolicyMatcher().Current()
	if snap == nil {
		t.Fatal("no snapshot published after re-enabling")
	}
	if got := snap.CIDRCount(); got != 0 {
		t.Fatalf("published snapshot = %d rules, want 0: a re-enable must not invent a placeholder rule", got)
	}
}

// The syncer accepts a configuration whose only rules are local, and it accepts
// the empty configuration too: the refusal this test used to assert here has moved
// to activation, which is the only layer that can tell an empty override list from
// an absent routing authority.
func TestSyncerAcceptsLocalOnlyConfiguration(t *testing.T) {
	local := localOnlySettings([]string{"203.0.113.0/24"})
	cfg, err := local.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	if _, err := policy.NewSyncer(policy.NewMatcher(), policy.NewFileStore(t.TempDir()), cfg); err != nil {
		t.Fatalf("NewSyncer refused a local-only configuration: %v", err)
	}

	// An empty record is a valid override-free policy, so the cycle publishes an
	// empty snapshot rather than refusing. The negative direction — activation with
	// no routing authority — is asserted in
	// TestEmptyLocalPolicyRefusesAndLeavesPBROff.
	empty := localOnlySettings(nil)
	emptyCfg, err := empty.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	emptyMatcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(emptyMatcher, policy.NewFileStore(t.TempDir()), emptyCfg)
	if err != nil {
		t.Fatalf("NewSyncer refused an empty configuration: %v", err)
	}
	res, syncErr := syncer.SyncOnce(context.Background())
	if syncErr != nil {
		t.Fatalf("an empty override list must publish; the routing authority is the classifier: %v", syncErr)
	}
	if !res.Published {
		t.Fatal("an empty policy cycle reported Published=false")
	}
	if snap := emptyMatcher.Current(); snap == nil || snap.CIDRCount() != 0 {
		t.Fatalf("published snapshot = %v, want an empty rule set: no sentinel CIDR may be invented", snap)
	}
}
