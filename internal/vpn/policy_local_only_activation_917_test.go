package vpn

// Behavioural coverage for the local-only activation change (#917): a policy
// record whose only rules are operator-supplied IPv4 exceptions must activate,
// and a record with no rules at all must still refuse.
//
// The point of these cases is that they never configure a source. Before this
// slice, activation needed a fetched list because a preset was mandatory, so a
// local-only record could not activate at all. Both directions are asserted
// here: the positive case proves the fetch-free path really installs the
// classifier over a published snapshot, and the negative case proves the
// non-empty-policy guard still refuses, with PBR left off.

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

// TestEmptyLocalPolicyRefusesAndLeavesPBROff is the negative direction the
// non-empty-policy guard owns: nothing published means no activation.
func TestEmptyLocalPolicyRefusesAndLeavesPBROff(t *testing.T) {
	out := runLocalOnlyActivation(t, localOnlySettings(nil))
	if out.err == nil {
		t.Fatal("activation succeeded with no policy rules at all")
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
}

// The syncer accepts a configuration whose only rules are local, and the
// empty-rule refusal stays with the publication guard rather than the
// constructor: an operator who enables policy routing with no rules must get the
// activation error, not a constructor error.
func TestSyncerAcceptsLocalOnlyConfiguration(t *testing.T) {
	local := localOnlySettings([]string{"203.0.113.0/24"})
	cfg, err := local.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	if _, err := policy.NewSyncer(policy.NewMatcher(), policy.NewFileStore(t.TempDir()), cfg); err != nil {
		t.Fatalf("NewSyncer refused a local-only configuration: %v", err)
	}

	// An empty record still must not publish. The guard that owns that decision
	// is the update cycle's zero-rule check, so the assertion is on its error.
	empty := localOnlySettings(nil)
	emptyCfg, err := empty.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	syncer, err := policy.NewSyncer(policy.NewMatcher(), policy.NewFileStore(t.TempDir()), emptyCfg)
	if err != nil {
		t.Fatalf("NewSyncer refused an empty configuration instead of leaving the refusal to the publication guard: %v", err)
	}
	res, syncErr := syncer.SyncOnce(context.Background())
	if syncErr == nil {
		t.Fatal("an empty policy cycle published a snapshot")
	}
	if res.Published {
		t.Fatal("an empty policy cycle reported Published")
	}
}
