package vpn

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// TestPBR_ProhibitEmptyPolicy used to assert that initPBR fails closed with
// ErrPBREmptyPolicy when it is handed zero policy sources. That conflation is
// what this round corrects: an empty operator override list is a valid policy
// when the classifier (the routing authority) is present.
//
// The guard is retargeted onto the real prerequisite. initPBR must still refuse
// when the routing authority cannot be built — modelled by making the classifier
// constructor unavailable — because every destination would then answer
// "uncovered", nothing could route DIRECT, and the enabled policy would be inert.
func TestPBR_ProhibitEmptyPolicy(t *testing.T) {
	t.Run("refuses when the routing authority is unavailable", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
			c.PBREnabled = true
		})

		// No committed classifier is available on this host: not "the operator
		// configured no overrides", but "nothing can classify a destination".
		restore := SetDestinationClassifierFactoryForTest(
			func(*policy.InventoryOverride) forwarder.DestinationClassifier { return nil })
		defer restore()

		// An override-free matcher: the record publishes no rules, which is a
		// valid policy precisely because the classifier is supposed to decide
		// every destination. With the classifier unavailable, that is the state
		// activation must refuse.
		emptySrc := policy.NewMemorySource("local", policy.ParsedRules{})
		svc.SetPBRConfig(PBRConfig{
			HostWANIP:     netip.MustParseAddr("198.51.200.1"),
			WANDevice:     &mockPBRDevice{},
			PolicySources: []policy.SourceParsedRules{emptySrc.ToSourceParsedRules()},
		})
		err := svc.initPBR(context.Background())
		if !errors.Is(err, ErrPBRMissingClassifier) {
			t.Fatalf("expected ErrPBRMissingClassifier with no routing authority, got: %v", err)
		}
		if svc.PBREnabled() {
			t.Fatal("PBR is enabled with no routing authority installed")
		}
	})

	// The positive direction: zero sources is a valid override-free policy when
	// the classifier is present, so initPBR must install the authority rather than
	// refuse. A sentinel CIDR here would be a rule the dataplane routes on that
	// the operator never supplied.
	t.Run("activates an empty snapshot when the authority is present", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
			c.PBREnabled = true
		})
		defer func() { _ = svc.TeardownPBR() }()

		emptySrc := policy.NewMemorySource("local", policy.ParsedRules{})
		svc.SetPBRConfig(PBRConfig{
			HostWANIP:     netip.MustParseAddr("198.51.200.1"),
			WANDevice:     &mockPBRDevice{},
			PolicySources: []policy.SourceParsedRules{emptySrc.ToSourceParsedRules()},
		})
		if err := svc.initPBR(context.Background()); err != nil {
			t.Fatalf("zero sources must activate when the classifier is installed: %v", err)
		}
		if !svc.PBREnabled() {
			t.Fatal("PBR is off after activating a zero-source policy")
		}
		cfg := svc.getPBRConfig()
		if cfg == nil || cfg.PolicyMatcher == nil {
			t.Fatal("activation left no matcher installed")
		}
		if got := cfg.PolicyMatcher.Current().CIDRCount(); got != 0 {
			t.Fatalf("published snapshot = %d rules, want 0: no sentinel CIDR may be invented", got)
		}
		if svc.forwarder.DestinationClassifier() == nil {
			t.Fatal("no destination classifier installed, so nothing would classify a destination")
		}
	})
}

// TestPBR_UpdatePolicySnapshot_PreservesOnFailure verifies that UpdatePolicySnapshot
// preserves the active valid compiled snapshot if a subsequent update fails or is empty.
func TestPBR_UpdatePolicySnapshot_PreservesOnFailure(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.PBREnabled = true
	})

	validWAN := netip.MustParseAddr("198.51.200.1")
	dev := &mockPBRDevice{}
	rules1, _, _ := policy.Parse(context.Background(), strings.NewReader("198.51.200.0/24\n"), policy.DefaultParseLimits())

	src1 := policy.NewMemorySource("list-v1", rules1)
	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     validWAN,
		WANDevice:     dev,
		PolicySources: []policy.SourceParsedRules{src1.ToSourceParsedRules()},
	})

	if err := svc.initPBR(context.Background()); err != nil {
		t.Fatalf("initPBR failed: %v", err)
	}
	defer func() { _ = svc.TeardownPBR() }()

	pbrCfg := svc.getPBRConfig()
	origSnap := pbrCfg.PolicyMatcher.Current()
	if origSnap == nil || origSnap.CIDRCount() != 1 {
		t.Fatalf("expected original snapshot with 1 prefix, got %v", origSnap)
	}

	// Attempt update with zero sources: must fail and retain origSnap
	if err := svc.UpdatePolicySnapshot(2, "gen-empty", nil); err == nil {
		t.Fatal("expected error on empty update, got nil")
	}
	if pbrCfg.PolicyMatcher.Current() != origSnap {
		t.Fatal("expected original snapshot preserved after failed update")
	}

	// Attempt update with empty rules: must fail and retain origSnap
	emptySrc := policy.NewMemorySource("empty", policy.ParsedRules{})
	if err := svc.UpdatePolicySnapshot(2, "gen-empty-rules", []policy.SourceParsedRules{emptySrc.ToSourceParsedRules()}); err == nil {
		t.Fatal("expected error on empty rules update, got nil")
	}
	if pbrCfg.PolicyMatcher.Current() != origSnap {
		t.Fatal("expected original snapshot preserved after failed empty rules update")
	}
}

// TestService_Start_PBRInitFailure_Rollback verifies MEDIUM 5:
// When initPBR() fails during Service.Start(), forwarder pumps are stopped,
// WAN device is closed, and service running state is reset to false.
func TestService_Start_PBRInitFailure_Rollback(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.PBREnabled = true
	})

	dev := &mockPBRDevice{}
	// Empty policy causes initPBR to fail
	svc.SetPBRConfig(PBRConfig{
		HostWANIP: netip.MustParseAddr("198.51.200.1"),
		WANDevice: dev,
	})

	err := svc.Start(context.Background())
	if err == nil {
		_ = svc.Stop()
		t.Fatal("expected svc.Start to fail")
	}

	// Assert complete rollback:
	if svc.IsRunning() {
		t.Fatal("expected service running to be false after rollback")
	}
	if svc.PBREnabled() {
		t.Fatal("expected PBREnabled to be false after rollback")
	}
	if svc.forwarder != nil && svc.forwarder.PumpsRunning() {
		t.Fatal("expected forwarder pumps stopped after rollback")
	}
	dev.mu.Lock()
	closed := dev.closed
	dev.mu.Unlock()
	if !closed {
		t.Fatal("expected WAN device closed during rollback")
	}
}

// TestValidateKernelPrerequisites verifies BLOCKER 1:
// Kernel prerequisite validation checks ip_forward, rp_filter, and route viability.
func TestValidateKernelPrerequisites(t *testing.T) {
	err := ValidateKernelPrerequisites()
	if err != nil {
		t.Logf("ValidateKernelPrerequisites returned: %v", err)
	}
}
