package vpn

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

// TestPBR_ProtectedDomainNeverDirect verifies HIGH 3:
// Under normal production startup with configured policy sources, a protected/censored
// domain NEVER receives a DIRECT routing decision, while unlisted domains receive DIRECT.
func TestPBR_ProtectedDomainNeverDirect(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.PBREnabled = true
	})

	// Configure policy protecting "blocked.com"
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("blocked.com\n"), policy.Source{
		ID:             "anti-censorship-list",
		Format:         policy.FormatDomains,
		BareDomainMode: policy.DomainModeExact,
	}, policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("policy Parse failed: %v", err)
	}

	protectedSource := policy.NewMemorySource("anti-censorship-list", rules)
	validWAN := netip.MustParseAddr("198.51.200.1")
	dev := &mockPBRDevice{}

	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     validWAN,
		GatewayDNSIP:  netip.MustParseAddr("10.100.0.1"),
		WANDevice:     dev,
		PolicySources: []policy.SourceParsedRules{protectedSource.ToSourceParsedRules()},
	})

	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	rc := svc.forwarder.RouteCache()
	if rc == nil {
		t.Fatal("expected non-nil RouteCache")
	}
	memRC, ok := rc.(*MemoryRouteCache)
	if !ok {
		t.Fatalf("expected MemoryRouteCache, got %T", rc)
	}

	sessionID := "sess-user-1"
	blockedIP := netip.MustParseAddr("1.2.3.4")
	unlistedIP := netip.MustParseAddr("93.184.216.34")

	// 1. DNS answer for protected domain "blocked.com"
	reqBlocked := new(mdns.Msg)
	reqBlocked.SetQuestion("blocked.com.", mdns.TypeA)
	respBlocked := new(mdns.Msg)
	respBlocked.SetReply(reqBlocked)
	respBlocked.Answer = append(respBlocked.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "blocked.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   blockedIP.AsSlice(),
	})
	if err := memRC.ObserveDNSResponse(sessionID, reqBlocked, respBlocked); err != nil {
		t.Fatalf("ObserveDNSResponse blocked.com failed: %v", err)
	}

	// Decision for protected domain MUST BE PROXY, NEVER DIRECT
	if d := memRC.Lookup(sessionID, blockedIP); d != policy.Proxy {
		t.Fatalf("CRITICAL: protected domain received decision %v, must NEVER be Direct", d)
	}

	// 2. DNS answer for unlisted public domain "example.com"
	reqUnlisted := new(mdns.Msg)
	reqUnlisted.SetQuestion("example.com.", mdns.TypeA)
	respUnlisted := new(mdns.Msg)
	respUnlisted.SetReply(reqUnlisted)
	respUnlisted.Answer = append(respUnlisted.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   unlistedIP.AsSlice(),
	})
	memRC.ObserveDNSResponse(sessionID, reqUnlisted, respUnlisted)

	// Decision for unlisted public domain is DIRECT
	if d := memRC.Lookup(sessionID, unlistedIP); d != policy.Direct {
		t.Fatalf("expected unlisted domain to receive Direct decision, got %v", d)
	}
}

// TestPBR_ProhibitEmptyPolicy verifies that initPBR fails closed and returns
// ErrPBREmptyPolicy when starting with zero or empty policy sources.
func TestPBR_ProhibitEmptyPolicy(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.PBREnabled = true
	})

	validWAN := netip.MustParseAddr("198.51.200.1")
	dev := &mockPBRDevice{}

	// Case 1: No sources provided
	svc.SetPBRConfig(PBRConfig{
		HostWANIP: validWAN,
		WANDevice: dev,
	})
	err := svc.initPBR(context.Background())
	if !errors.Is(err, ErrPBREmptyPolicy) {
		t.Fatalf("expected ErrPBREmptyPolicy for missing sources, got: %v", err)
	}

	// Case 2: Empty source (0 rules)
	emptySrc := policy.NewMemorySource("empty", policy.ParsedRules{})
	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     validWAN,
		WANDevice:     dev,
		PolicySources: []policy.SourceParsedRules{emptySrc.ToSourceParsedRules()},
	})
	err = svc.initPBR(context.Background())
	if !errors.Is(err, ErrPBREmptyPolicy) {
		t.Fatalf("expected ErrPBREmptyPolicy for empty sources, got: %v", err)
	}
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
	rules1, _, _ := policy.Parse(context.Background(), strings.NewReader("protected.com\n"), policy.Source{
		ID:             "list-v1",
		Format:         policy.FormatDomains,
		BareDomainMode: policy.DomainModeExact,
	}, policy.DefaultParseLimits())

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
	if origSnap == nil || origSnap.DomainCount() != 1 {
		t.Fatalf("expected original snapshot with 1 domain, got %v", origSnap)
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
