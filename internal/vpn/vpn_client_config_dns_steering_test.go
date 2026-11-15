package vpn

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	mdns "github.com/miekg/dns"
)

var (
	awgDefaultDNS1 = awg.AWGDefaults["dns1"]
	awgDefaultDNS2 = awg.AWGDefaults["dns2"]
)

func parseClientConfigDNS(t *testing.T, config string) string {
	t.Helper()
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "DNS = ") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "DNS = "))
		}
	}
	t.Fatalf("client configuration has no DNS directive:\n%s", config)
	return ""
}

func newSteeringPBRConfig(t *testing.T, gwDNS netip.Addr) PBRConfig {
	t.Helper()
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("198.51.200.0/24\n"), policy.Source{
		ID:     "steering-cidrs",
		Format: policy.FormatIPv4,
	}, policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("policy Parse: %v", err)
	}
	matcher := policy.NewMatcher()
	snap, err := policy.CompileSnapshot(1, "gen-steering", []policy.SourceParsedRules{
		{SourceID: "steering-cidrs", Rules: rules},
	})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	matcher.Publish(snap)

	routeCache := NewMemoryRouteCache()
	routeCache.AttachMatcher(matcher)

	resolver := &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		return resp, nil
	}}
	srv, err := gatewaydns.NewServer(gatewaydns.ServerConfig{Gateway: netip.AddrPortFrom(gwDNS, 53)}, resolver, matcher)
	if err != nil {
		t.Fatalf("gateway DNS server: %v", err)
	}
	gw, err := gatewaydns.NewGateway(gatewaydns.GatewayConfig{
		Gateway:                  netip.AddrPortFrom(gwDNS, 53),
		RouteObserver:            routeCache,
		InterceptAllDestinations: true,
	}, srv)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	return PBRConfig{
		Enabled:       true,
		HostWANIP:     netip.MustParseAddr("203.0.113.10"),
		GatewayDNSIP:  gwDNS,
		WANDevice:     &mockPBRDevice{},
		RouteCache:    routeCache,
		PolicyMatcher: matcher,
		DNSGateway:    gw,
	}
}

// TestGenerateClientConfig_DNSSteeringFollowsPolicyState proves the generated
// client configuration steers clients to the policy resolver while policy
// routing is active and keeps the existing external resolvers while it is
// inactive, in both directions.
func TestGenerateClientConfig_DNSSteeringFollowsPolicyState(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "dns-steering-user", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	assertDNS := func(step, want string, steering bool) {
		t.Helper()
		config, _, err := svc.GenerateClientConfig(ctx, userID)
		if err != nil {
			t.Fatalf("%s: GenerateClientConfig failed: %v", step, err)
		}
		if got := parseClientConfigDNS(t, config); got != want {
			t.Fatalf("%s: DNS = %q, want %q\n%s", step, got, want, config)
		}
		if steering && strings.Contains(config, awgDefaultDNS1) {
			t.Fatalf("%s: active steering still pushed an external resolver:\n%s", step, config)
		}
	}

	defaultDNS := awgDefaultDNS1 + ", " + awgDefaultDNS2
	assertDNS("policy routing inactive", defaultDNS, false)

	gwDNS := netip.MustParseAddr("10.100.0.1")
	if err := svc.ConfigurePBR(newSteeringPBRConfig(t, gwDNS)); err != nil {
		t.Fatalf("ConfigurePBR failed: %v", err)
	}
	assertDNS("policy routing active", gwDNS.String(), true)

	if err := svc.TeardownPBR(); err != nil {
		t.Fatalf("TeardownPBR failed: %v", err)
	}
	assertDNS("policy routing inactive again", defaultDNS, false)
}
