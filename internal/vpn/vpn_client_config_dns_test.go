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
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
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

// newGatewayResolverPBRConfig builds an active policy-routing configuration
// whose gateway answers plain DNS. It is exactly the state in which a
// configuration used to be steered at the panel resolver, so it is the state a
// generated profile must ignore.
func newGatewayResolverPBRConfig(t *testing.T, gwDNS netip.Addr) PBRConfig {
	t.Helper()
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("198.51.200.0/24\n"), policy.Source{
		ID:     "client-dns-cidrs",
		Format: policy.FormatIPv4,
	}, policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("policy Parse: %v", err)
	}
	matcher := policy.NewMatcher()
	snap, err := policy.CompileSnapshot(1, "gen-client-dns", []policy.SourceParsedRules{
		{SourceID: "client-dns-cidrs", Rules: rules},
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

// TestGenerateClientConfigCarriesExternalResolversOnly is the profile contract:
// a generated client configuration always carries the configured external
// resolvers and never the panel's gateway resolver, whatever state policy
// routing is in. A profile that named the gateway would depend on a resolver
// this build no longer runs.
func TestGenerateClientConfigCarriesExternalResolversOnly(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "client-dns-user", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	externalDNS := awgDefaultDNS1 + ", " + awgDefaultDNS2
	var gatewayDNS string

	assertExternalOnly := func(step string) {
		t.Helper()
		config, _, err := svc.GenerateClientConfig(ctx, userID)
		if err != nil {
			t.Fatalf("%s: GenerateClientConfig failed: %v", step, err)
		}
		if got := parseClientConfigDNS(t, config); got != externalDNS {
			t.Fatalf("%s: DNS = %q, want the external resolvers %q\n%s", step, got, externalDNS, config)
		}
		if gatewayDNS != "" && strings.Contains(config, gatewayDNS) {
			t.Fatalf("%s: the generated profile names the panel resolver %q:\n%s", step, gatewayDNS, config)
		}
	}

	assertExternalOnly("policy routing inactive")

	gwDNS := netip.MustParseAddr("10.100.0.1")
	gatewayDNS = gwDNS.String()
	if err := svc.ConfigurePBR(newGatewayResolverPBRConfig(t, gwDNS)); err != nil {
		t.Fatalf("ConfigurePBR failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.TeardownPBR() })
	if !svc.PBREnabled() {
		t.Fatal("fixture did not enable policy routing")
	}
	assertExternalOnly("policy routing active")

	if err := svc.TeardownPBR(); err != nil {
		t.Fatalf("TeardownPBR failed: %v", err)
	}
	assertExternalOnly("policy routing inactive again")
}

// TestTeardownPBRStopsAnsweringGatewayDNS is the other half of the same
// contract: once policy routing is disabled the panel installs no resolver, so
// a profile that still names the gateway address receives no DNS answer from
// it. Without this the policy resolver would keep answering after teardown.
func TestTeardownPBRStopsAnsweringGatewayDNS(t *testing.T) {
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 64)
	svc := &Service{forwarder: fwd}
	t.Cleanup(func() { _ = fwd.Stop() })

	gwDNS := netip.MustParseAddr("10.100.0.1")
	if err := svc.ConfigurePBR(newGatewayResolverPBRConfig(t, gwDNS)); err != nil {
		t.Fatalf("ConfigurePBR failed: %v", err)
	}
	if fwd.DNSHandler() == nil {
		t.Fatal("active policy routing installed no DNS handler")
	}

	if err := svc.TeardownPBR(); err != nil {
		t.Fatalf("TeardownPBR failed: %v", err)
	}
	if handler := fwd.DNSHandler(); handler != nil {
		t.Fatalf("teardown left %T installed: the panel would still answer gateway-addressed DNS", handler)
	}
}
