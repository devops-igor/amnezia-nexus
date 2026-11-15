package vpn

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// These tests cover the #824 slice-1 wiring in this package: the resolver dials
// the configured list, the effective default is the AdGuard pair, a live
// settings change swaps the list without rebuilding the data path, and the
// policy status reports the last upstream outcome.

// upstreamTestServer is a real UDP DNS responder so the resolver exercises its
// production exchange path.
type upstreamTestServer struct {
	addr netip.AddrPort
}

func startUpstreamTestServer(t *testing.T, answer netip.Addr) *upstreamTestServer {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	server := &mdns.Server{
		PacketConn: conn,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			m := new(mdns.Msg)
			m.SetReply(req)
			m.Answer = append(m.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
				A:   answer.AsSlice(),
			})
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return &upstreamTestServer{addr: netip.MustParseAddrPort(conn.LocalAddr().String())}
}

// blackholeUpstream returns a loopback address that receives packets and never
// answers, which is how a blocked provider behaves.
func blackholeUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return netip.MustParseAddrPort(conn.LocalAddr().String())
}

func upstreamEntry(addr netip.AddrPort) policy.Upstream {
	return policy.Upstream{Address: addr.Addr().String(), Port: int(addr.Port()), Transport: policy.TransportPlain}
}

func upstreamQuery(name string) *mdns.Msg {
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	return req
}

// TestPolicyStatusReportsUpstreamHealth is the operator-facing acceptance: a
// simulated transport failure is reported with its kind, and a later success
// clears it.
func TestPolicyStatusReportsUpstreamHealth(t *testing.T) {
	blocked := blackholeUpstream(t)
	resolver, err := gatewaydns.NewUpstreamResolver(gatewaydns.ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamEntry(blocked)},
		QueryTimeout:          3 * time.Second,
		AttemptTimeout:        50 * time.Millisecond,
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}

	svc := &Service{}
	svc.SetPBRConfig(PBRConfig{DNSResolver: resolver})
	t.Cleanup(svc.clearPBRConfig)

	if _, err := resolver.Exchange(context.Background(), upstreamQuery("blocked.example.")); err == nil {
		t.Fatal("exchange against a black-holed upstream succeeded")
	}
	status := svc.PolicyStatusSnapshot()
	if status.LastUpstreamFailureKind != string(gatewaydns.FailureTimeout) {
		t.Fatalf("last_upstream_failure_kind = %q, want %q", status.LastUpstreamFailureKind, gatewaydns.FailureTimeout)
	}
	if status.LastUpstreamFailure != blocked.String() {
		t.Fatalf("last_upstream_failure = %q, want %q", status.LastUpstreamFailure, blocked.String())
	}
	if status.LastUpstream != "" {
		t.Fatalf("last_upstream = %q, want empty before any accepted answer", status.LastUpstream)
	}

	good := startUpstreamTestServer(t, netip.MustParseAddr("203.0.113.40"))
	if err := resolver.SetUpstreams([]policy.Upstream{upstreamEntry(good.addr)}); err != nil {
		t.Fatalf("SetUpstreams: %v", err)
	}
	if _, err := resolver.Exchange(context.Background(), upstreamQuery("recovered.example.")); err != nil {
		t.Fatalf("exchange against the recovered upstream failed: %v", err)
	}
	status = svc.PolicyStatusSnapshot()
	if status.LastUpstreamFailure != "" || status.LastUpstreamFailureKind != "" {
		t.Fatalf("a successful exchange left the failure state set: %+v", status)
	}
	if status.LastUpstream != good.addr.String() {
		t.Fatalf("last_upstream = %q, want %q", status.LastUpstream, good.addr.String())
	}
}

// TestPolicyStatusWithoutResolverReportsNoUpstream proves the extra fields stay
// empty when no policy resolver exists, so "no evidence" is not confused with a
// failure.
func TestPolicyStatusWithoutResolverReportsNoUpstream(t *testing.T) {
	svc := &Service{}
	svc.SetPBRConfig(PBRConfig{})
	t.Cleanup(svc.clearPBRConfig)

	status := svc.PolicyStatusSnapshot()
	if status.LastUpstream != "" || status.LastUpstreamFailure != "" || status.LastUpstreamFailureKind != "" {
		t.Fatalf("status without a resolver reported upstream data: %+v", status)
	}
}

// TestNewPolicyUpstreamResolverUsesConfiguredOrDefaults pins the resolver's
// effective list: the configured entries when present, the AdGuard default pair
// otherwise.
func TestNewPolicyUpstreamResolverUsesConfiguredOrDefaults(t *testing.T) {
	configured := []policy.Upstream{
		{Address: "9.9.9.9", Port: 53},
		{Address: "dns.example.com", Port: 5353},
	}
	resolver, err := newPolicyUpstreamResolver(configured)
	if err != nil {
		t.Fatalf("newPolicyUpstreamResolver(configured) = %v, want nil", err)
	}
	got := resolver.Upstreams()
	if len(got) != len(configured) {
		t.Fatalf("resolver upstreams = %v, want %v", got, configured)
	}
	for i := range configured {
		if got[i] != configured[i] {
			t.Fatalf("resolver upstream %d = %+v, want %+v", i, got[i], configured[i])
		}
	}

	defaults, err := newPolicyUpstreamResolver(nil)
	if err != nil {
		t.Fatalf("newPolicyUpstreamResolver(nil) = %v, want nil", err)
	}
	want := policy.DefaultUpstreams()
	got = defaults.Upstreams()
	if len(got) != len(want) {
		t.Fatalf("default resolver upstreams = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("default resolver upstream %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestInitPBRInstallsConfiguredUpstreams exercises the production activation
// path: the list handed to initPBR is what the live resolver dials.
func TestInitPBRInstallsConfiguredUpstreams(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) { c.PBREnabled = true })
	src := policy.NewMemorySource("default-production-policy", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	configured := []policy.Upstream{{Address: "9.9.9.9", Port: 53}, {Address: "149.112.112.112", Port: 53}}

	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     netip.MustParseAddr("198.51.100.77"),
		WANDevice:     &mockPBRDevice{},
		PolicySources: []policy.SourceParsedRules{src.ToSourceParsedRules()},
		UpstreamDNS:   configured,
	})
	if err := svc.initPBR(context.Background()); err != nil {
		t.Fatalf("initPBR failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.TeardownPBR() })

	pbrCfg := svc.getPBRConfig()
	if pbrCfg == nil || pbrCfg.DNSResolver == nil {
		t.Fatal("initPBR did not install an upstream resolver")
	}
	got := pbrCfg.DNSResolver.Upstreams()
	if len(got) != len(configured) {
		t.Fatalf("live resolver upstreams = %v, want %v", got, configured)
	}
	for i := range configured {
		if got[i] != configured[i] {
			t.Fatalf("live resolver upstream %d = %+v, want %+v", i, got[i], configured[i])
		}
	}
}

// TestInitPBRWithoutConfiguredUpstreamsUsesDefaultPair is the default-effective
// configuration acceptance: an activation that carries no list dials the
// AdGuard pair.
func TestInitPBRWithoutConfiguredUpstreamsUsesDefaultPair(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) { c.PBREnabled = true })
	src := policy.NewMemorySource("default-production-policy", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})

	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     netip.MustParseAddr("198.51.100.77"),
		WANDevice:     &mockPBRDevice{},
		PolicySources: []policy.SourceParsedRules{src.ToSourceParsedRules()},
	})
	if err := svc.initPBR(context.Background()); err != nil {
		t.Fatalf("initPBR failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.TeardownPBR() })

	pbrCfg := svc.getPBRConfig()
	if pbrCfg == nil || pbrCfg.DNSResolver == nil {
		t.Fatal("initPBR did not install an upstream resolver")
	}
	got := pbrCfg.DNSResolver.Upstreams()
	want := policy.DefaultUpstreams()
	if len(got) != len(want) {
		t.Fatalf("live resolver upstreams = %v, want the default pair %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("live resolver upstream %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// While policy routing is active the client configuration names the gateway
	// resolver, not the upstream: only the gateway's answers can become routing
	// evidence. The upstream list therefore drives the resolver alone here.
	gw := svc.deriveDefaultGatewayDNSIP().String()
	if dns1, dns2 := svc.clientConfigDNSServers(); dns1 != gw || dns2 != gw {
		t.Fatalf("active client configuration DNS = (%q, %q), want the gateway %q", dns1, dns2, gw)
	}
}

// TestApplyLiveUpstreamsSwapsInstalledResolver covers a settings change while
// policy routing is already live: the installed resolver takes the new list and
// keeps the old one when the new one is rejected.
func TestApplyLiveUpstreamsSwapsInstalledResolver(t *testing.T) {
	installed := []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	resolver, err := gatewaydns.NewUpstreamResolver(gatewaydns.ResolverConfig{Upstreams: installed})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	svc := &Service{}
	svc.SetPBRConfig(PBRConfig{DNSResolver: resolver})
	t.Cleanup(svc.clearPBRConfig)

	updated := policy.DefaultSettings()
	updated.UpstreamDNS = []policy.Upstream{{Address: "1.0.0.1", Port: 53}, {Address: "8.8.4.4", Port: 53}}
	if err := svc.applyLiveUpstreams(updated); err != nil {
		t.Fatalf("applyLiveUpstreams: %v", err)
	}
	got := resolver.Upstreams()
	if len(got) != 2 || got[0].Address != "1.0.0.1" || got[1].Address != "8.8.4.4" {
		t.Fatalf("live resolver upstreams = %v, want the new list", got)
	}

	// An empty list means "back to the effective defaults".
	if err := svc.applyLiveUpstreams(policy.DefaultSettings()); err != nil {
		t.Fatalf("applyLiveUpstreams(defaults): %v", err)
	}
	defaults := policy.DefaultUpstreams()
	got = resolver.Upstreams()
	if len(got) != len(defaults) || got[0] != defaults[0] {
		t.Fatalf("live resolver upstreams = %v, want the default pair %v", got, defaults)
	}

	// A rejected list must leave the installed one in effect.
	rejected := policy.DefaultSettings()
	rejected.UpstreamDNS = []policy.Upstream{{Address: "94.140.14.14", Port: 853, Transport: policy.TransportDoT}}
	if err := svc.applyLiveUpstreams(rejected); err == nil {
		t.Fatal("applyLiveUpstreams accepted an unimplemented transport")
	}
	if got := resolver.Upstreams(); len(got) != len(defaults) || got[0] != defaults[0] {
		t.Fatalf("a rejected update changed the installed list: %v", got)
	}
}

// TestApplyLiveUpstreamsWithoutRuntimeIsNoOp keeps the disabled path inert.
func TestApplyLiveUpstreamsWithoutRuntimeIsNoOp(t *testing.T) {
	svc := &Service{}
	svc.SetPBRConfig(PBRConfig{})
	t.Cleanup(svc.clearPBRConfig)

	if err := svc.applyLiveUpstreams(policy.DefaultSettings()); err != nil {
		t.Fatalf("applyLiveUpstreams with no runtime = %v, want nil", err)
	}
}

// TestContinuityResponderUsesConfiguredUpstreams keeps the issued-profile
// responder on the operator's list instead of a hardcoded provider, so a
// disabled deployment does not silently fall back to a blocked one. An empty
// list still yields the effective default pair.
func TestContinuityResponderUsesConfiguredUpstreams(t *testing.T) {
	var captured []gatewaydns.ResolverConfig
	original := newDNSContinuityResolver
	newDNSContinuityResolver = func(cfg gatewaydns.ResolverConfig) (gatewaydns.Resolver, error) {
		captured = append(captured, cfg)
		return &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			return resp, nil
		}}, nil
	}
	t.Cleanup(func() { newDNSContinuityResolver = original })

	svc := &Service{forwarder: forwarder.NewForwarder(nil, "10.100.0.0/16", 8)}
	t.Cleanup(svc.closeDNSContinuity)
	gateway := netip.MustParseAddr("10.100.0.1")

	configured := []policy.Upstream{{Address: "9.9.9.9", Port: 53}, {Address: "149.112.112.112", Port: 53}}
	svc.installDNSContinuityLocked(gateway, configured)
	if len(captured) != 1 {
		t.Fatalf("continuity resolver builds = %d, want 1", len(captured))
	}
	if len(captured[0].Upstreams) != len(configured) || captured[0].Upstreams[0] != configured[0] {
		t.Fatalf("continuity resolver upstreams = %v, want %v", captured[0].Upstreams, configured)
	}

	// Repeating the same install must not rebuild the responder.
	svc.installDNSContinuityLocked(gateway, configured)
	if len(captured) != 1 {
		t.Fatalf("repeated identical install rebuilt the responder: %d builds", len(captured))
	}

	// An empty list resolves through the effective default pair.
	svc.installDNSContinuityLocked(gateway, nil)
	if len(captured) != 2 {
		t.Fatalf("continuity resolver builds = %d, want 2", len(captured))
	}
	defaults := policy.DefaultUpstreams()
	if len(captured[1].Upstreams) != len(defaults) || captured[1].Upstreams[0] != defaults[0] {
		t.Fatalf("continuity resolver upstreams = %v, want the default pair %v", captured[1].Upstreams, defaults)
	}
}
