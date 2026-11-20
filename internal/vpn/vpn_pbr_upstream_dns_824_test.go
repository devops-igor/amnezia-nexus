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
	// The client configuration names the external resolvers the profile pair is
	// derived from, so the profile never depends on a resolver the panel runs. The
	// upstream list therefore drives the resolver alone.
	dns1, dns2 := defaultClientDNSServers()
	wantPair := renderedProfileDNS()
	if got := dns1 + ", " + dns2; got != wantPair {
		t.Fatalf("active client configuration DNS = %q, want the external pair %q", got, wantPair)
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

	// A DoT list is an accepted configuration and takes effect live, without
	// rebuilding the resolver or the data path.
	dot := policy.DefaultSettings()
	dot.UpstreamDNS = []policy.Upstream{
		{Address: "94.140.14.14", Transport: policy.TransportDoT},
		{Address: "dns.example.com", Port: 853, Transport: policy.TransportDoT},
	}
	if err := svc.applyLiveUpstreams(dot); err != nil {
		t.Fatalf("applyLiveUpstreams(dot): %v", err)
	}
	got = resolver.Upstreams()
	if len(got) != 2 || got[0].Transport != policy.TransportDoT || got[1].Address != "dns.example.com" {
		t.Fatalf("live resolver upstreams = %v, want the configured DoT list", got)
	}
	if got[0].Port != policy.DefaultDoTPort {
		t.Fatalf("live DoT upstream port = %d, want the effective default %d", got[0].Port, policy.DefaultDoTPort)
	}

	// A DoH list is accepted and takes effect live as well.
	doh := policy.DefaultSettings()
	doh.UpstreamDNS = []policy.Upstream{{Address: "dns.example.com", Transport: policy.TransportDoH}}
	if err := svc.applyLiveUpstreams(doh); err != nil {
		t.Fatalf("applyLiveUpstreams(doh): %v", err)
	}
	if got = resolver.Upstreams(); len(got) != 1 || got[0].Transport != policy.TransportDoH || got[0].Port != policy.DefaultDoHPort {
		t.Fatalf("live resolver upstreams = %v, want the DoH entry with its default port", got)
	}

	// Re-install the DoT list, then prove a transport this build does not know is
	// refused and the accepted list stays in effect.
	if err := svc.applyLiveUpstreams(dot); err != nil {
		t.Fatalf("applyLiveUpstreams(dot) again: %v", err)
	}
	rejected := policy.DefaultSettings()
	rejected.UpstreamDNS = []policy.Upstream{{Address: "dns.example.com", Port: 443, Transport: "quic"}}
	if err := svc.applyLiveUpstreams(rejected); err == nil {
		t.Fatal("applyLiveUpstreams accepted a transport this build does not implement")
	}
	if got := resolver.Upstreams(); len(got) != 2 || got[0].Transport != policy.TransportDoT {
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
