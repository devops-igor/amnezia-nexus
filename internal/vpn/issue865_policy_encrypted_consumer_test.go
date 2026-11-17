package vpn

// Issue #865: the policy-on (intercepting) Service-configured encrypted resolver
// proof — the last open consumer of the editor's configuration.
//
// Why this file exists. The continuity consumer (issue865_service_encrypted_
// consumer_test.go) proves a Service-configured encrypted list reaches a real
// client reply, but that responder deliberately produces no routing evidence.
// The policy resolver is the consumer that turns answers into DIRECT/PROXY
// evidence, and it is the reason the operator configures an upstream list at all.
// Until now it could not be reached by a fixture: the production constructor
// passes gatewaydns.ResolverConfig{Upstreams: ...} only, so loopback upstreams are
// refused and the trust/dial seams are unexported.
//
// What changed, and what did not. newPolicyUpstreamResolver is now a package-level
// variable with an unchanged body, exactly like newDNSContinuityResolver, so a test
// can wrap it. The wrapper in this file calls the real
// gatewaydns.NewUpstreamResolver on the configuration the Service actually passes
// and adds only AllowLoopbackUpstream; every other production behaviour — the
// default fallback, transport selection, certificate/hostname verification, pins —
// is the production one. The unchanged constructor is captured before the wrapper
// is installed and is asserted separately: it still refuses a loopback entry and
// still applies the exact defaults and the exact configured list.
//
// Nothing here prebuilds a resolver or gateway for the Service: the Service builds
// them through initPBR (the production startup path) from SetPBRConfig input, and
// a real client stack exchanges real DNS packets through the real forwarder.
//
// Trust isolation is the same child-process pattern as the continuity proof: the
// parent mints a private CA, the child inherits it only through SSL_CERT_FILE, and
// the host's trust store and every other process are untouched.

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

const (
	// issue865PolicyChildEnv marks the isolated child whose system trust store is
	// the private fixture CA.
	issue865PolicyChildEnv = "ISSUE865_POLICY_CHILD"
	// issue865PolicyFixtureDirEnv points the child at the material the parent minted.
	issue865PolicyFixtureDirEnv = "ISSUE865_POLICY_FIXTURE_DIR"
	// issue865PolicyMarker is printed only after every controlled result passed.
	issue865PolicyMarker = "ISSUE865_POLICY_PROOF_OK"

	issue865PolicySession = "issue865-policy-session"
	issue865PolicyPeer    = "issue865-policy-peer"
	issue865PolicyBackend = int64(17)
	// issue865ForeignResolver is the address the client queries: the policy gateway
	// intercepts a foreign resolver, so the query never leaves the process.
	issue865ForeignResolver = "8.8.8.8:53"
)

// TestIssue865PolicyEncryptedConsumer is the parent half. It mints the fixture
// material and runs the isolated child, failing on a skipped, silent or failing
// child rather than treating an empty run as a pass.
func TestIssue865PolicyEncryptedConsumer(t *testing.T) {
	if os.Getenv(issue865PolicyChildEnv) == "1" {
		t.Skip("this is the isolated child process; the parent test is the entry point")
	}
	dir := t.TempDir()
	trusted := issue865MintCA(t)
	trusted.issue865WriteCA(t, filepath.Join(dir, "ca.pem"))
	issue865WriteLeaf(t, dir, "leaf", trusted)
	untrusted := issue865MintCA(t)
	issue865WriteLeaf(t, dir, "other", untrusted)

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate this test binary: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable,
		"-test.run=^TestIssue865PolicyEncryptedConsumerChild$",
		"-test.v", "-test.count=1", "-test.timeout=120s")
	cmd.Env = append(os.Environ(),
		issue865PolicyChildEnv+"=1",
		"SSL_CERT_FILE="+filepath.Join(dir, "ca.pem"),
		issue865PolicyFixtureDirEnv+"="+dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated child failed: %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{
		"--- PASS: TestIssue865PolicyEncryptedConsumerChild",
		issue865PolicyMarker,
		"dot=1",
		"doh=1",
		"cert_refused=1",
		"pin_refused=1",
		"defaults_preserved=1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("isolated child output is missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "--- SKIP") {
		t.Fatalf("the isolated child skipped instead of proving the consumer:\n%s", text)
	}
	t.Logf("isolated child output:\n%s", text)
}

// issue865PolicyPhase is one fresh Service, forwarder, client and route cache wired
// through the production PBR startup path.
type issue865PolicyPhase struct {
	svc    *Service
	cache  *MemoryRouteCache
	client *continuityClient
}

// issue865StartPolicyPhase activates policy routing through Service.SetPBRConfig
// plus initPBR — the production startup path — with entry as the configured
// upstream list. No resolver or gateway is supplied by the test.
func issue865StartPolicyPhase(t *testing.T, entry policy.Upstream) *issue865PolicyPhase {
	t.Helper()

	rules, _, err := policy.Parse(context.Background(), strings.NewReader("198.51.200.0/24\n"), policy.Source{
		ID:     "issue865-cidrs",
		Format: policy.FormatIPv4,
	}, policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("compile policy rules: %v", err)
	}
	matcher := policy.NewMatcher()
	snapshot, err := policy.CompileSnapshot(1, "gen-issue865", []policy.SourceParsedRules{
		{SourceID: "issue865-cidrs", Rules: rules},
	})
	if err != nil {
		t.Fatalf("compile policy snapshot: %v", err)
	}
	matcher.Publish(snapshot)

	cache := NewMemoryRouteCache()
	cache.AttachMatcher(matcher)

	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 64)
	fwd.AttachBackendDevice(issue865PolicyBackend, &mockPBRDevice{})
	client, path := newContinuityClient(t, fwd, issue865PolicyPeer, issue865ClientIP)
	t.Cleanup(client.close)
	fwd.RegisterSessionWithReturnPath(issue865PolicySession, "issue865-policy-connection",
		issue865PolicyPeer, issue865ClientIP.String(), issue865PolicyBackend, path)

	svc := &Service{forwarder: fwd}
	svc.SetPBRConfig(PBRConfig{
		Enabled:       true,
		HostWANIP:     netip.MustParseAddr("198.18.0.2"),
		GatewayDNSIP:  issue865Gateway,
		WANDevice:     &mockPBRDevice{},
		RouteCache:    cache,
		PolicyMatcher: matcher,
		UpstreamDNS:   []policy.Upstream{entry},
	})
	if err := svc.initPBR(t.Context()); err != nil {
		t.Fatalf("production PBR activation with the configured upstream list failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.TeardownPBR() })
	return &issue865PolicyPhase{svc: svc, cache: cache, client: client}
}

// query sends one DNS query from the real client stack to a foreign resolver, which
// the active policy gateway intercepts.
func (p *issue865PolicyPhase) query(t *testing.T, name string, id uint16) *mdns.Msg {
	t.Helper()
	return continuityUDPQuery(t, p.client.stack, netip.MustParseAddrPort(issue865ForeignResolver), name, id)
}

// waitDecision waits for the answer to be observed as routing evidence.
func (p *issue865PolicyPhase) waitDecision(t *testing.T, ip netip.Addr, want policy.Decision) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got policy.Decision
	for time.Now().Before(deadline) {
		got = p.cache.Lookup(issue865PolicySession, ip)
		if got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("evidence for %s = %v, want %v", ip, got, want)
}

// assertNoEvidence asserts that no evidence was recorded for ip. The observation
// runs after the resolver returns, so the window is bounded rather than instant.
func (p *issue865PolicyPhase) assertNoEvidence(t *testing.T, ip netip.Addr) {
	t.Helper()
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := p.cache.Lookup(issue865PolicySession, ip); got != policy.Unknown {
			t.Fatalf("a refused encrypted exchange produced evidence for %s: %v", ip, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// issue865PolicyWrapper mirrors the production constructor exactly except for the
// test-only loopback admission the local fixture needs.
func issue865PolicyWrapper(configured []policy.Upstream) (*gatewaydns.UpstreamResolver, error) {
	upstreams := configured
	if len(upstreams) == 0 {
		upstreams = policy.DefaultUpstreams()
	}
	return gatewaydns.NewUpstreamResolver(gatewaydns.ResolverConfig{
		Upstreams:             upstreams,
		AllowLoopbackUpstream: true,
	})
}

// TestIssue865PolicyEncryptedConsumerChild drives the intercepting policy resolver
// through the production activation path in an isolated process.
func TestIssue865PolicyEncryptedConsumerChild(t *testing.T) {
	if os.Getenv(issue865PolicyChildEnv) != "1" {
		t.Skip("runs only inside the isolated child process started by the parent test")
	}
	dir := os.Getenv(issue865PolicyFixtureDirEnv)
	if dir == "" {
		t.Fatal("fixture directory is missing from the child environment")
	}
	trusted := issue865LoadKeyPair(t, dir, "leaf")
	untrusted := issue865LoadKeyPair(t, dir, "other")

	// The unchanged production constructor, kept for the control below.
	production := newPolicyUpstreamResolver
	newPolicyUpstreamResolver = issue865PolicyWrapper
	t.Cleanup(func() { newPolicyUpstreamResolver = production })

	// 1. DoT positive: the Service builds the resolver from the configured list and
	// the client's intercepted query is answered through the encrypted exchange and
	// becomes routing evidence.
	dot := issue865StartDoT(t, trusted)
	dotPhase := issue865StartPolicyPhase(t, policy.Upstream{
		Address: "127.0.0.1", Port: dot.port, Transport: policy.TransportDoT,
	})
	issue865AssertAnswer(t, "policy DoT matched", dotPhase.query(t, "matched.example.", 18650), issue865MatchedIP)
	issue865AssertAnswer(t, "policy DoT direct", dotPhase.query(t, "direct.example.", 18651), issue865DirectIP)
	dotPhase.waitDecision(t, issue865MatchedIP, policy.Proxy)
	dotPhase.waitDecision(t, issue865DirectIP, policy.Direct)
	if got := dot.handshakes.Load(); got == 0 {
		t.Fatal("DoT fixture saw no TLS handshake: the configured entry was not dialed")
	}

	// 2. DoH positive: same production path, DoH transport.
	doh := issue865StartDoH(t, trusted)
	dohPhase := issue865StartPolicyPhase(t, policy.Upstream{
		Address: "127.0.0.1", Port: doh.port, Transport: policy.TransportDoH,
	})
	issue865AssertAnswer(t, "policy DoH direct", dohPhase.query(t, "direct.example.", 18652), issue865DirectIP)
	dohPhase.waitDecision(t, issue865DirectIP, policy.Direct)
	if got := doh.requests.Load(); got == 0 {
		t.Fatal("DoH fixture served no DoH request: the configured entry was not dialed")
	}
	if got := doh.rejected.Load(); got != 0 {
		t.Fatalf("DoH fixture rejected %d requests: the exchange was not a DoH POST on the RFC 8484 path", got)
	}

	// 3. Certificate refusal: the resolver reaches the listener, the chain does not
	// verify, the client gets SERVFAIL and no evidence is invented.
	certRefused := issue865StartDoT(t, untrusted)
	certPhase := issue865StartPolicyPhase(t, policy.Upstream{
		Address: "127.0.0.1", Port: certRefused.port, Transport: policy.TransportDoT,
	})
	issue865AssertRefused(t, "policy untrusted certificate", certPhase.query(t, "matched.example.", 18653))
	if got := certRefused.handshakes.Load(); got == 0 {
		t.Fatal("the untrusted-certificate control never reached the encrypted listener")
	}
	certPhase.assertNoEvidence(t, issue865MatchedIP)
	certPhase.assertNoEvidence(t, issue865DirectIP)

	// 4. Pin refusal: the chain verifies, the configured pin does not match the leaf.
	pinRefused := issue865StartDoT(t, trusted)
	pinPhase := issue865StartPolicyPhase(t, policy.Upstream{
		Address: "127.0.0.1", Port: pinRefused.port, Transport: policy.TransportDoT,
		SPKIPin: issue865SPKIPin(t, untrusted),
	})
	issue865AssertRefused(t, "policy pin mismatch", pinPhase.query(t, "matched.example.", 18654))
	if got := pinRefused.handshakes.Load(); got == 0 {
		t.Fatal("the pin-mismatch control never reached the encrypted listener")
	}
	pinPhase.assertNoEvidence(t, issue865MatchedIP)

	// 5. The unchanged production constructor is untouched by all of the above: it
	// still refuses a loopback upstream (the admission this fixture needed is
	// test-only) and still applies the exact defaults and the exact configured list.
	if _, err := production([]policy.Upstream{{
		Address: "127.0.0.1", Port: dot.port, Transport: policy.TransportDoT,
	}}); err == nil {
		t.Fatal("the production constructor accepted a loopback upstream: admission was weakened")
	}
	defaults, err := production(nil)
	if err != nil {
		t.Fatalf("the production constructor refused its own defaults: %v", err)
	}
	wantDefaults := policy.DefaultUpstreams()
	gotDefaults := defaults.Upstreams()
	if len(gotDefaults) != len(wantDefaults) {
		t.Fatalf("default upstreams = %v, want %v", gotDefaults, wantDefaults)
	}
	for i := range wantDefaults {
		if gotDefaults[i] != wantDefaults[i] {
			t.Fatalf("default upstream %d = %+v, want %+v", i, gotDefaults[i], wantDefaults[i])
		}
	}
	configured := []policy.Upstream{
		{Address: "9.9.9.9", Port: 53, Transport: policy.TransportPlain},
		{Address: "dns.example.com", Port: 853, Transport: policy.TransportDoT},
	}
	explicit, err := production(configured)
	if err != nil {
		t.Fatalf("the production constructor refused a valid configured list: %v", err)
	}
	gotConfigured := explicit.Upstreams()
	if len(gotConfigured) != len(configured) {
		t.Fatalf("configured upstreams = %v, want the exact configured list %v", gotConfigured, configured)
	}
	for i := range configured {
		if gotConfigured[i] != configured[i] {
			t.Fatalf("configured upstream %d = %+v, want %+v", i, gotConfigured[i], configured[i])
		}
	}

	fmt.Printf("%s dot=1 doh=1 cert_refused=1 pin_refused=1 defaults_preserved=1\n", issue865PolicyMarker)
}
