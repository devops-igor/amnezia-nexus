package vpn

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
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

// renderedProfileDNS is the resolver pair a generated profile must carry: the
// plain-transport entries of the same DefaultUpstreams the policy resolver falls
// back to. Deriving the expectation from that one definition keeps the profile and
// its test from pinning two copies of the same literals.
func renderedProfileDNS() string {
	first, second := "", ""
	for _, upstream := range policy.DefaultUpstreams() {
		if upstream.EffectiveTransport() != policy.TransportPlain {
			continue
		}
		switch {
		case first == "":
			first = upstream.Address
		case second == "":
			second = upstream.Address
		}
	}
	if second == "" {
		second = first
	}
	return first + ", " + second
}

// newActivePBRConfig builds an enabled policy-routing configuration over a real
// matcher and route cache. It is exactly the state in which a generated profile
// used to be steered at the panel resolver, so it is the state a generated
// profile must ignore.
func newActivePBRConfig(t *testing.T) PBRConfig {
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

	return PBRConfig{
		Enabled:       true,
		HostWANIP:     netip.MustParseAddr("203.0.113.10"),
		WANDevice:     &mockPBRDevice{},
		PolicyMatcher: matcher,
	}
}

// TestGenerateClientConfigCarriesExternalResolversOnly is the profile contract:
// a generated client configuration always carries the external resolver pair and
// never a panel address, whatever state policy routing is in. A profile that
// named the panel would depend on a resolver this build does not run.
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

	externalDNS := renderedProfileDNS()
	if externalDNS != awgDefaultDNS1+", "+awgDefaultDNS2 {
		t.Fatalf("profile resolver pair = %q, want %q", externalDNS, awgDefaultDNS1+", "+awgDefaultDNS2)
	}

	assertExternalOnly := func(step string) {
		t.Helper()
		config, _, err := svc.GenerateClientConfig(ctx, userID)
		if err != nil {
			t.Fatalf("%s: GenerateClientConfig failed: %v", step, err)
		}
		if got := parseClientConfigDNS(t, config); got != externalDNS {
			t.Fatalf("%s: DNS = %q, want the external resolvers %q\n%s", step, got, externalDNS, config)
		}
	}

	assertExternalOnly("policy routing inactive")

	if err := svc.ConfigurePBR(newActivePBRConfig(t)); err != nil {
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
