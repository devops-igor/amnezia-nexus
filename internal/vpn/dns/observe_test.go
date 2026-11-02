package gatewaydns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

func compileTestSnapshot(t *testing.T, domainRules string, cidrRules string) *policy.Snapshot {
	t.Helper()
	var sources []policy.SourceParsedRules
	if domainRules != "" {
		p, _, err := policy.Parse(context.Background(), strings.NewReader(domainRules), policy.Source{
			ID:             "test-domains",
			Format:         policy.FormatDomains,
			BareDomainMode: policy.DomainModeInclusiveSuffix,
		}, policy.DefaultParseLimits())
		if err != nil {
			t.Fatalf("failed to parse domains: %v", err)
		}
		sources = append(sources, policy.SourceParsedRules{
			SourceID: "test-domains",
			Rules:    p,
		})
	}
	if cidrRules != "" {
		p, _, err := policy.Parse(context.Background(), strings.NewReader(cidrRules), policy.Source{
			ID:     "test-cidrs",
			Format: policy.FormatIPv4,
		}, policy.DefaultParseLimits())
		if err != nil {
			t.Fatalf("failed to parse CIDRs: %v", err)
		}
		sources = append(sources, policy.SourceParsedRules{
			SourceID: "test-cidrs",
			Rules:    p,
		})
	}
	if len(sources) == 0 {
		p, _, _ := policy.Parse(context.Background(), strings.NewReader("dummy.internal"), policy.Source{
			ID:             "dummy",
			Format:         policy.FormatDomains,
			BareDomainMode: policy.DomainModeExact,
		}, policy.DefaultParseLimits())
		sources = append(sources, policy.SourceParsedRules{SourceID: "dummy", Rules: p})
	}

	snap, err := policy.CompileSnapshot(1, "gen-test", sources)
	if err != nil {
		t.Fatalf("failed to compile snapshot: %v", err)
	}
	return snap
}

func setupTestSession(t *testing.T, generation string) (*policy.RouteCache, *policy.SessionCache) {
	t.Helper()
	rc, err := policy.NewRouteCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	rc.SetPolicyGeneration(generation)
	sess, err := rc.Open(policy.Scope{SessionID: "sess-observe", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("failed to open session: %v", err)
	}
	return rc, sess
}

func TestObserve_DirectAndProxy(t *testing.T) {
	snapshot := compileTestSnapshot(t, "blocked.com\n.proxy.org", "")
	rc, sess := setupTestSession(t, snapshot.Generation())
	_ = rc

	now := time.Now()
	publicIP := netip.MustParseAddr("93.184.216.34")

	// 1. Unlisted domain -> DIRECT
	req := new(mdns.Msg)
	req.SetQuestion("unlisted.com.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "unlisted.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 120},
		A:   publicIP.AsSlice(),
	})

	obs, err := ObserveResponse(req, resp, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("ObserveResponse failed: %v", err)
	}
	if len(obs) != 1 || obs[0].Decision != policy.Direct {
		t.Fatalf("expected 1 DIRECT observation, got %+v", obs)
	}
	if got := sess.Lookup(publicIP, snapshot.Generation(), now); got != policy.Direct {
		t.Errorf("expected Direct in cache lookup, got %v", got)
	}

	// 2. Listed domain -> PROXY
	req2 := new(mdns.Msg)
	req2.SetQuestion("sub.proxy.org.", mdns.TypeA)
	resp2 := new(mdns.Msg)
	resp2.SetReply(req2)
	resp2.Answer = append(resp2.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "sub.proxy.org.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   publicIP.AsSlice(),
	})

	obs2, err := ObserveResponse(req2, resp2, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("ObserveResponse failed: %v", err)
	}
	if len(obs2) != 1 || obs2[0].Decision != policy.Proxy {
		t.Fatalf("expected 1 PROXY observation, got %+v", obs2)
	}
	// Shared-IP conflict resolution: PROXY overrides prior DIRECT
	if got := sess.Lookup(publicIP, snapshot.Generation(), now); got != policy.Proxy {
		t.Errorf("expected Proxy to override Direct for publicIP, got %v", got)
	}
}

func TestObserve_CNAMEChains(t *testing.T) {
	snapshot := compileTestSnapshot(t, "protected.net", "")
	_, sess := setupTestSession(t, snapshot.Generation())
	now := time.Now()
	publicIP := netip.MustParseAddr("1.1.1.1")

	// Chain: unlisted.com -> edge.protected.net -> publicIP
	req := new(mdns.Msg)
	req.SetQuestion("unlisted.com.", mdns.TypeA)

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.CNAME{
		Hdr:    mdns.RR_Header{Name: "unlisted.com.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 120},
		Target: "edge.protected.net.",
	})
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "edge.protected.net.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30},
		A:   publicIP.AsSlice(),
	})

	obs, err := ObserveResponse(req, resp, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("ObserveResponse failed: %v", err)
	}
	if len(obs) != 1 || obs[0].Decision != policy.Proxy {
		t.Fatalf("expected PROXY due to CNAME target, got %+v", obs)
	}
	// Effective TTL must be min(120, 30) = 30s
	expectedExpiry := now.Add(30 * time.Second)
	if obs[0].ExpiresAt != expectedExpiry {
		t.Errorf("expected expiry %v, got %v", expectedExpiry, obs[0].ExpiresAt)
	}
	if got := sess.Lookup(publicIP, snapshot.Generation(), now); got != policy.Proxy {
		t.Errorf("expected Proxy in cache, got %v", got)
	}
}

func TestObserve_CNAMECycleDetection(t *testing.T) {
	snapshot := compileTestSnapshot(t, "protected.net", "")
	_, sess := setupTestSession(t, snapshot.Generation())
	now := time.Now()

	// Cycle: a.com -> b.com -> a.com
	req := new(mdns.Msg)
	req.SetQuestion("a.com.", mdns.TypeA)

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.CNAME{
		Hdr:    mdns.RR_Header{Name: "a.com.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60},
		Target: "b.com.",
	})
	resp.Answer = append(resp.Answer, &mdns.CNAME{
		Hdr:    mdns.RR_Header{Name: "b.com.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60},
		Target: "a.com.",
	})

	obs, err := ObserveResponse(req, resp, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obs != nil {
		t.Errorf("expected nil observations on cycle, got %+v", obs)
	}
}

func TestObserve_ConflictingCNAMEAndA(t *testing.T) {
	snapshot := compileTestSnapshot(t, "protected.net", "")
	_, sess := setupTestSession(t, snapshot.Generation())
	now := time.Now()

	// Invalid: owner has both CNAME and A
	req := new(mdns.Msg)
	req.SetQuestion("conflict.com.", mdns.TypeA)

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.CNAME{
		Hdr:    mdns.RR_Header{Name: "conflict.com.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60},
		Target: "target.com.",
	})
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "conflict.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.1.1.1").To4(),
	})

	obs, err := ObserveResponse(req, resp, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obs != nil {
		t.Errorf("expected nil observations for conflicting CNAME+A, got %+v", obs)
	}
}

func TestObserve_NormalizationFailureDoesNotGrantDirect(t *testing.T) {
	snapshot := compileTestSnapshot(t, "protected.net", "")
	_, sess := setupTestSession(t, snapshot.Generation())
	now := time.Now()

	// Name with underscore is valid in DNS (e.g. SRV or domain keys), but fails policy normalization.
	req := new(mdns.Msg)
	req.SetQuestion("_domainkey.example.com.", mdns.TypeA)

	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "_domainkey.example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34").To4(),
	})

	obs, err := ObserveResponse(req, resp, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obs != nil {
		t.Errorf("normalization failure must produce no route evidence (UNKNOWN), got %+v", obs)
	}
}

func TestObserve_NilSnapshotSafety(t *testing.T) {
	_, sess := setupTestSession(t, "gen-test")
	now := time.Now()

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.216.34").To4(),
	})

	// With nil snapshot, must return nil observations -> UNKNOWN
	obs, err := ObserveResponse(req, resp, nil, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obs != nil {
		t.Errorf("nil snapshot must return nil observations, got %+v", obs)
	}
}

func TestObserve_AddressValidation_NonPublicIP(t *testing.T) {
	snapshot := compileTestSnapshot(t, "blocked.com", "")
	_, sess := setupTestSession(t, snapshot.Generation())
	now := time.Now()

	// Unlisted domain resolves to private RFC 1918 IP (10.0.0.1)
	req := new(mdns.Msg)
	req.SetQuestion("internal.corp.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "internal.corp.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.0.1").To4(),
	})

	obs, err := ObserveResponse(req, resp, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obs != nil {
		t.Errorf("non-public IP must never receive DIRECT evidence, got %+v", obs)
	}
}

func TestObserve_IPRuleMatchesProxy(t *testing.T) {
	// Domain unlisted, but CIDR matches proxy
	snapshot := compileTestSnapshot(t, "", "140.82.112.0/20")
	_, sess := setupTestSession(t, snapshot.Generation())
	now := time.Now()
	githubIP := netip.MustParseAddr("140.82.121.4")

	req := new(mdns.Msg)
	req.SetQuestion("unlisted.com.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "unlisted.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   githubIP.AsSlice(),
	})

	obs, err := ObserveResponse(req, resp, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(obs) != 1 || obs[0].Decision != policy.Proxy {
		t.Fatalf("expected PROXY due to CIDR match, got %+v", obs)
	}
}

func TestObserve_TTLZeroNotCached(t *testing.T) {
	snapshot := compileTestSnapshot(t, "", "")
	_, sess := setupTestSession(t, snapshot.Generation())
	now := time.Now()
	publicIP := netip.MustParseAddr("93.184.216.34")

	req := new(mdns.Msg)
	req.SetQuestion("zerottl.com.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "zerottl.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 0},
		A:   publicIP.AsSlice(),
	})

	obs, err := ObserveResponse(req, resp, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if obs != nil {
		t.Errorf("TTL 0 must not be cached, got %+v", obs)
	}
}

func TestObserve_ZeroTTLProxyRevokesActiveDirect(t *testing.T) {
	snapshot := compileTestSnapshot(t, "blocked.com", "")
	_, sess := setupTestSession(t, snapshot.Generation())
	now := time.Now()
	publicIP := netip.MustParseAddr("93.184.216.34")

	// 1. Unlisted domain resolves to publicIP with TTL 300 -> DIRECT
	req := new(mdns.Msg)
	req.SetQuestion("unlisted.com.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "unlisted.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   publicIP.AsSlice(),
	})

	obs, err := ObserveResponse(req, resp, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("ObserveResponse 1 failed: %v", err)
	}
	if len(obs) != 1 || obs[0].Decision != policy.Direct {
		t.Fatalf("expected DIRECT observation, got %+v", obs)
	}
	if got := sess.Lookup(publicIP, snapshot.Generation(), now); got != policy.Direct {
		t.Fatalf("expected Direct in cache before suppression, got %v", got)
	}

	// 2. Blocked/proxy-required domain resolves to the same publicIP with TTL 0 -> PROXY
	req2 := new(mdns.Msg)
	req2.SetQuestion("blocked.com.", mdns.TypeA)
	resp2 := new(mdns.Msg)
	resp2.SetReply(req2)
	resp2.Answer = append(resp2.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "blocked.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 0},
		A:   publicIP.AsSlice(),
	})

	obs2, err := ObserveResponse(req2, resp2, snapshot, sess, now, 3600*time.Second)
	if err != nil {
		t.Fatalf("ObserveResponse 2 failed: %v", err)
	}
	if len(obs2) != 1 || obs2[0].Decision != policy.Proxy {
		t.Fatalf("expected PROXY observation with zero TTL, got %+v", obs2)
	}

	// 3. Confirm that the prior DIRECT grant was immediately revoked and lookup returns UNKNOWN (safe fallback).
	if got := sess.Lookup(publicIP, snapshot.Generation(), now); got != policy.Unknown {
		t.Errorf("expected Unknown (safe fallback) after zero-TTL proxy suppression, got %v", got)
	}
}
