package xray

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/xray/scanner"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// withLookupIP swaps the resolver seam for the duration of a test.
func withLookupIP(t *testing.T, fn func(ctx context.Context, network, host string) ([]net.IP, error)) {
	t.Helper()
	prev := lookupIP
	lookupIP = fn
	t.Cleanup(func() { lookupIP = prev })
}

// TestValidateDecoyDomainContext_BoundedByCallerDeadline is the regression test for the
// unsafe lifetime behind the original code: DNS ran under context.Background(), so a
// resolver that never answers could hang an install indefinitely. The lookup must observe
// the caller's deadline and return promptly once it expires.
func TestValidateDecoyDomainContext_BoundedByCallerDeadline(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	withLookupIP(t, func(ctx context.Context, network, host string) ([]net.IP, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("resolver released")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := ValidateDecoyDomainContext(ctx, "decoy.example", "", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when resolution is cancelled, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("validation ignored the caller deadline: took %v", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected the deadline error to propagate, got %v", err)
	}
}

// TestValidateDecoyDomainContext_ParentCancellationStopsLookup pins that an install that is
// cancelled upstream (client disconnect, shutdown) does not keep waiting on DNS.
func TestValidateDecoyDomainContext_ParentCancellationStopsLookup(t *testing.T) {
	withLookupIP(t, func(ctx context.Context, network, host string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before validation begins

	done := make(chan error, 1)
	go func() { done <- ValidateDecoyDomainContext(ctx, "decoy.example", "", nil) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for a cancelled context, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("validation did not return after parent cancellation")
	}
}

// TestValidateDecoyDomainContext_UnresolvableFailsClosed is the second behaviour change:
// the original returned nil when DNS failed, silently accepting a decoy that cannot
// camouflage anything. An unresolvable decoy must be rejected.
func TestValidateDecoyDomainContext_UnresolvableFailsClosed(t *testing.T) {
	withLookupIP(t, func(ctx context.Context, network, host string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})

	err := ValidateDecoyDomainContext(context.Background(), "does-not-exist.example", "", nil)
	if err == nil {
		t.Fatal("unresolvable decoy domain must be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "resolve decoy domain") {
		t.Errorf("expected a resolution error, got %v", err)
	}
}

// TestValidateDecoyDomainContext_ResolvesHostnameThroughSeam proves the validator actually
// takes the DNS path for hostnames (the contributor tests only used IP literals, which never
// touch the resolver) and applies blacklist + ASN rules to the resolved address.
func TestValidateDecoyDomainContext_ResolvesHostnameThroughSeam(t *testing.T) {
	var lookups atomic.Int32
	withLookupIP(t, func(ctx context.Context, network, host string) ([]net.IP, error) {
		lookups.Add(1)
		if network != "ip4" {
			t.Errorf("network = %q, want ip4", network)
		}
		switch host {
		case "good-decoy.example":
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		case "apple-decoy.example":
			return []net.IP{net.ParseIP("203.0.113.1")}, nil
		default:
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
	})

	geoDB := scanner.NewGeoDBFromRanges([]scanner.IPRange{
		{StartIP: binaryIP(net.ParseIP("203.0.113.1")), EndIP: binaryIP(net.ParseIP("203.0.113.1")), ASN: 714, Country: [2]byte{'U', 'S'}},
		{StartIP: binaryIP(net.ParseIP("203.0.113.10")), EndIP: binaryIP(net.ParseIP("203.0.113.10")), ASN: 8075, Country: [2]byte{'U', 'S'}},
	})

	// Microsoft CDN address resolves and passes.
	if err := ValidateDecoyDomainContext(context.Background(), "good-decoy.example", "", geoDB); err != nil {
		t.Errorf("expected resolvable non-Apple decoy to pass, got %v", err)
	}

	// An Apple AS714 decoy rejected only after resolution.
	err := ValidateDecoyDomainContext(context.Background(), "apple-decoy.example", "", geoDB)
	if err == nil {
		t.Fatal("expected AS714 decoy to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "714") {
		t.Errorf("expected error mentioning AS714, got %v", err)
	}

	if lookups.Load() == 0 {
		t.Error("resolver seam was never consulted; hostname resolution path untested")
	}
}

// TestParseXrayInstallOptions_RejectsBlacklistedDecoy is the production-path test for AC1:
// the value an operator submits through the install API is rejected before any SSH or
// container work, and the error is informative.
func TestParseXrayInstallOptions_RejectsBlacklistedDecoy(t *testing.T) {
	mgrParams := map[string]any{
		"server_name": "gateway.icloud.com",
	}
	server := &models.Server{ID: 1, Host: "192.0.2.1"}

	_, _, _, _, _, _, _, err := parseXrayInstallOptions(context.Background(), nil, mgrParams, server)
	if err == nil {
		t.Fatal("expected install options to reject a blacklisted decoy, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "censor") {
		t.Errorf("expected an informative blacklist error, got %v", err)
	}
}

// TestParseXrayInstallOptions_RejectsUnresolvableDecoyViaInstall makes sure the fail-closed
// policy is what Install actually does, not just what the validator does in isolation.
func TestParseXrayInstallOptions_RejectsUnresolvableDecoyViaInstall(t *testing.T) {
	withLookupIP(t, func(ctx context.Context, network, host string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})

	_, _, _, _, _, _, _, err := parseXrayInstallOptions(context.Background(), nil,
		map[string]any{"server_name": "unresolvable.example"}, &models.Server{ID: 9, Host: "192.0.2.9"})
	if err == nil {
		t.Fatal("expected install to reject an unresolvable decoy, got nil")
	}
	if !strings.Contains(err.Error(), "reject decoy domain") {
		t.Errorf("expected install to wrap the rejection clearly, got %v", err)
	}
}

// TestUpdateExistingConfig_PreservesUnrelatedInbounds is the regression test for the
// destructive truncation: the contributor's code assigned inbounds[:1], deleting every
// inbound after the first — including inbounds the manager never created. Only the
// auxiliary non-443 REALITY mirror may be removed.
func TestUpdateExistingConfig_PreservesUnrelatedInbounds(t *testing.T) {
	existing := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{
			// index 0: the primary REALITY inbound this feature owns
			map[string]any{
				"port":     443,
				"protocol": "vless",
				"settings": map[string]any{
					"clients":    []any{map[string]any{"id": "client-a", "flow": ""}},
					"decryption": "none",
				},
				"streamSettings": map[string]any{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": map[string]any{
						"serverNames": []any{"old.example"},
						"dest":        "old.example:443",
					},
				},
			},
			// index 1: auxiliary REALITY mirror on a non-standard port -> must be dropped
			map[string]any{
				"port":           54321,
				"protocol":       "vless",
				"streamSettings": map[string]any{"security": "reality"},
			},
			// index 2: operator's own SOCKS inbound -> must be preserved
			map[string]any{
				"port":     1080,
				"protocol": "socks",
				"settings": map[string]any{"auth": "noauth"},
			},
			// index 3: operator's own plaintext HTTP inbound -> must be preserved
			map[string]any{
				"port":           8080,
				"protocol":       "http",
				"streamSettings": map[string]any{"security": "none"},
			},
		},
	}
	raw, err := json.Marshal(existing)
	if err != nil {
		t.Fatal(err)
	}

	updated, err := updateExistingConfig(raw, 443, "new.example", "xtls-rprx-vision", false, true, true)
	if err != nil {
		t.Fatalf("updateExistingConfig: %v", err)
	}

	var doc struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(updated, &doc); err != nil {
		t.Fatalf("unmarshal updated config: %v", err)
	}

	var seen []string
	for _, in := range doc.Inbounds {
		proto, _ := in["protocol"].(string)
		port, _ := in["port"].(float64)
		seen = append(seen, proto)
		if proto == "vless" && port == 54321 {
			t.Error("auxiliary REALITY inbound on port 54321 was not removed")
		}
	}
	if len(doc.Inbounds) != 3 {
		t.Fatalf("expected 3 inbounds (primary + socks + http), got %d: %v", len(doc.Inbounds), seen)
	}
	if seen[0] != "vless" || seen[1] != "socks" || seen[2] != "http" {
		t.Errorf("expected order [vless socks http] preserved, got %v", seen)
	}

	// The primary inbound must have received the requested updates.
	primary := doc.Inbounds[0]
	rs := primary["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if names := rs["serverNames"].([]any); names[0] != "new.example" {
		t.Errorf("serverNames = %v, want new.example", names)
	}
	if dest := rs["dest"].(string); dest != "new.example:443" {
		t.Errorf("dest = %q, want new.example:443", dest)
	}
	clients := primary["settings"].(map[string]any)["clients"].([]any)
	if flow := clients[0].(map[string]any)["flow"]; flow != "xtls-rprx-vision" {
		t.Errorf("client flow = %v, want xtls-rprx-vision", flow)
	}
}

// TestUpdateExistingConfig_NonRealityAuxiliaryPortKept pins that inbounds which merely happen
// to sit on a non-443 port are not collateral damage: only REALITY mirrors are removed.
func TestUpdateExistingConfig_NonRealityAuxiliaryPortKept(t *testing.T) {
	existing := map[string]any{
		"inbounds": []any{
			map[string]any{"port": 443, "protocol": "vless", "streamSettings": map[string]any{"security": "reality"}},
			map[string]any{"port": 8443, "protocol": "trojan", "streamSettings": map[string]any{"security": "tls"}},
		},
	}
	raw, _ := json.Marshal(existing)

	updated, err := updateExistingConfig(raw, 443, "d.example", "", true, false, false)
	if err != nil {
		t.Fatalf("updateExistingConfig: %v", err)
	}
	var doc struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	_ = json.Unmarshal(updated, &doc)
	if len(doc.Inbounds) != 2 {
		t.Fatalf("expected both inbounds preserved, got %d", len(doc.Inbounds))
	}
}

// TestUpdateExistingConfig_NoInboundsIsAnError pins that a config with no inbounds is rejected
// instead of being silently rewritten into something that does not serve traffic.
func TestUpdateExistingConfig_NoInboundsIsAnError(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"inbounds": []any{}})
	if _, err := updateExistingConfig(raw, 443, "d.example", "", true, false, false); err == nil {
		t.Fatal("expected an error for a config with no inbounds, got nil")
	}
}

// TestInstall_PreservesOperatorInboundsEndToEnd drives the real Install path against the mock
// SSH client: an operator's own inbound in an existing config.json must survive a reinstall
// that changes the REALITY port, and the aux 54321 mirror must be gone.
func TestInstall_PreservesOperatorInboundsEndToEnd(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{
		ID:   90210,
		Host: "192.0.2.90",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{"installed": true, "port": 443, "engine_profile": "legacy"},
		},
	}

	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// Start from a realistic config: primary REALITY + aux REALITY + operator socks inbound.
	baseCfg, err := RenderXrayConfig(443, "example.com", "example.com:443", key,
		[]string{"0123456789abcdef"}, []XrayClient{{ID: "e8512bce-e575-4805-a678-1d64c033e83e", Flow: "xtls-rprx-vision", Email: "kept"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(baseCfg, &doc); err != nil {
		t.Fatal(err)
	}
	doc["inbounds"] = append(doc["inbounds"].([]any),
		map[string]any{
			"port":     54321,
			"protocol": "vless",
			"settings": map[string]any{"clients": []any{}, "decryption": "none"},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					// A real 54321 mirror carried the same REALITY identity as the primary.
					"dest":        "example.com:443",
					"serverNames": []any{"example.com"},
					"privateKey":  key,
					"shortIDs":    []any{"0123456789abcdef"},
				},
			},
		},
		map[string]any{"port": 1080, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}},
	)
	withExtra, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	mockSSH.files[XrayConfigPath] = withExtra

	if err := mgr.Install(context.Background(), server, map[string]any{"port": 8443}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig after install: %v", err)
	}
	var protocols []string
	for _, in := range parsed.Inbounds {
		protocols = append(protocols, in.Protocol)
		if in.Port == 54321 {
			t.Error("auxiliary REALITY inbound on 54321 survived reinstall")
		}
	}
	if len(parsed.Inbounds) != 2 {
		t.Fatalf("expected primary + operator socks inbound, got %d: %v", len(parsed.Inbounds), protocols)
	}
	if parsed.Inbounds[0].Port != 8443 {
		t.Errorf("primary inbound port = %d, want 8443", parsed.Inbounds[0].Port)
	}
	foundSocks := false
	for _, in := range parsed.Inbounds {
		if in.Protocol == "socks" && in.Port == 1080 {
			foundSocks = true
		}
	}
	if !foundSocks {
		t.Errorf("operator SOCKS inbound on 1080 was dropped: %v", protocols)
	}
}
