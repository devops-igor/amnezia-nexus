package naive

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestRenderCaddyfile_ActiveProbeFallbackBlock(t *testing.T) {
	const expectedFallback = `:443 {
    tls internal
    respond "Not Found" 404 {
        close
    }
}`

	tests := []struct {
		name    string
		port    int
		domain  string
		clients []NaiveClient
	}{
		{
			name:    "default port 443 with domain and clients",
			port:    443,
			domain:  "vpn.example.com",
			clients: []NaiveClient{{Username: "u1", Password: "p1"}},
		},
		{
			name:    "default port 443 with domain and zero clients",
			port:    443,
			domain:  "vpn.example.com",
			clients: nil,
		},
		{
			name:    "non-default port 8443 with domain and clients",
			port:    8443,
			domain:  "vpn.custom.org",
			clients: []NaiveClient{{Username: "u1", Password: "p1"}},
		},
		{
			name:    "non-default port 8443 with zero clients",
			port:    8443,
			domain:  "vpn.custom.org",
			clients: nil,
		},
		{
			name:    "localhost domain",
			port:    443,
			domain:  "localhost",
			clients: nil,
		},
		{
			name:    "raw IP domain",
			port:    443,
			domain:  "198.51.100.42",
			clients: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rendered := RenderCaddyfile(tc.port, tc.domain, tc.clients)
			if !strings.Contains(rendered, expectedFallback) {
				t.Fatalf("rendered Caddyfile missing expected active-probe fallback block:\n%s\nExpected to contain:\n%s",
					rendered, expectedFallback)
			}

			// Validate token quotes and brace balance
			if err := validateCaddyfileTokens(rendered); err != nil {
				t.Errorf("token validation failed: %v", err)
			}
			openBraces := strings.Count(rendered, "{")
			closeBraces := strings.Count(rendered, "}")
			if openBraces != closeBraces {
				t.Errorf("unmatched braces: %d '{' vs %d '}'", openBraces, closeBraces)
			}
		})
	}
}

func TestRenderCaddyfile_HeaderCamouflage(t *testing.T) {
	const expectedHeaders = `    header {
        -Server
        -Alt-Svc
    }`

	tests := []struct {
		name   string
		port   int
		domain string
	}{
		{name: "port 443 public domain", port: 443, domain: "vpn.corp.com"},
		{name: "port 443 test domain", port: 443, domain: "vpn.example.com"},
		{name: "port 8443 custom port", port: 8443, domain: "vpn.custom.org"},
		{name: "localhost", port: 443, domain: "localhost"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rendered := RenderCaddyfile(tc.port, tc.domain, nil)
			if !strings.Contains(rendered, expectedHeaders) {
				t.Fatalf("rendered Caddyfile missing header camouflage directives:\n%s\nExpected:\n%s",
					rendered, expectedHeaders)
			}
			if !strings.Contains(rendered, "-Server") {
				t.Errorf("missing -Server directive in Caddyfile:\n%s", rendered)
			}
			if !strings.Contains(rendered, "-Alt-Svc") {
				t.Errorf("missing -Alt-Svc directive in Caddyfile:\n%s", rendered)
			}
		})
	}
}

func TestRenderCaddyfile_TestDomainsEmitTLSInternal(t *testing.T) {
	testDomains := []string{
		"localhost",
		"node.localhost",
		"mybox.local",
		"127.0.0.1",
		"198.51.100.1",
		"::1",
		"2001:db8::1",
		"[2001:db8::1]",
		"example.com",
		"vpn.example.com",
		"sub.vpn.example.com",
		"example.net",
		"vpn.example.net",
		"example.org",
		"vpn.example.org",
		"app.test",
		"service.example",
		"dummy.invalid",
		"service.internal",
	}

	for _, d := range testDomains {
		t.Run("test domain: "+d, func(t *testing.T) {
			rendered := RenderCaddyfile(443, d, nil)
			// In test domains, tls internal MUST be present in BOTH fallback block and site block
			count := strings.Count(rendered, "tls internal")
			if count < 2 {
				t.Fatalf("expected at least 2 'tls internal' occurrences (fallback + site block) for %q, got %d:\n%s",
					d, count, rendered)
			}
		})
	}

	publicDomains := []string{
		"vpn.mycompany.com",
		"nexus.production.org",
		"proxy.customcorp.net",
		"secure.vpnserver.io",
	}

	for _, d := range publicDomains {
		t.Run("public domain: "+d, func(t *testing.T) {
			rendered := RenderCaddyfile(443, d, nil)
			// For public domains, tls internal MUST only appear ONCE (inside the :443 fallback block)
			count := strings.Count(rendered, "tls internal")
			if count != 1 {
				t.Fatalf("public domain %q must not emit tls internal in site block (expected count 1 for fallback only, got %d):\n%s",
					d, count, rendered)
			}
		})
	}
}

func TestIsTestDomainOrIP(t *testing.T) {
	cases := []struct {
		domain string
		want   bool
	}{
		{"", true},
		{"localhost", true},
		{"LOCALHOST", true},
		{"foo.localhost", true},
		{"my-host.local", true},
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"[2001:db8::1]", true},
		{"example.com", true},
		{"vpn.example.com", true},
		{"sub.vpn.example.com", true},
		{"EXAMPLE.COM", true},
		{"VPN.EXAMPLE.COM", true},
		{"example.net", true},
		{"vpn.example.net", true},
		{"example.org", true},
		{"vpn.example.org", true},
		{"myhost.test", true},
		{"myhost.example", true},
		{"myhost.invalid", true},
		{"myhost.internal", true},
		{"https://vpn.example.com", true},
		{"vpn.example.com:443", true},
		{"192.168.1.1:8443", true},

		// Public domains
		{"google.com", false},
		{"cloudflare.net", false},
		{"wikipedia.org", false},
		{"vpn.mycompany.com", false},
		{"mycorp.io", false},
		{"https://vpn.mycompany.com", false},
		{"vpn.mycompany.com:443", false},
	}

	for _, tc := range cases {
		got := isTestDomainOrIP(tc.domain)
		if got != tc.want {
			t.Errorf("isTestDomainOrIP(%q) = %v; want %v", tc.domain, got, tc.want)
		}
	}
}

func TestPreFlightDNSValidation(t *testing.T) {
	ctx := context.Background()
	serverHost := "198.51.100.50"

	t.Run("unresolvable public domain fails Install with actionable error", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, &net.DNSError{
				Err:        "no such host",
				Name:       host,
				IsNotFound: true,
			}
		})

		server := &models.Server{ID: 101, Host: serverHost, SSHPort: 22}
		params := map[string]any{
			"port": 443,
			"naive_options": map[string]any{
				"domain": "unresolvable.mycustomvpn.org",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err == nil {
			t.Fatalf("expected Install to fail for unresolvable domain, got nil error")
		}
		errMsg := err.Error()
		if !strings.Contains(errMsg, "pre-flight DNS validation failed") {
			t.Errorf("error must mention pre-flight DNS validation failed, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "unresolvable.mycustomvpn.org") {
			t.Errorf("error must mention unresolvable domain name, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, serverHost) {
			t.Errorf("error must mention expected server IP %s, got: %s", serverHost, errMsg)
		}

		// Verify remote system was untouched
		if len(mockSSH.files) > 0 {
			t.Errorf("files were written to remote host despite DNS failure: %v", mockSSH.files)
		}
	})

	t.Run("public domain resolving to wrong IP fails Install with actionable error", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		})

		server := &models.Server{ID: 102, Host: serverHost, SSHPort: 22}
		params := map[string]any{
			"port": 443,
			"naive_options": map[string]any{
				"domain": "wrongip.mycustomvpn.org",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err == nil {
			t.Fatalf("expected Install to fail for mismatched IP, got nil error")
		}
		errMsg := err.Error()
		if !strings.Contains(errMsg, "pre-flight DNS validation failed") {
			t.Errorf("error must mention pre-flight DNS validation failed, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "93.184.216.34") {
			t.Errorf("error must mention resolved IP 93.184.216.34, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, serverHost) {
			t.Errorf("error must mention expected server IP %s, got: %s", serverHost, errMsg)
		}
	})

	t.Run("public domain resolving to server IP succeeds", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP(serverHost)}, nil
		})

		server := &models.Server{ID: 103, Host: serverHost, SSHPort: 22}
		params := map[string]any{
			"port": 443,
			"naive_options": map[string]any{
				"domain": "valid.mycustomvpn.org",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err != nil {
			t.Fatalf("Install should succeed when domain resolves to server IP, got: %v", err)
		}

		caddyContent := string(mockSSH.files[NaiveCaddyfilePath])
		if !strings.Contains(caddyContent, "valid.mycustomvpn.org") {
			t.Errorf("Caddyfile missing domain: %s", caddyContent)
		}
	})

	t.Run("test domain skips DNS validation automatically", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		// Set a lookup function that always fails; test domain must never call it
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, errors.New("lookup must not be invoked for test domain")
		})

		server := &models.Server{ID: 104, Host: serverHost, SSHPort: 22}
		params := map[string]any{
			"port": 443,
			"naive_options": map[string]any{
				"domain": "sub.example.com",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err != nil {
			t.Fatalf("Install must succeed for test domain without DNS lookup, got: %v", err)
		}
	})

	t.Run("localhost and IP skip DNS validation automatically", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, errors.New("lookup must not be invoked for localhost or IP")
		})

		server := &models.Server{ID: 105, Host: serverHost, SSHPort: 22}
		err := mgr.Install(ctx, server, map[string]any{"port": 443})
		if err != nil {
			t.Fatalf("Install must succeed when domain defaults to IP, got: %v", err)
		}
	})

	t.Run("skip_dns_validation flag in params overrides check", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, errors.New("unresolvable public domain")
		})

		server := &models.Server{ID: 106, Host: serverHost, SSHPort: 22}
		params := map[string]any{
			"port":                443,
			"skip_dns_validation": true,
			"naive_options": map[string]any{
				"domain": "override.mycustomvpn.org",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err != nil {
			t.Fatalf("Install must succeed when skip_dns_validation=true, got: %v", err)
		}
	})

	t.Run("skip_dns_check in naive_options overrides check", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, errors.New("unresolvable public domain")
		})

		server := &models.Server{ID: 107, Host: serverHost, SSHPort: 22}
		params := map[string]any{
			"port": 443,
			"naive_options": map[string]any{
				"domain":         "override.mycustomvpn.org",
				"skip_dns_check": "true",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err != nil {
			t.Fatalf("Install must succeed when skip_dns_check in naive_options is true, got: %v", err)
		}
	})

	t.Run("test_override_ip matches server host", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		// No custom DNS function set; uses parameter override
		server := &models.Server{ID: 108, Host: serverHost, SSHPort: 22}
		params := map[string]any{
			"port":             443,
			"test_override_ip": serverHost,
			"naive_options": map[string]any{
				"domain": "param-override.mycustomvpn.org",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err != nil {
			t.Fatalf("Install must succeed with test_override_ip, got: %v", err)
		}
	})

	t.Run("test_override_ips mismatch returns validation error", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		server := &models.Server{ID: 109, Host: serverHost, SSHPort: 22}
		params := map[string]any{
			"port":              443,
			"test_override_ips": []string{"10.0.0.1", "10.0.0.2"},
			"naive_options": map[string]any{
				"domain": "param-mismatch.mycustomvpn.org",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err == nil {
			t.Fatalf("expected Install to fail for mismatched test_override_ips")
		}
		if !strings.Contains(err.Error(), "10.0.0.1") || !strings.Contains(err.Error(), serverHost) {
			t.Errorf("unexpected error format: %v", err)
		}
	})
}

func TestParseCaddyfile_HardenedStructureRoundTrip(t *testing.T) {
	ctx := context.Background()

	// 1. Render and parse default port 443 with domain and clients
	rendered443 := RenderCaddyfile(443, "vpn.prod.org", []NaiveClient{
		{Username: "client1", Password: "pass1secret123"},
	})
	d443, p443, clients443, err := ParseCaddyfile(rendered443)
	if err != nil {
		t.Fatalf("ParseCaddyfile 443 failed: %v", err)
	}
	if d443 != "vpn.prod.org" || p443 != 443 {
		t.Errorf("443 parse mismatch: domain=%s port=%d", d443, p443)
	}
	if len(clients443) != 1 || clients443[0].Username != "client1" {
		t.Errorf("443 clients mismatch: %+v", clients443)
	}

	// 2. Render and parse 0 clients
	rendered0 := RenderCaddyfile(443, "vpn.prod.org", nil)
	d0, p0, clients0, err := ParseCaddyfile(rendered0)
	if err != nil {
		t.Fatalf("ParseCaddyfile 0-client failed: %v", err)
	}
	if d0 != "vpn.prod.org" || p0 != 443 || len(clients0) != 0 {
		t.Errorf("0-client parse mismatch: domain=%s port=%d clients=%v", d0, p0, clients0)
	}

	// 3. Render and parse non-default port 8443
	rendered8443 := RenderCaddyfile(8443, "vpn.custom.org", []NaiveClient{
		{Username: "u8443", Password: "p8443"},
	})
	d8443, p8443, clients8443, err := ParseCaddyfile(rendered8443)
	if err != nil {
		t.Fatalf("ParseCaddyfile 8443 failed: %v", err)
	}
	if d8443 != "vpn.custom.org" || p8443 != 8443 {
		t.Errorf("8443 parse mismatch: domain=%s port=%d", d8443, p8443)
	}
	if len(clients8443) != 1 {
		t.Errorf("8443 clients mismatch: %+v", clients8443)
	}

	// 4. Client additions and removals preserve fallback block and header camouflage
	mockSSH := newMockNaiveSSHClient()
	mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 200, Host: "198.51.100.200", SSHPort: 22}

	mockSSH.files[NaiveCaddyfilePath] = []byte(rendered0)

	// Add client
	_, err = mgr.AddClient(ctx, server, map[string]any{
		"username": "added_user",
		"password": "added_pass_secure",
	})
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}

	afterAdd := string(mockSSH.files[NaiveCaddyfilePath])
	if !strings.Contains(afterAdd, ":443 {\n    tls internal\n    respond \"Not Found\" 404") {
		t.Errorf("AddClient corrupted fallback block:\n%s", afterAdd)
	}
	if !strings.Contains(afterAdd, "-Server") || !strings.Contains(afterAdd, "-Alt-Svc") {
		t.Errorf("AddClient stripped header camouflage:\n%s", afterAdd)
	}

	// Remove client
	err = mgr.RemoveClient(ctx, server, "added_user")
	if err != nil {
		t.Fatalf("RemoveClient failed: %v", err)
	}

	afterRemove := string(mockSSH.files[NaiveCaddyfilePath])
	if !strings.Contains(afterRemove, ":443 {\n    tls internal\n    respond \"Not Found\" 404") {
		t.Errorf("RemoveClient corrupted fallback block:\n%s", afterRemove)
	}
	if !strings.Contains(afterRemove, "-Server") || !strings.Contains(afterRemove, "-Alt-Svc") {
		t.Errorf("RemoveClient stripped header camouflage:\n%s", afterRemove)
	}
}
