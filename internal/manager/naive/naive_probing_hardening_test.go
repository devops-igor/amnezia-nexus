package naive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestRenderCaddyfile_ActiveProbeDefense(t *testing.T) {
	tests := []struct {
		name       string
		port       int
		domain     string
		clients    []NaiveClient
		wantHeader string
		expectSNI  string
	}{
		{
			name:       "default port 443 with domain and clients",
			port:       443,
			domain:     "vpn.example.com",
			clients:    []NaiveClient{{Username: "u1", Password: "p1"}},
			wantHeader: ":443, vpn.example.com {",
			expectSNI:  "vpn.example.com",
		},
		{
			name:       "default port 443 with domain and zero clients",
			port:       443,
			domain:     "vpn.example.com",
			clients:    nil,
			wantHeader: ":443, vpn.example.com {",
			expectSNI:  "vpn.example.com",
		},
		{
			name:       "non-default port 8443 with domain and clients",
			port:       8443,
			domain:     "vpn.custom.org",
			clients:    []NaiveClient{{Username: "u1", Password: "p1"}},
			wantHeader: ":8443, vpn.custom.org:8443 {",
			expectSNI:  "vpn.custom.org",
		},
		{
			name:       "non-default port 8443 with zero clients",
			port:       8443,
			domain:     "vpn.custom.org",
			clients:    nil,
			wantHeader: ":8443, vpn.custom.org:8443 {",
			expectSNI:  "vpn.custom.org",
		},
		{
			name:       "localhost domain",
			port:       443,
			domain:     "localhost",
			clients:    nil,
			wantHeader: ":443, localhost {",
			expectSNI:  "localhost",
		},
		{
			name:       "raw IP domain",
			port:       443,
			domain:     "198.51.100.42",
			clients:    nil,
			wantHeader: ":443, 198.51.100.42 {",
			expectSNI:  "198.51.100.42",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rendered := RenderCaddyfile(tc.port, tc.domain, tc.clients)

			// 1. Must contain global options with fallback SNI for TLS probing defense and protocols h1 h2 to eliminate HTTP/3 QUIC on UDP 443
			wantDefaultSNI := fmt.Sprintf("default_sni %s", tc.expectSNI)
			wantFallbackSNI := fmt.Sprintf("fallback_sni %s", tc.expectSNI)
			if !strings.Contains(rendered, wantDefaultSNI) || !strings.Contains(rendered, wantFallbackSNI) {
				t.Fatalf("rendered Caddyfile missing global default/fallback SNI for %q:\n%s", tc.expectSNI, rendered)
			}
			const wantProtocols = "servers {\n        protocols h1 h2\n    }"
			if !strings.Contains(rendered, wantProtocols) {
				t.Fatalf("rendered Caddyfile missing global protocols restriction:\n%s\nExpected:\n%s", rendered, wantProtocols)
			}

			// 2. Must contain hostless listener address in site header to accept arbitrary CONNECT authorities
			if !strings.Contains(rendered, tc.wantHeader) {
				t.Fatalf("rendered Caddyfile missing expected site header %q:\n%s", tc.wantHeader, rendered)
			}

			// 3. Must contain in-route @rawProbe defense
			wantRawProbe := fmt.Sprintf("@rawProbe {\n            not method CONNECT\n            not host %s\n        }", tc.expectSNI)
			if !strings.Contains(rendered, wantRawProbe) {
				t.Fatalf("rendered Caddyfile missing in-route @rawProbe matcher:\n%s\nExpected:\n%s", rendered, wantRawProbe)
			}
			const wantRawProbeHandle = `handle @rawProbe {
            respond "Not Found" 404 {
                close
            }
        }`
			if !strings.Contains(rendered, wantRawProbeHandle) {
				t.Fatalf("rendered Caddyfile missing in-route handle @rawProbe:\n%s", rendered)
			}

			// 4. Validate token quotes and brace balance
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
	const expectedHandleErrors = `    handle_errors {
        header {
            -Server
            -Alt-Svc
        }
        respond "{err.status_code} {err.status_text}" {err.status_code}
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
			if !strings.Contains(rendered, expectedHandleErrors) {
				t.Fatalf("rendered Caddyfile missing handle_errors camouflage block:\n%s\nExpected:\n%s",
					rendered, expectedHandleErrors)
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
			// In test domains, tls internal MUST be present in the site block
			count := strings.Count(rendered, "tls internal")
			if count != 1 {
				t.Fatalf("expected exactly 1 'tls internal' occurrence in site block for %q, got %d:\n%s",
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
			// For public domains, tls internal MUST NOT be emitted (Let's Encrypt / ZeroSSL automated)
			count := strings.Count(rendered, "tls internal")
			if count != 0 {
				t.Fatalf("public domain %q must not emit tls internal (expected 0, got %d):\n%s",
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
		if !errors.Is(err, ErrDNSValidation) {
			t.Errorf("expected ErrDNSValidation sentinel error, got: %v", err)
		}
		errMsg := err.Error()
		if !strings.Contains(errMsg, "pre-flight DNS validation failed") {
			t.Errorf("error must mention pre-flight DNS validation failed, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "unresolvable.mycustomvpn.org") {
			t.Errorf("error must mention unresolvable domain name, got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "does not resolve") {
			t.Errorf("error must mention does not resolve, got: %s", errMsg)
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
		if !errors.Is(err, ErrDNSValidation) {
			t.Errorf("expected ErrDNSValidation sentinel error, got: %v", err)
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

	t.Run("server host as same hostname as domain passes without DNS query", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "vpn.operator.net" {
				return []net.IP{net.ParseIP("198.51.100.50")}, nil
			}
			return nil, errors.New("unexpected lookup")
		})

		server := &models.Server{ID: 110, Host: "vpn.operator.net", SSHPort: 22}
		params := map[string]any{
			"port": 443,
			"naive_options": map[string]any{
				"domain": "vpn.operator.net",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err != nil {
			t.Fatalf("Install should succeed when server.Host matches domain: %v", err)
		}
	})

	t.Run("server host as hostname alias resolving to same IP succeeds", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("198.51.100.50")}, nil
		})

		server := &models.Server{ID: 111, Host: "node.operator.net", SSHPort: 22}
		params := map[string]any{
			"port": 443,
			"naive_options": map[string]any{
				"domain": "vpn.operator.net",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err != nil {
			t.Fatalf("Install should succeed when hostname resolves to same IP: %v", err)
		}
	})

	t.Run("server host as bracketed IPv6 resolving to same IP succeeds", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("2001:db8::50")}, nil
		})

		server := &models.Server{ID: 112, Host: "[2001:db8::50]", SSHPort: 22}
		params := map[string]any{
			"port": 443,
			"naive_options": map[string]any{
				"domain": "vpn.operator.net",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err != nil {
			t.Fatalf("Install should succeed for bracketed IPv6: %v", err)
		}
	})

	t.Run("server host as hostname alias resolving to different IP fails", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
		mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "vpn.operator.net" {
				return []net.IP{net.ParseIP("198.51.100.50")}, nil
			}
			return []net.IP{net.ParseIP("198.51.100.99")}, nil
		})

		server := &models.Server{ID: 113, Host: "node.operator.net", SSHPort: 22}
		params := map[string]any{
			"port": 443,
			"naive_options": map[string]any{
				"domain": "vpn.operator.net",
			},
		}

		err := mgr.Install(ctx, server, params)
		if err == nil {
			t.Fatalf("expected Install to fail for mismatched hostname IP")
		}
		if !strings.Contains(err.Error(), "pre-flight DNS validation failed") {
			t.Errorf("error must mention pre-flight DNS validation failed, got: %v", err)
		}
	})

	t.Run("private management IP behind NAT validates public domain DNS", func(t *testing.T) {
		type testCase struct {
			name       string
			serverHost string
			lookupIPs  []net.IP
			lookupErr  error
			wantErr    bool
		}
		var cases []testCase
		for _, host := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "::1", "fd00::1"} {
			cases = append(cases,
				testCase{host + "/valid domain succeeds", host, []net.IP{net.ParseIP("198.51.100.99")}, nil, false},
				testCase{host + "/unresolvable domain fails", host, nil, &net.DNSError{Err: "no such host", Name: "vpn.operator.net", IsNotFound: true}, true},
				testCase{host + "/zero ips fails", host, []net.IP{}, nil, true},
			)
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mockSSH := newMockNaiveSSHClient()
				mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
				mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
					return tc.lookupIPs, tc.lookupErr
				})
				server := &models.Server{ID: 114, Host: tc.serverHost, SSHPort: 22}
				params := map[string]any{"port": 443, "naive_options": map[string]any{"domain": "vpn.operator.net"}}
				err := mgr.Install(ctx, server, params)
				if tc.wantErr {
					if err == nil || !errors.Is(err, ErrDNSValidation) {
						t.Fatalf("expected ErrDNSValidation on %s, got: %v", tc.serverHost, err)
					}
					if len(mockSSH.files) > 0 {
						t.Fatalf("files written despite DNS failure on %s: %v", tc.serverHost, mockSSH.files)
					}
				} else if err != nil {
					t.Fatalf("expected success on %s, got: %v", tc.serverHost, err)
				}
			})
		}
	})
}

func TestParseCaddyfile_HardenedStructureRoundTrip(t *testing.T) {
	ctx := context.Background()

	// 1. Render and parse default port 443 with domain and clients
	const expectedHandleErrors = `    handle_errors {
        header {
            -Server
            -Alt-Svc
        }
        respond "{err.status_code} {err.status_text}" {err.status_code}
    }`

	rendered443 := RenderCaddyfile(443, "vpn.prod.org", []NaiveClient{
		{Username: "client1", Password: "pass1secret123"},
	})
	if !strings.Contains(rendered443, expectedHandleErrors) {
		t.Fatalf("rendered443 missing handle_errors block:\n%s", rendered443)
	}
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
	if !strings.Contains(rendered0, expectedHandleErrors) {
		t.Fatalf("rendered0 missing handle_errors block:\n%s", rendered0)
	}
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
	if !strings.Contains(rendered8443, expectedHandleErrors) {
		t.Fatalf("rendered8443 missing handle_errors block:\n%s", rendered8443)
	}
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

	// 4. Client additions and removals preserve probe hardening, handle_errors, and header camouflage
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
	if !strings.Contains(afterAdd, "default_sni vpn.prod.org") || !strings.Contains(afterAdd, "fallback_sni vpn.prod.org") {
		t.Errorf("AddClient corrupted global SNI settings:\n%s", afterAdd)
	}
	if !strings.Contains(afterAdd, "protocols h1 h2") {
		t.Errorf("AddClient corrupted protocols h1 h2 restriction:\n%s", afterAdd)
	}
	if !strings.Contains(afterAdd, ":443, vpn.prod.org {") {
		t.Errorf("AddClient corrupted site header:\n%s", afterAdd)
	}
	if !strings.Contains(afterAdd, "@rawProbe {") || !strings.Contains(afterAdd, "handle @rawProbe {") {
		t.Errorf("AddClient corrupted @rawProbe handler:\n%s", afterAdd)
	}
	if !strings.Contains(afterAdd, "-Server") || !strings.Contains(afterAdd, "-Alt-Svc") {
		t.Errorf("AddClient stripped header camouflage:\n%s", afterAdd)
	}
	if !strings.Contains(afterAdd, expectedHandleErrors) {
		t.Errorf("AddClient corrupted handle_errors block:\n%s", afterAdd)
	}
	if dAdd, pAdd, clientsAdd, err := ParseCaddyfile(afterAdd); err != nil || dAdd != "vpn.prod.org" || pAdd != 443 || len(clientsAdd) != 1 || clientsAdd[0].Username != "added_user" {
		t.Errorf("ParseCaddyfile failed on afterAdd: domain=%s port=%d clients=%v err=%v", dAdd, pAdd, clientsAdd, err)
	}

	// Remove client
	err = mgr.RemoveClient(ctx, server, "added_user")
	if err != nil {
		t.Fatalf("RemoveClient failed: %v", err)
	}

	afterRemove := string(mockSSH.files[NaiveCaddyfilePath])
	if !strings.Contains(afterRemove, "default_sni vpn.prod.org") || !strings.Contains(afterRemove, "fallback_sni vpn.prod.org") {
		t.Errorf("RemoveClient corrupted global SNI settings:\n%s", afterRemove)
	}
	if !strings.Contains(afterRemove, "protocols h1 h2") {
		t.Errorf("RemoveClient corrupted protocols h1 h2 restriction:\n%s", afterRemove)
	}
	if !strings.Contains(afterRemove, ":443, vpn.prod.org {") {
		t.Errorf("RemoveClient corrupted site header:\n%s", afterRemove)
	}
	if !strings.Contains(afterRemove, "@rawProbe {") || !strings.Contains(afterRemove, "handle @rawProbe {") {
		t.Errorf("RemoveClient corrupted @rawProbe handler:\n%s", afterRemove)
	}
	if !strings.Contains(afterRemove, "-Server") || !strings.Contains(afterRemove, "-Alt-Svc") {
		t.Errorf("RemoveClient stripped header camouflage:\n%s", afterRemove)
	}
	if !strings.Contains(afterRemove, expectedHandleErrors) {
		t.Errorf("RemoveClient corrupted handle_errors block:\n%s", afterRemove)
	}
	if dRem, pRem, clientsRem, err := ParseCaddyfile(afterRemove); err != nil || dRem != "vpn.prod.org" || pRem != 443 || len(clientsRem) != 0 {
		t.Errorf("ParseCaddyfile failed on afterRemove: domain=%s port=%d clients=%v err=%v", dRem, pRem, clientsRem, err)
	}
}

func TestAuditEquivalent_ValidHostnameServerInstall(t *testing.T) {
	for _, tc := range []struct{ name, host, ip string }{
		{"IPv4_control", "198.51.100.50", "198.51.100.50"},
		{"hostname_same_as_domain", "vpn.operator.net", "198.51.100.50"},
		{"hostname_alias", "node.operator.net", "198.51.100.50"},
		{"IPv6_control", "2001:db8::50", "2001:db8::50"},
		{"bracketed_IPv6", "[2001:db8::50]", "2001:db8::50"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := models.ValidateHost(tc.host); err != nil {
				t.Fatal(err)
			}
			mock := newMockNaiveSSHClient()
			mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mock}, awg.NewServerLockRegistry())
			mgr.SetDNSLookup(func(ctx context.Context, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP(tc.ip)}, nil
			})
			server := &models.Server{ID: 684, Host: tc.host, SSHPort: 22}
			err := mgr.Install(context.Background(), server, map[string]any{
				"port": 443,
				"naive_options": &models.NaiveInstallOptions{
					Domain: "vpn.operator.net",
				},
			})
			if err != nil {
				t.Fatalf("valid server host and matching DNS must install: %v", err)
			}
		})
	}
}

func TestAuditEquivalent_ProxySiteMustAcceptCONNECTAuthority(t *testing.T) {
	for _, port := range []int{443, 8443} {
		t.Run(fmt.Sprintf("port_%d", port), func(t *testing.T) {
			rendered := RenderCaddyfile(port, "vpn.operator.net", []NaiveClient{{Username: "audit", Password: "fixture-only"}})
			depth := 0
			site := ""
			for _, line := range strings.Split(rendered, "\n") {
				trim := strings.TrimSpace(line)
				if depth == 0 && strings.HasSuffix(trim, "{") {
					site = strings.TrimSpace(strings.TrimSuffix(trim, "{"))
				}
				if strings.HasPrefix(trim, "forward_proxy") {
					catchall := false
					for _, addr := range strings.Split(site, ",") {
						if strings.HasPrefix(strings.TrimSpace(addr), ":") {
							catchall = true
						}
					}
					if !catchall {
						t.Errorf("proxy site only matches its own domain; destination-authority CONNECT cannot enter this route")
					}
				}
				depth += strings.Count(trim, "{") - strings.Count(trim, "}")
			}
		})
	}
}

type auditEquivalentConn struct{ net.Conn }

func (auditEquivalentConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("198.51.100.50"), Port: 443}
}
func (auditEquivalentConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 50000}
}

func TestAuditEquivalent_TLSCertificateSelection(t *testing.T) {
	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cfg, nil }})
	defer cache.Stop()
	cfg = certmagic.New(cache, certmagic.Config{})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(684),
		DNSNames:     []string{"vpn.operator.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.CacheUnmanagedTLSCertificate(context.Background(), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hello := func(name string) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{
			ServerName:        name,
			Conn:              auditEquivalentConn{},
			SupportedVersions: []uint16{tls.VersionTLS13},
			SignatureSchemes:  []tls.SignatureScheme{tls.Ed25519},
			CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		}
	}
	if _, err := cfg.GetCertificateWithContext(context.Background(), hello("vpn.operator.net")); err != nil {
		t.Fatalf("configured-name control: %v", err)
	}
	for _, sni := range []string{"", "random.operator.net"} {
		_, err := cfg.GetCertificateWithContext(context.Background(), hello(sni))
		if err == nil {
			t.Fatalf("expected absent certificate for unmatched SNI=%q", sni)
		}
	}
	cfg.DefaultServerName = "vpn.operator.net"
	cfg.FallbackServerName = "vpn.operator.net"
	for _, sni := range []string{"", "random.operator.net"} {
		_, err := cfg.GetCertificateWithContext(context.Background(), hello(sni))
		if err != nil {
			t.Fatalf("fallback control failed: %v", err)
		}
	}
}

func adaptCaddyfileToJSON(content string) ([]byte, error) {
	if err := validateCaddyfileStructure(content); err != nil {
		return nil, fmt.Errorf("caddyfile structure invalid: %w", err)
	}
	domain, port, clients, err := ParseCaddyfile(content)
	if err != nil {
		return nil, fmt.Errorf("caddyfile parse failed: %w", err)
	}
	routes := []map[string]any{
		{"handle": []map[string]any{{"handler": "headers", "response": map[string]any{"delete": []string{"Server", "Alt-Svc"}}}}},
		{
			"match":  []map[string]any{{"not": []map[string]any{{"method": []string{"CONNECT"}}, {"host": []string{domain}}}}},
			"handle": []map[string]any{{"handler": "static_response", "status_code": 404, "close": true}},
		},
	}
	if len(clients) > 0 && strings.Contains(content, "forward_proxy") {
		routes = append(routes, map[string]any{"handle": []map[string]any{{"handler": "forward_proxy", "probe_resistance": true}}})
	}
	routes = append(routes, map[string]any{"handle": []map[string]any{{"handler": "file_server", "root": "/srv"}}})

	cfg := map[string]any{
		"admin": map[string]any{"listen": "127.0.0.1:2019"},
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen":    []string{fmt.Sprintf(":%d", port)},
						"protocols": []string{"h1", "h2"},
						"routes":    routes,
						"errors": map[string]any{
							"routes": []map[string]any{{
								"handle": []map[string]any{
									{"handler": "headers", "response": map[string]any{"delete": []string{"Server", "Alt-Svc"}}},
									{"handler": "static_response", "status_code": "{err.status_code}"},
								},
							}},
						},
						"tls_connection_policies": []map[string]any{{"default_sni": domain, "fallback_sni": domain}},
					},
				},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func TestCaddyConfigurationAdaptation_RouteStructureAndProbeDefense(t *testing.T) {
	for _, tc := range []struct {
		name       string
		port       int
		domain     string
		clients    []NaiveClient
		expectAuth bool
	}{
		{"public_clients", 443, "vpn.prod.org", []NaiveClient{{Username: "u1", Password: "p1"}}, true},
		{"public_zero_clients", 443, "vpn.prod.org", nil, false},
		{"custom_port_clients", 8443, "vpn.custom.org", []NaiveClient{{Username: "u2", Password: "p2"}}, true},
		{"test_domain_ip", 443, "198.51.100.42", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caddyfile := RenderCaddyfile(tc.port, tc.domain, tc.clients)
			data, err := adaptCaddyfileToJSON(caddyfile)
			if err != nil || !json.Valid(data) {
				t.Fatalf("adaptation failed: %v", err)
			}
			var parsed struct {
				Apps struct {
					HTTP struct {
						Servers map[string]struct {
							Protocols []string                    `json:"protocols"`
							Routes    []map[string]any            `json:"routes"`
							Errors    map[string][]map[string]any `json:"errors"`
						} `json:"servers"`
					} `json:"http"`
				} `json:"apps"`
			}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("unmarshal adapted JSON failed: %v", err)
			}
			srv := parsed.Apps.HTTP.Servers["srv0"]
			if len(srv.Protocols) != 2 || srv.Protocols[0] != "h1" || srv.Protocols[1] != "h2" {
				t.Errorf("expected protocols [h1 h2], got: %v", srv.Protocols)
			}
			hasRawProbe, hasProxy := false, false
			for _, r := range srv.Routes {
				if r["match"] != nil {
					hasRawProbe = true
				}
				for _, h := range r["handle"].([]any) {
					if h.(map[string]any)["handler"] == "forward_proxy" {
						hasProxy = true
					}
				}
			}
			if !hasRawProbe {
				t.Error("adapted route structure missing @rawProbe")
			}
			if tc.expectAuth != hasProxy {
				t.Errorf("expected forward_proxy=%t, got %t", tc.expectAuth, hasProxy)
			}
			if len(srv.Errors["routes"]) == 0 {
				t.Error("adapted JSON missing error handlers")
			}
		})
	}
}
