package policy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestValidateFetchIP(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		// Private (RFC 1918)
		{ip: "10.0.0.1", blocked: true},
		{ip: "172.16.0.1", blocked: true},
		{ip: "172.31.255.255", blocked: true},
		{ip: "192.168.1.1", blocked: true},

		// Loopback
		{ip: "127.0.0.1", blocked: true},
		{ip: "127.255.255.254", blocked: true},

		// Link-Local & Cloud Metadata
		{ip: "169.254.169.254", blocked: true},
		{ip: "169.254.0.1", blocked: true},

		// CGNAT / Alibaba Metadata
		{ip: "100.64.0.1", blocked: true},
		{ip: "100.100.100.200", blocked: true},
		{ip: "100.127.255.255", blocked: true},

		// Azure WireServer
		{ip: "168.63.129.16", blocked: true},

		// Current network / Broadcast / Multicast
		{ip: "0.0.0.0", blocked: true},
		{ip: "224.0.0.1", blocked: true},
		{ip: "240.0.0.1", blocked: true},
		{ip: "255.255.255.255", blocked: true},

		// Benchmark / Documentation
		{ip: "192.0.2.1", blocked: true},
		{ip: "198.18.0.1", blocked: true},
		{ip: "198.51.100.1", blocked: true},
		{ip: "203.0.113.1", blocked: true},

		// IPv6 & IPv4-mapped IPv6
		{ip: "::1", blocked: true},
		{ip: "2001:db8::1", blocked: true},
		{ip: "::ffff:127.0.0.1", blocked: true},
		{ip: "::ffff:169.254.169.254", blocked: true},

		// Public addresses (Must pass)
		{ip: "93.184.216.34", blocked: false}, // example.com
		{ip: "1.1.1.1", blocked: false},
		{ip: "8.8.8.8", blocked: false},
		{ip: "140.82.121.4", blocked: false}, // github.com
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.ip)
			if err != nil {
				t.Fatalf("parse addr %q: %v", tt.ip, err)
			}
			err = ValidateFetchIP(addr)
			if tt.blocked && err == nil {
				t.Errorf("ValidateFetchIP(%s) = nil, want blocked error", tt.ip)
			}
			if !tt.blocked && err != nil {
				t.Errorf("ValidateFetchIP(%s) unexpected error: %v", tt.ip, err)
			}
		})
	}
}

func TestValidateFetchURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "valid standard https 443", url: "https://example.com/rules.lst", wantErr: false},
		{name: "valid explicit port 443", url: "https://example.com:443/rules.lst", wantErr: false},
		{name: "valid public ip literal", url: "https://93.184.216.34/rules.lst", wantErr: false},

		// Rejections
		{name: "plain http", url: "http://example.com/rules.lst", wantErr: true},
		{name: "nonstandard port", url: "https://example.com:8443/rules.lst", wantErr: true},
		{name: "private ip literal", url: "https://192.168.1.1/rules.lst", wantErr: true},
		{name: "loopback ip literal", url: "https://127.0.0.1/rules.lst", wantErr: true},
		{name: "metadata ip literal", url: "https://169.254.169.254/rules.lst", wantErr: true},
		{name: "userinfo in url", url: "https://admin:pass@example.com/rules.lst", wantErr: true},
		{name: "fragment in url", url: "https://example.com/rules.lst#section", wantErr: true},
		{name: "single label hostname", url: "https://localhost/rules.lst", wantErr: true},
		{name: "ipv6 literal", url: "https://[2001:db8::1]/rules.lst", wantErr: true},
		{name: "empty url", url: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateFetchURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateFetchURL(%q) err = %v, wantErr = %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestFetcher_SSRFDNSResolutionDefense(t *testing.T) {
	fetcher := NewFetcher(DefaultFetchLimits())

	// Simulate DNS resolving to cloud metadata IP
	fetcher.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}

	_, err := fetcher.Fetch(context.Background(), "https://evil-metadata.example.com/rules.lst", "", "")
	if err == nil || !strings.Contains(err.Error(), "SSRF defense blocked") {
		t.Fatalf("expected SSRF block error, got %v", err)
	}

	// Simulate mixed DNS resolution (one public, one private)
	fetcher.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("10.0.0.5"),
		}, nil
	}

	_, err = fetcher.Fetch(context.Background(), "https://mixed-dns.example.com/rules.lst", "", "")
	if err == nil || !strings.Contains(err.Error(), "SSRF defense blocked") {
		t.Fatalf("expected SSRF block for mixed DNS resolution, got %v", err)
	}
}

func TestFetcher_DownloadScenarios(t *testing.T) {
	// Start an HTTPS test server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/valid.lst":
			if r.Header.Get("If-None-Match") == `"v1.0"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"v1.0"`)
			w.Header().Set("Last-Modified", "Mon, 02 Nov 2026 12:00:00 GMT")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("example.com\n.google.com\n*.yahoo.com\n"))

		case "/oversized.lst":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("a.com\n", 500)))

		case "/html-challenge.lst":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<!DOCTYPE html><html><body>Captcha</body></html>"))

		case "/json-error.lst":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error": "Access Denied"}`))

		case "/compressed.lst":
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("some-data"))

		case "/redirect-loop.lst":
			http.Redirect(w, r, "https://rules.example.com/redirect-loop.lst", http.StatusFound)

		case "/redirect-to-private.lst":
			http.Redirect(w, r, "https://192.168.1.1/rules.lst", http.StatusFound)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// Extract server listener address
	serverAddr := ts.Listener.Addr().String()

	newTestFetcher := func(limits FetchLimits) *Fetcher {
		f := NewFetcher(limits)
		f.tlsConfig = &tls.Config{
			InsecureSkipVerify: true, // test fixture cert
		}
		f.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
			// Return an approved public IP to satisfy SSRF IP check
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		f.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Route literal TCP connection to test server listener
			var d net.Dialer
			return d.DialContext(ctx, "tcp", serverAddr)
		}
		return f
	}

	t.Run("successful 200 download", func(t *testing.T) {
		f := newTestFetcher(DefaultFetchLimits())
		res, err := f.Fetch(context.Background(), "https://rules.example.com/valid.lst", "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.StatusCode != 200 || res.NotModified {
			t.Fatalf("unexpected res: %+v", res)
		}
		if res.ETag != `"v1.0"` {
			t.Errorf("unexpected ETag: %s", res.ETag)
		}
		if !strings.Contains(string(res.Body), "example.com") {
			t.Errorf("expected body to contain example.com: %s", string(res.Body))
		}
	})

	t.Run("conditional 304 not modified", func(t *testing.T) {
		f := newTestFetcher(DefaultFetchLimits())
		res, err := f.Fetch(context.Background(), "https://rules.example.com/valid.lst", `"v1.0"`, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.StatusCode != 304 || !res.NotModified {
			t.Fatalf("expected 304 NotModified, got %+v", res)
		}
	})

	t.Run("oversized body exceeds limit", func(t *testing.T) {
		f := newTestFetcher(FetchLimits{
			MaxSourceBytes: 100, // Small limit
			MaxLineBytes:   4096,
			Timeout:        5 * time.Second,
		})
		_, err := f.Fetch(context.Background(), "https://rules.example.com/oversized.lst", "", "")
		if err == nil || !strings.Contains(err.Error(), "exceeded limit") {
			t.Fatalf("expected body limit exceeded error, got %v", err)
		}
	})

	t.Run("html challenge rejected", func(t *testing.T) {
		f := newTestFetcher(DefaultFetchLimits())
		_, err := f.Fetch(context.Background(), "https://rules.example.com/html-challenge.lst", "", "")
		if err == nil || !strings.Contains(err.Error(), "unexpected HTML") {
			t.Fatalf("expected HTML rejection error, got %v", err)
		}
	})

	t.Run("json error payload rejected", func(t *testing.T) {
		f := newTestFetcher(DefaultFetchLimits())
		_, err := f.Fetch(context.Background(), "https://rules.example.com/json-error.lst", "", "")
		if err == nil || !strings.Contains(err.Error(), "unexpected HTML, XML, or JSON") {
			t.Fatalf("expected JSON rejection error, got %v", err)
		}
	})

	t.Run("compressed encoding rejected", func(t *testing.T) {
		f := newTestFetcher(DefaultFetchLimits())
		_, err := f.Fetch(context.Background(), "https://rules.example.com/compressed.lst", "", "")
		if err == nil || !strings.Contains(err.Error(), "unsupported content encoding") {
			t.Fatalf("expected content-encoding rejection error, got %v", err)
		}
	})

	t.Run("redirect to private IP rejected by CheckRedirect", func(t *testing.T) {
		f := newTestFetcher(DefaultFetchLimits())
		_, err := f.Fetch(context.Background(), "https://rules.example.com/redirect-to-private.lst", "", "")
		if err == nil || !strings.Contains(err.Error(), "redirect target rejected") {
			t.Fatalf("expected redirect target rejection, got %v", err)
		}
	})
}
