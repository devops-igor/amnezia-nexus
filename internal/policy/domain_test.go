package policy

import (
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "simple ASCII uppercase", in: "EXAMPLE.COM.", want: "example.com"},
		{name: "trailing dot stripped", in: "sub.example.com.", want: "sub.example.com"},
		{name: "cyrillic IDN", in: "пример.рф", want: "xn--e1afmkfd.xn--p1ai"},
		{name: "german sharp s", in: "faß.de", want: "xn--fa-hia.de"},
		{name: "fullwidth dot mapping", in: "example。com。", want: "example.com"},
		{name: "hyphen in middle allowed", in: "r3---sn.example", want: "r3---sn.example"},
		{name: "single label ccTLD", in: "ua", want: "ua"},
		{name: "two label domain", in: "google.com", want: "google.com"},
		{name: "deep subdomain", in: "a.b.c.d.example.com", want: "a.b.c.d.example.com"},

		// Errors
		{name: "empty", in: "", wantErr: true},
		{name: "spaces only", in: "   ", wantErr: true},
		{name: "leading quote", in: "\"certr.ru", wantErr: true},
		{name: "embedded space", in: "bad name.example", wantErr: true},
		{name: "double dot", in: "bad..example", wantErr: true},
		{name: "multiple trailing dots", in: "example.com..", wantErr: true},
		{name: "URL scheme", in: "https://example.com/x", wantErr: true},
		{name: "leading hyphen", in: "-bad.example", wantErr: true},
		{name: "trailing hyphen in label", in: "bad-.example", wantErr: true},
		{name: "underscore", in: "_dns.example", wantErr: true},
		{name: "empty punycode", in: "xn--.example", wantErr: true},
		{name: "IPv4 literal rejected as domain", in: "127.0.0.1", wantErr: true},
		{name: "IPv6 literal rejected as domain", in: "::1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDomain(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeDomain(%q) error = %v, wantErr = %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("NormalizeDomain(%q) = %q, want = %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseDomainRule(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		defaultMode DomainMode
		wantBase    string
		wantFlags   domainFlags
		wantIsIP    bool
		wantIPStr   string
		wantErr     bool
	}{
		{
			name:        "bare exact",
			raw:         "example.com",
			defaultMode: DomainModeExact,
			wantBase:    "example.com",
			wantFlags:   domainExact,
		},
		{
			name:        "bare inclusive suffix preset",
			raw:         "example.com",
			defaultMode: DomainModeInclusiveSuffix,
			wantBase:    "example.com",
			wantFlags:   domainInclusiveSuffix,
		},
		{
			name:        "explicit inclusive suffix dot prefix",
			raw:         ".example.com",
			defaultMode: DomainModeExact,
			wantBase:    "example.com",
			wantFlags:   domainInclusiveSuffix,
		},
		{
			name:        "explicit strict descendants wildcard prefix",
			raw:         "*.example.com",
			defaultMode: DomainModeExact,
			wantBase:    "example.com",
			wantFlags:   domainDescendants,
		},
		{
			name:        "existing .ua suffix",
			raw:         ".ua",
			defaultMode: DomainModeExact,
			wantBase:    "ua",
			wantFlags:   domainInclusiveSuffix,
		},
		{
			name:        "IPv4 literal in domain rule",
			raw:         "198.51.100.1",
			defaultMode: DomainModeExact,
			wantIsIP:    true,
			wantIPStr:   "198.51.100.1",
		},
		{
			name:        "IPv4 literal with space",
			raw:         "  203.0.113.5  ",
			defaultMode: DomainModeExact,
			wantIsIP:    true,
			wantIPStr:   "203.0.113.5",
		},

		// Malformed rules
		{name: "empty", raw: "", defaultMode: DomainModeExact, wantErr: true},
		{name: "bare star", raw: "*", defaultMode: DomainModeExact, wantErr: true},
		{name: "star without dot", raw: "*example.com", defaultMode: DomainModeExact, wantErr: true},
		{name: "bare dot", raw: ".", defaultMode: DomainModeExact, wantErr: true},
		{name: "dot star dot", raw: ".*.example.com", defaultMode: DomainModeExact, wantErr: true},
		{name: "star dot star dot", raw: "*.*.example.com", defaultMode: DomainModeExact, wantErr: true},
		{name: "internal wildcard", raw: "a.*.example.com", defaultMode: DomainModeExact, wantErr: true},
		{name: "IPv6 literal error", raw: "::1", defaultMode: DomainModeExact, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, flags, isIP, ip, err := ParseDomainRule(tt.raw, tt.defaultMode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseDomainRule(%q) error = %v, wantErr = %v", tt.raw, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if isIP != tt.wantIsIP {
				t.Fatalf("ParseDomainRule(%q) isIP = %v, want %v", tt.raw, isIP, tt.wantIsIP)
			}
			if isIP {
				if ip.String() != tt.wantIPStr {
					t.Fatalf("ParseDomainRule(%q) ip = %v, want %v", tt.raw, ip, tt.wantIPStr)
				}
				return
			}
			if base != tt.wantBase || flags != tt.wantFlags {
				t.Fatalf("ParseDomainRule(%q) base=%q flags=%d, want base=%q flags=%d",
					tt.raw, base, flags, tt.wantBase, tt.wantFlags)
			}
		})
	}
}
