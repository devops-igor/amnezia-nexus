package policy

import (
	"net/netip"
	"testing"
)

func TestParseIPv4Rule(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantPrefix string
		wantErr    bool
	}{
		{name: "standard /24", in: "192.168.1.0/24", wantPrefix: "192.168.1.0/24"},
		{name: "unmasked /24 canonicalized", in: "192.168.1.55/24", wantPrefix: "192.168.1.0/24"},
		{name: "all ipv4 /0", in: "0.0.0.0/0", wantPrefix: "0.0.0.0/0"},
		{name: "single IP /32", in: "10.0.0.1/32", wantPrefix: "10.0.0.1/32"},
		{name: "bare IP treated as /32", in: "10.0.0.1", wantPrefix: "10.0.0.1/32"},
		{name: "max ip /32", in: "255.255.255.255", wantPrefix: "255.255.255.255/32"},

		// Errors
		{name: "empty", in: "", wantErr: true},
		{name: "spaces only", in: "   ", wantErr: true},
		{name: "invalid cidr", in: "192.168.1.0/33", wantErr: true},
		{name: "invalid text", in: "not-an-ip", wantErr: true},
		{name: "ipv6 cidr", in: "2001:db8::/32", wantErr: true},
		{name: "ipv6 addr", in: "2001:db8::1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseIPv4Rule(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseIPv4Rule(%q) error = %v, wantErr = %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && p.String() != tt.wantPrefix {
				t.Fatalf("ParseIPv4Rule(%q) = %q, want %q", tt.in, p.String(), tt.wantPrefix)
			}
		})
	}
}

func TestMergeRanges(t *testing.T) {
	t.Run("empty and single", func(t *testing.T) {
		if len(mergeRanges(nil)) != 0 {
			t.Fatal("expected empty")
		}
		single := []ipRange{{lo: 10, hi: 20}}
		got := mergeRanges(single)
		if len(got) != 1 || got[0] != single[0] {
			t.Fatalf("unexpected single: %+v", got)
		}
	})

	t.Run("adjacent and overlapping", func(t *testing.T) {
		// [1, 3] and [4, 8] are adjacent -> [1, 8]
		// [20, 30] is separate
		// [0xffffffff, 0xffffffff] is at the end
		input := []ipRange{
			{lo: 20, hi: 30},
			{lo: 1, hi: 3},
			{lo: 4, hi: 8},
			{lo: 0xffffffff, hi: 0xffffffff},
		}
		merged := mergeRanges(input)
		if len(merged) != 3 {
			t.Fatalf("expected 3 merged ranges, got %d: %+v", len(merged), merged)
		}
		if merged[0] != (ipRange{lo: 1, hi: 8}) {
			t.Fatalf("expected [1, 8], got %+v", merged[0])
		}
		if merged[1] != (ipRange{lo: 20, hi: 30}) {
			t.Fatalf("expected [20, 30], got %+v", merged[1])
		}
		if merged[2] != (ipRange{lo: 0xffffffff, hi: 0xffffffff}) {
			t.Fatalf("expected [0xffffffff, 0xffffffff], got %+v", merged[2])
		}
	})

	t.Run("contained range", func(t *testing.T) {
		input := []ipRange{
			{lo: 10, hi: 50},
			{lo: 15, hi: 25},
			{lo: 40, hi: 60},
		}
		merged := mergeRanges(input)
		if len(merged) != 1 || merged[0] != (ipRange{lo: 10, hi: 60}) {
			t.Fatalf("expected [10, 60], got %+v", merged)
		}
	})
}

func TestIPv4IndexMatch(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.128/25"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("10.0.0.1/32"),
	}

	idx := newIPv4Index(prefixes)

	testCases := []struct {
		addr string
		want bool
	}{
		// 198.51.100.128/25: 198.51.100.128 to 198.51.100.255
		{addr: "198.51.100.127", want: false},
		{addr: "198.51.100.128", want: true},
		{addr: "198.51.100.200", want: true},
		{addr: "198.51.100.255", want: true},
		{addr: "198.51.101.0", want: false},

		// 203.0.113.0/24: 203.0.113.0 to 203.0.113.255
		{addr: "203.0.112.255", want: false},
		{addr: "203.0.113.0", want: true},
		{addr: "203.0.113.10", want: true},
		{addr: "203.0.113.255", want: true},
		{addr: "203.0.114.0", want: false},

		// 10.0.0.1/32
		{addr: "10.0.0.0", want: false},
		{addr: "10.0.0.1", want: true},
		{addr: "10.0.0.2", want: false},

		// Outside all
		{addr: "0.0.0.0", want: false},
		{addr: "255.255.255.255", want: false},

		// IPv6 mapped IPv4
		{addr: "::ffff:10.0.0.1", want: true},
		{addr: "::ffff:10.0.0.2", want: false},

		// Pure IPv6
		{addr: "2001:db8::1", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("parse addr %q: %v", tc.addr, err)
			}
			got := idx.match(addr)
			if got != tc.want {
				t.Errorf("idx.match(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestIPv4IndexAllIPv4(t *testing.T) {
	idx := newIPv4Index([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	for _, ipStr := range []string{"0.0.0.0", "1.1.1.1", "192.168.1.1", "255.255.255.255"} {
		ip := netip.MustParseAddr(ipStr)
		if !idx.match(ip) {
			t.Errorf("expected 0.0.0.0/0 to match %s", ipStr)
		}
	}
}
