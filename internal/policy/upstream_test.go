package policy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// These tests cover what survives of the upstream DNS surface: the entry type,
// its validation, the transport port defaults, the SPKI pin decoding, and the
// one definition of the default plain-DNS pair that every generated client
// configuration renders its DNS servers from.
//
// The operator editor and the encrypted resolver that used to consume a stored
// list are gone, so the tests that described a persisted list, its normalization
// and its JSON round trip went with them. What is asserted here is the behaviour
// the profile renderer and the shipped default pair still depend on.

func TestUpstreamValidateRejections(t *testing.T) {
	tests := []struct {
		name       string
		upstream   Upstream
		wantSubstr string
	}{
		{"empty address", Upstream{Port: 53}, "address is empty"},
		{"surrounding whitespace", Upstream{Address: " 94.140.14.14", Port: 53}, "whitespace"},
		{"malformed ipv4 literal", Upstream{Address: "300.1.1.1", Port: 53}, "not a valid IP literal"},
		{"malformed ipv4 literal with four octets and a fifth", Upstream{Address: "1.2.3.4.5", Port: 53}, "not a valid IP literal"},
		{"malformed ipv6 literal", Upstream{Address: "2001:db8::zz", Port: 53}, "not a valid IP literal"},
		{"loopback ipv4", Upstream{Address: "127.0.0.1", Port: 53}, "loopback"},
		{"loopback ipv6", Upstream{Address: "::1", Port: 53}, "loopback"},
		{"loopback hostname", Upstream{Address: "localhost", Port: 53}, "loopback"},
		{"loopback hostname with trailing dot", Upstream{Address: "LocalHost.", Port: 53}, "loopback"},
		{"multicast ipv4", Upstream{Address: "224.0.0.1", Port: 53}, "multicast"},
		{"multicast ipv6", Upstream{Address: "ff02::1", Port: 53}, "multicast"},
		{"unspecified ipv4", Upstream{Address: "0.0.0.0", Port: 53}, "unspecified"},
		{"unspecified ipv6", Upstream{Address: "::", Port: 53}, "unspecified"},
		{"missing port", Upstream{Address: "94.140.14.14"}, "explicit port"},
		{"negative port", Upstream{Address: "94.140.14.14", Port: -1}, "outside the valid range"},
		{"port above range", Upstream{Address: "94.140.14.14", Port: 65536}, "outside the valid range"},
		{"hostname with space", Upstream{Address: "bad host.example.com", Port: 53}, "not a valid hostname"},
		{"hostname with empty label", Upstream{Address: "a..b.example.com", Port: 53}, "empty label"},
		{"hostname with leading hyphen", Upstream{Address: "-bad.example.com", Port: 53}, "starts or ends with a hyphen"},
		{"hostname with trailing hyphen", Upstream{Address: "bad-.example.com", Port: 53}, "starts or ends with a hyphen"},
		{"hostname with underscore", Upstream{Address: "dns_server.example.com", Port: 53}, "contains"},
		{"hostname label too long", Upstream{Address: strings.Repeat("a", 64) + ".example.com", Port: 53}, "longer than"},
		{"hostname too long", Upstream{Address: strings.Repeat("abcdefgh.", 32) + "com", Port: 53}, "longer than"},
		{"unknown transport", Upstream{Address: "94.140.14.14", Port: 53, Transport: "tls"}, "unknown transport"},
		{"doh url with scheme", Upstream{Address: "https://dns.example.com", Port: 443, Transport: TransportDoH}, "not a bare host"},
		{"doh url with path", Upstream{Address: "dns.example.com/dns-query", Port: 443, Transport: TransportDoH}, "not a bare host"},
		{"doh url with query", Upstream{Address: "dns.example.com?dns=x", Transport: TransportDoH}, "not a bare host"},
		{"doh url with userinfo", Upstream{Address: "user@dns.example.com", Transport: TransportDoH}, "not a bare host"},
		{"doh plaintext url", Upstream{Address: "http://dns.example.com", Port: 80, Transport: TransportDoH}, "not a bare host"},
		{"doh negative port", Upstream{Address: "dns.example.com", Port: -1, Transport: TransportDoH}, "outside the valid range"},
		{"doh port above range", Upstream{Address: "dns.example.com", Port: 65536, Transport: TransportDoH}, "outside the valid range"},
		{"doh loopback", Upstream{Address: "127.0.0.1", Transport: TransportDoH}, "loopback"},
		{"doh loopback hostname", Upstream{Address: "localhost", Transport: TransportDoH}, "loopback"},
		{"doh multicast", Upstream{Address: "224.0.0.1", Transport: TransportDoH}, "multicast"},
		{"doh unspecified", Upstream{Address: "0.0.0.0", Transport: TransportDoH}, "unspecified"},
		{"doh malformed pin", Upstream{Address: "dns.example.com", Transport: TransportDoH, SPKIPin: "not base64!"}, "not valid standard base64"},
		{"doh short pin", Upstream{Address: "dns.example.com", Transport: TransportDoH, SPKIPin: "c2hvcnQ="}, "want a 32-byte SHA-256 digest"},
		{"dot negative port", Upstream{Address: "94.140.14.14", Port: -1, Transport: TransportDoT}, "outside the valid range"},
		{"dot port above range", Upstream{Address: "94.140.14.14", Port: 65536, Transport: TransportDoT}, "outside the valid range"},
		{"dot loopback", Upstream{Address: "127.0.0.1", Transport: TransportDoT}, "loopback"},
		{"dot multicast", Upstream{Address: "224.0.0.1", Port: 853, Transport: TransportDoT}, "multicast"},
		{"pin on plain transport", Upstream{Address: "94.140.14.14", Port: 53, SPKIPin: testSPKIPin()}, "only honored by the encrypted transports"},
		{"pin not base64", Upstream{Address: "94.140.14.14", Transport: TransportDoT, SPKIPin: "not base64!"}, "not valid standard base64"},
		{"pin too short", Upstream{Address: "94.140.14.14", Transport: TransportDoT, SPKIPin: "c2hvcnQ="}, "want a 32-byte SHA-256 digest"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.upstream.Validate()
			if err == nil {
				t.Fatalf("Validate(%+v) = nil, want an error mentioning %q", tc.upstream, tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("Validate(%+v) = %q, want it to mention %q", tc.upstream, err, tc.wantSubstr)
			}
		})
	}
}

func TestUpstreamValidateAccepts(t *testing.T) {
	upstreams := []Upstream{
		{Address: "94.140.14.14", Port: 53},
		{Address: "94.140.14.14", Port: 53, Transport: TransportPlain},
		{Address: "2001:4860:4860::8888", Port: 53},
		{Address: "dns.example.com", Port: 53},
		{Address: "dns.example.com.", Port: 53},
		{Address: "DNS.Example.COM", Port: 5353},
		{Address: "resolver.internal", Port: 53},
		// DoT entries: explicit port, transport default port, hostname and IP
		// literal, with and without a pin.
		{Address: "94.140.14.14", Port: 853, Transport: TransportDoT},
		{Address: "dns.example.com", Transport: TransportDoT},
		{Address: "dns.example.com.", Transport: TransportDoT, SPKIPin: testSPKIPin()},
		{Address: "2001:4860:4860::8888", Transport: TransportDoT},
		{Address: "dns.example.com", Port: 8853, Transport: TransportDoT},
	}
	for _, upstream := range upstreams {
		if err := upstream.Validate(); err != nil {
			t.Fatalf("Validate(%+v) = %v, want nil", upstream, err)
		}
	}
}

// testSPKIPin is a syntactically valid pin: standard base64 of a 32-byte
// SHA-256 digest. Validation checks only the encoding and length, so the value
// itself is irrelevant here.
func testSPKIPin() string {
	digest := sha256.Sum256([]byte("upstream-pin-fixture"))
	return base64.StdEncoding.EncodeToString(digest[:])
}

// TestUpstreamDoTDefaultPort covers the one port default the contract allows:
// 853 when a DoT entry states no port, while plain DNS still requires an
// explicit one. The assertion is made through Validate, because that is the
// contract callers actually get: the port default is only observable as "this
// entry is accepted without a port".
func TestUpstreamDoTDefaultPort(t *testing.T) {
	entry := Upstream{Address: "dns.example.com", Transport: TransportDoT}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate(DoT without port) = %v, want nil", err)
	}
	if got := entry.EffectiveTransport().defaultPort(); got != DefaultDoTPort {
		t.Fatalf("defaultPort() = %d, want %d", got, DefaultDoTPort)
	}

	// Plain DNS has no port default, so the omission is refused rather than
	// silently filled in with a port nobody chose.
	if err := (Upstream{Address: "dns.example.com"}).Validate(); err == nil || !strings.Contains(err.Error(), "explicit port") {
		t.Fatalf("Validate(plain without port) = %v, want an explicit-port error", err)
	}
}

// TestUpstreamDoHDefaultPort covers the DoH port default and the pin contract:
// 443 when a DoH entry states no port, and a pin accepted because DoH verifies
// the leaf key.
func TestUpstreamDoHDefaultPort(t *testing.T) {
	entry := Upstream{Address: "dns.example.com", Transport: TransportDoH, SPKIPin: testSPKIPin()}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate(DoH without port, with pin) = %v, want nil", err)
	}
	if got := entry.EffectiveTransport().defaultPort(); got != DefaultDoHPort {
		t.Fatalf("defaultPort() = %d, want %d", got, DefaultDoHPort)
	}
}

// TestUpstreamSPKIPin covers the pin's decoding, which the encrypted transports
// relied on to verify the leaf key. The pin decoding stays because the entry type
// still describes a pinnable upstream, and a caller reading this package must get
// a decode error rather than a silent "no pin".
func TestUpstreamSPKIPin(t *testing.T) {
	pin := testSPKIPin()
	entry := Upstream{Address: "94.140.14.14", Transport: TransportDoT, SPKIPin: pin}
	digest, err := entry.SPKIPinDigest()
	if err != nil {
		t.Fatalf("SPKIPinDigest() = %v, want nil", err)
	}
	if len(digest) != sha256.Size {
		t.Fatalf("SPKIPinDigest() length = %d, want %d", len(digest), sha256.Size)
	}

	// No pin stays no pin, so a record written without one needs no migration.
	if got, err := (Upstream{Address: "94.140.14.14", Transport: TransportDoT}).SPKIPinDigest(); err != nil || got != nil {
		t.Fatalf("SPKIPinDigest() without a pin = (%v, %v), want (nil, nil)", got, err)
	}

	// A malformed pin is an error, never a silent downgrade to "unpinned".
	if _, err := (Upstream{Address: "94.140.14.14", Transport: TransportDoT, SPKIPin: "not base64!"}).SPKIPinDigest(); err == nil {
		t.Fatal("SPKIPinDigest() on a malformed pin = nil error, want a decode error")
	}
}

func TestUpstreamLoopbackSentinel(t *testing.T) {
	err := Upstream{Address: "127.0.0.1", Port: 53}.Validate()
	if !errors.Is(err, ErrUpstreamLoopback) {
		t.Fatalf("Validate(loopback) = %v, want it to wrap ErrUpstreamLoopback", err)
	}
}

// TestDefaultUpstreamsAreValid is the surviving oracle for the one definition the
// profile renderer reads. Every generated client configuration renders its DNS
// servers from DefaultUpstreams, so a default that is not plain, not addressable
// or not exactly a pair would put an unusable resolver in every new profile with
// no compiler error to warn about it.
func TestDefaultUpstreamsAreValid(t *testing.T) {
	defaults := DefaultUpstreams()
	if len(defaults) != 2 {
		t.Fatalf("DefaultUpstreams() = %v, want 2 entries", defaults)
	}
	for _, upstream := range defaults {
		if err := upstream.Validate(); err != nil {
			t.Fatalf("default upstream %+v is invalid: %v", upstream, err)
		}
		if upstream.EffectiveTransport() != TransportPlain {
			t.Fatalf("default upstream %+v is not plain: a profile would render it as a plain DNS directive", upstream)
		}
		if upstream.Port != DefaultUpstreamPort {
			t.Fatalf("default upstream %+v does not state the plain default port %d", upstream, DefaultUpstreamPort)
		}
		if strings.TrimSpace(upstream.Address) == "" {
			t.Fatalf("default upstream %+v has no address to render", upstream)
		}
	}
}

// TestStoredRecordWithRemovedUpstreamFieldStillLoads is the persistence contract
// for the field this change removes. A record written by an earlier build still
// carries `upstream_dns`; the settings row must keep decoding, because Go's
// decoder ignores a field the struct no longer has. Nothing converts the value and
// nothing needs a migration: it stops being read, and it stops being written on
// the next save.
func TestStoredRecordWithRemovedUpstreamFieldStillLoads(t *testing.T) {
	stored := []byte(`{"enabled":true,"preset":"geoblock","custom_urls":[],` +
		`"sync_interval_seconds":3600,` +
		`"upstream_dns":[{"address":"9.9.9.9","port":853,"transport":"dot","spki_pin":"` + testSPKIPin() + `"}]}`)

	var decoded Settings
	if err := json.Unmarshal(stored, &decoded); err != nil {
		t.Fatalf("unmarshal a record carrying the removed upstream_dns field: %v", err)
	}
	if !decoded.Enabled {
		t.Error("the record's enabled flag was lost")
	}
	if decoded.Preset != PresetGeoblock {
		t.Errorf("preset = %q, want %q", decoded.Preset, PresetGeoblock)
	}
	if decoded.SyncInterval != 3600 {
		t.Errorf("sync_interval_seconds = %d, want 3600", decoded.SyncInterval)
	}
	if decoded.IsZero() {
		t.Error("a record with a preset and enabled decoded as the zero record")
	}
	if err := decoded.Normalize().Validate(); err != nil {
		t.Errorf("a record carrying the removed field no longer validates: %v", err)
	}

	// The removed field does not come back on the way out: a save from this build
	// writes a record that no longer names it at all.
	encoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "upstream_dns") {
		t.Fatalf("a re-saved record still carries upstream_dns: %s", encoded)
	}
}
