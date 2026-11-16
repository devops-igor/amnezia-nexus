package policy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

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
// 853 when a DoT entry states no port, applied before the record is written,
// while plain DNS still requires an explicit one.
func TestUpstreamDoTDefaultPort(t *testing.T) {
	entry := Upstream{Address: "dns.example.com", Transport: TransportDoT}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate(DoT without port) = %v, want nil", err)
	}
	if got := entry.EffectivePort(); got != DefaultDoTPort {
		t.Fatalf("EffectivePort() = %d, want %d", got, DefaultDoTPort)
	}
	if got := entry.HostPort(); got != "dns.example.com:853" {
		t.Fatalf("HostPort() = %q, want %q", got, "dns.example.com:853")
	}
	if got := entry.String(); got != "dot://dns.example.com:853" {
		t.Fatalf("String() = %q, want %q", got, "dot://dns.example.com:853")
	}

	// The persisted record states the port it dials.
	normalized := Settings{UpstreamDNS: []Upstream{entry}}.Normalize()
	if got := normalized.UpstreamDNS[0].Port; got != DefaultDoTPort {
		t.Fatalf("Normalize() port = %d, want the DoT default %d", got, DefaultDoTPort)
	}

	// An explicit port is honored, and plain DNS still has no port default.
	if got := (Upstream{Address: "dns.example.com", Port: 8853, Transport: TransportDoT}).HostPort(); got != "dns.example.com:8853" {
		t.Fatalf("explicit DoT HostPort() = %q, want %q", got, "dns.example.com:8853")
	}
	if err := (Upstream{Address: "dns.example.com"}).Validate(); err == nil || !strings.Contains(err.Error(), "explicit port") {
		t.Fatalf("Validate(plain without port) = %v, want an explicit-port error", err)
	}
}

// TestUpstreamSPKIPin covers the pin's persisted shape and its decoding, which
// the resolver relies on to verify the leaf key.
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

	// The pin survives the persisted representation.
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"spki_pin"`) {
		t.Fatalf("marshalled entry %s has no spki_pin field", raw)
	}
	var reloaded Upstream
	if err := json.Unmarshal(raw, &reloaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if reloaded != entry {
		t.Fatalf("reloaded entry = %+v, want %+v", reloaded, entry)
	}

	// No pin stays no pin, so a slice-1 record needs no migration.
	if got, err := (Upstream{Address: "94.140.14.14", Transport: TransportDoT}).SPKIPinDigest(); err != nil || got != nil {
		t.Fatalf("SPKIPinDigest() without a pin = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestUpstreamLoopbackSentinel(t *testing.T) {
	err := Upstream{Address: "127.0.0.1", Port: 53}.Validate()
	if !errors.Is(err, ErrUpstreamLoopback) {
		t.Fatalf("Validate(loopback) = %v, want it to wrap ErrUpstreamLoopback", err)
	}
}

func TestUpstreamHostPortFormatting(t *testing.T) {
	if got := (Upstream{Address: "94.140.14.14", Port: 53}).HostPort(); got != "94.140.14.14:53" {
		t.Fatalf("HostPort() = %q, want %q", got, "94.140.14.14:53")
	}
	if got := (Upstream{Address: "2001:db8::1", Port: 53}).HostPort(); got != "[2001:db8::1]:53" {
		t.Fatalf("HostPort() = %q, want %q", got, "[2001:db8::1]:53")
	}
	if got := (Upstream{Address: "94.140.14.14", Port: 853, Transport: TransportDoT}).String(); got != "dot://94.140.14.14:853" {
		t.Fatalf("String() = %q, want %q", got, "dot://94.140.14.14:853")
	}
}

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
			t.Fatalf("default upstream %+v is not plain", upstream)
		}
	}
}

func TestSettingsEffectiveUpstreams(t *testing.T) {
	// An empty list means "use the defaults", not "no resolver".
	empty := Settings{}
	if got := empty.EffectiveUpstreams(); len(got) != len(DefaultUpstreams()) {
		t.Fatalf("EffectiveUpstreams() on an empty record = %v, want the defaults", got)
	}

	configured := []Upstream{{Address: "9.9.9.9", Port: 53}}
	settings := Settings{UpstreamDNS: configured}
	got := settings.EffectiveUpstreams()
	if len(got) != 1 || got[0] != configured[0] {
		t.Fatalf("EffectiveUpstreams() = %v, want %v", got, configured)
	}
	// The returned slice is owned by the caller.
	got[0].Address = "203.0.113.1"
	if settings.UpstreamDNS[0].Address != "9.9.9.9" {
		t.Fatalf("EffectiveUpstreams() aliased the stored record: %+v", settings.UpstreamDNS)
	}

	// A DoT entry that states no port reaches the consumer with its effective
	// port, so nothing downstream has to invent the transport default.
	withDot := Settings{UpstreamDNS: []Upstream{{Address: "dns.example.com", Transport: TransportDoT}}}
	effective := withDot.EffectiveUpstreams()
	if len(effective) != 1 || effective[0].Port != DefaultDoTPort {
		t.Fatalf("EffectiveUpstreams() for a DoT entry = %v, want port %d", effective, DefaultDoTPort)
	}
}

func validSettingsBase() Settings {
	s := DefaultSettings()
	s.Preset = PresetGeoblock
	return s
}

func TestSettingsValidateUpstreamList(t *testing.T) {
	t.Run("too many entries", func(t *testing.T) {
		s := validSettingsBase()
		s.UpstreamDNS = []Upstream{
			{Address: "94.140.14.14", Port: 53},
			{Address: "94.140.15.15", Port: 53},
			{Address: "9.9.9.9", Port: 53},
			{Address: "8.8.8.8", Port: 53},
		}
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), "exceed the maximum") {
			t.Fatalf("Validate() = %v, want a maximum-entries error", err)
		}
	})

	t.Run("duplicate entry", func(t *testing.T) {
		s := validSettingsBase()
		s.UpstreamDNS = []Upstream{
			{Address: "9.9.9.9", Port: 53},
			{Address: "9.9.9.9", Port: 53},
		}
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), "duplicates") {
			t.Fatalf("Validate() = %v, want a duplicate error", err)
		}
	})

	t.Run("invalid entry reports its position", func(t *testing.T) {
		s := validSettingsBase()
		s.UpstreamDNS = []Upstream{
			{Address: "9.9.9.9", Port: 53},
			{Address: "127.0.0.1", Port: 53},
		}
		err := s.Validate()
		if err == nil {
			t.Fatal("Validate() = nil, want a rejection")
		}
		if !strings.Contains(err.Error(), "entry 2") || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("Validate() = %q, want it to name entry 2 and the loopback rule", err)
		}
	})

	t.Run("three valid entries accepted", func(t *testing.T) {
		s := validSettingsBase()
		s.UpstreamDNS = []Upstream{
			{Address: "94.140.14.14", Port: 53},
			{Address: "2001:4860:4860::8888", Port: 53},
			{Address: "dns.example.com", Port: 5353, Transport: TransportPlain},
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("three dot entries accepted including a pin", func(t *testing.T) {
		s := validSettingsBase()
		s.UpstreamDNS = []Upstream{
			{Address: "94.140.14.14", Port: 853, Transport: TransportDoT},
			{Address: "dns.example.com", Transport: TransportDoT, SPKIPin: testSPKIPin()},
			{Address: "2001:4860:4860::8888", Port: 853, Transport: TransportDoT},
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("mixed transports accepted and one alternate survives", func(t *testing.T) {
		s := validSettingsBase()
		s.UpstreamDNS = []Upstream{
			{Address: "94.140.14.14", Transport: TransportDoT},
			{Address: "94.140.15.15", Port: 53},
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("same address on plain and dot is not a duplicate", func(t *testing.T) {
		s := validSettingsBase()
		s.UpstreamDNS = []Upstream{
			{Address: "94.140.14.14", Port: 53},
			{Address: "94.140.14.14", Port: 853, Transport: TransportDoT},
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("doh entry is accepted next to the other transports", func(t *testing.T) {
		s := validSettingsBase()
		s.UpstreamDNS = []Upstream{
			{Address: "dns.adguard-dns.com", Port: 443, Transport: TransportDoH},
			{Address: "dns.adguard-dns.com", Port: 853, Transport: TransportDoT},
			{Address: "94.140.14.14", Port: 53},
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("doh accepts hostname, trailing dot, ipv4 and ipv6 literals", func(t *testing.T) {
		for _, address := range []string{"dns.example.com", "dns.example.com.", "94.140.14.14", "2a10:50c0::ad1:ff"} {
			s := validSettingsBase()
			s.UpstreamDNS = []Upstream{{Address: address, Transport: TransportDoH}}
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate(doh %q) = %v, want nil", address, err)
			}
		}
	})

	t.Run("doh url in the address is refused and names the fix", func(t *testing.T) {
		s := validSettingsBase()
		s.UpstreamDNS = []Upstream{{Address: "https://dns.example.com/dns-query", Transport: TransportDoH}}
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), "not a bare host") || !strings.Contains(err.Error(), "entry 1 rejected") {
			t.Fatalf("Validate() = %v, want a specific bare-host error for entry 1", err)
		}
	})

	t.Run("no list keeps the default and validates", func(t *testing.T) {
		if err := validSettingsBase().Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})
}

// TestSettingsUpstreamJSONRoundTrip covers the persisted representation: the
// record must decode back into the same effective configuration, which is what a
// restart does.
func TestSettingsUpstreamJSONRoundTrip(t *testing.T) {
	saved := validSettingsBase()
	saved.UpstreamDNS = []Upstream{{Address: "9.9.9.9", Port: 53}, {Address: "dns.example.com", Port: 5353}}

	raw, err := json.Marshal(saved)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"upstream_dns"`) {
		t.Fatalf("marshalled record %s has no upstream_dns field", raw)
	}

	var reloaded Settings
	if err := json.Unmarshal(raw, &reloaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reloaded = reloaded.Normalize()
	if err := reloaded.Validate(); err != nil {
		t.Fatalf("reloaded record is invalid: %v", err)
	}
	effective := reloaded.EffectiveUpstreams()
	if len(effective) != len(saved.UpstreamDNS) {
		t.Fatalf("reloaded upstreams = %v, want %v", effective, saved.UpstreamDNS)
	}
	for i := range saved.UpstreamDNS {
		if effective[i] != saved.UpstreamDNS[i] {
			t.Fatalf("reloaded upstream %d = %+v, want %+v", i, effective[i], saved.UpstreamDNS[i])
		}
	}
}

// TestLegacySettingsRecordKeepsEffectiveDefault is the upgrade path: a record
// written before the upstream field existed must keep working and resolve
// through the current effective default.
func TestLegacySettingsRecordKeepsEffectiveDefault(t *testing.T) {
	legacy := []byte(`{"enabled":true,"preset":"geoblock","custom_urls":[],"sync_interval_seconds":3600}`)

	var stored Settings
	if err := json.Unmarshal(legacy, &stored); err != nil {
		t.Fatalf("unmarshal legacy record: %v", err)
	}
	if stored.IsZero() {
		t.Fatal("legacy record with a preset decoded as the zero record")
	}
	if len(stored.UpstreamDNS) != 0 {
		t.Fatalf("legacy record gained upstreams: %v", stored.UpstreamDNS)
	}
	if err := stored.Normalize().Validate(); err != nil {
		t.Fatalf("legacy record no longer validates: %v", err)
	}
	effective := stored.EffectiveUpstreams()
	defaults := DefaultUpstreams()
	if len(effective) != len(defaults) {
		t.Fatalf("legacy record effective upstreams = %v, want %v", effective, defaults)
	}
	for i := range defaults {
		if effective[i] != defaults[i] {
			t.Fatalf("legacy record effective upstream %d = %+v, want %+v", i, effective[i], defaults[i])
		}
	}
}

// TestUpstreamDoHDefaultPort covers the DoH port default and the pin contract:
// 443 when a DoH entry states no port, applied before the record is written, an
// explicit port honored, and a pin accepted because DoH verifies the leaf key.
func TestUpstreamDoHDefaultPort(t *testing.T) {
	entry := Upstream{Address: "dns.example.com", Transport: TransportDoH, SPKIPin: testSPKIPin()}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate(DoH without port, with pin) = %v, want nil", err)
	}
	if got := entry.EffectivePort(); got != DefaultDoHPort {
		t.Fatalf("EffectivePort() = %d, want %d", got, DefaultDoHPort)
	}
	if got := entry.String(); got != "doh://dns.example.com:443" {
		t.Fatalf("String() = %q, want %q", got, "doh://dns.example.com:443")
	}
	normalized := Settings{UpstreamDNS: []Upstream{entry}}.Normalize()
	if got := normalized.UpstreamDNS[0].Port; got != DefaultDoHPort {
		t.Fatalf("Normalize() port = %d, want the DoH default %d", got, DefaultDoHPort)
	}
	if got := (Upstream{Address: "dns.example.com", Port: 8443, Transport: TransportDoH}).HostPort(); got != "dns.example.com:8443" {
		t.Fatalf("explicit DoH HostPort() = %q, want %q", got, "dns.example.com:8443")
	}
}
