package policy

import (
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
		{"dot not implemented", Upstream{Address: "94.140.14.14", Port: 853, Transport: TransportDoT}, "not supported"},
		{"doh not implemented", Upstream{Address: "dns.example.com", Port: 443, Transport: TransportDoH}, "not supported"},
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
	}
	for _, upstream := range upstreams {
		if err := upstream.Validate(); err != nil {
			t.Fatalf("Validate(%+v) = %v, want nil", upstream, err)
		}
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
