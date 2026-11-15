package handlers

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// TestPolicySettingsEqualCoversUpstreamList pins the compensation guard: a save
// that only changed the upstream list must be recognised as a different record,
// so a refused activation cannot mistake it for the value it wrote and skip the
// rollback.
func TestPolicySettingsEqualCoversUpstreamList(t *testing.T) {
	base := policy.DefaultSettings()
	base.Preset = policy.PresetGeoblock
	base.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}

	if !policySettingsEqual(base, base.Normalize()) {
		t.Fatal("a record is not equal to its own normalized copy")
	}

	other := base.Normalize()
	other.UpstreamDNS = []policy.Upstream{{Address: "1.0.0.1", Port: 53}}
	if policySettingsEqual(base, other) {
		t.Fatal("records with different upstream lists compared equal")
	}

	more := base.Normalize()
	more.UpstreamDNS = append(more.UpstreamDNS, policy.Upstream{Address: "1.0.0.1", Port: 53})
	if policySettingsEqual(base, more) {
		t.Fatal("records with different upstream counts compared equal")
	}

	noUpstreams := base.Normalize()
	noUpstreams.UpstreamDNS = nil
	if policySettingsEqual(base, noUpstreams) {
		t.Fatal("a record with an empty upstream list compared equal to one with entries")
	}

	for _, mutate := range []func(*policy.Settings){
		func(s *policy.Settings) { s.Enabled = !s.Enabled },
		func(s *policy.Settings) { s.Preset = policy.PresetCustom },
		func(s *policy.Settings) { s.SyncInterval++ },
		func(s *policy.Settings) { s.CustomURLs = []string{"https://lists.example/domains.lst"} },
	} {
		changed := base.Normalize()
		mutate(&changed)
		if policySettingsEqual(base, changed) {
			t.Fatalf("a record changed by %p compared equal: %+v", mutate, changed)
		}
	}
}
