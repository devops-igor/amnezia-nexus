package main

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// Regression for F824-01 at the panel entrypoint: a saved upstream list must
// reach the continuity responder even when the persisted record has policy
// routing disabled, which is the state every issued gateway-DNS profile is in
// after the feature was turned off.
func TestDisabledStartupInstallsPersistedUpstreams(t *testing.T) {
	db, cfg, settings := newPolicyStartupFixture(t)
	settings.Enabled = false
	settings.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := db.SetSetting(context.Background(), policy.SettingsKey, settings); err != nil {
		t.Fatalf("persist the disabled record: %v", err)
	}

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { vpnSvc.StopPolicyRouting() })
	t.Cleanup(func() { _ = vpnSvc.Stop() })

	if err := startPersistedPolicyRouting(context.Background(), db, vpnSvc, cfg); err != nil {
		t.Fatalf("startup with a disabled record returned an error: %v", err)
	}
	if vpnSvc.PBREnabled() {
		t.Fatal("policy routing is enabled for a disabled record")
	}

	got := vpnSvc.EffectiveDNSUpstreams()
	if len(got) != 1 || got[0].Address != "9.9.9.9" || got[0].Port != 53 {
		t.Fatalf("disabled startup left the responder on %v, want the persisted list [9.9.9.9:53]", got)
	}
}

// The compatibility control: a disabled record written before the field existed
// carries no list, so startup must keep the effective default pair.
func TestDisabledStartupWithoutListKeepsDefaults(t *testing.T) {
	db, cfg, _ := newPolicyStartupFixture(t)
	var legacy policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &legacy); err != nil {
		t.Fatalf("read the fixture record: %v", err)
	}
	legacy.Enabled = false
	legacy.UpstreamDNS = nil
	if err := db.SetSetting(context.Background(), policy.SettingsKey, legacy); err != nil {
		t.Fatalf("persist the pre-field record: %v", err)
	}

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { vpnSvc.StopPolicyRouting() })
	t.Cleanup(func() { _ = vpnSvc.Stop() })

	if err := startPersistedPolicyRouting(context.Background(), db, vpnSvc, cfg); err != nil {
		t.Fatalf("startup returned an error: %v", err)
	}
	got := vpnSvc.EffectiveDNSUpstreams()
	if len(got) != len(policy.DefaultUpstreams()) || got[0] != policy.DefaultUpstreams()[0] {
		t.Fatalf("pre-field record yielded %v, want the default pair", got)
	}
}
