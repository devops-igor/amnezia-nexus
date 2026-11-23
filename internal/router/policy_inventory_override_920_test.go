package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/handlers"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// The persisted operator override, end to end (issue #920).
//
// The chain under test is the production one: PUT /api/vpn/policy validates and
// persists the record, applies it to the running policy routing service, and the
// classifier the packet path consults must then answer from the operator's set.
// 198.51.100.0/24 (TEST-NET-2) is used because the committed Russian allocation
// does not contain it and no CDN ASN covers it, so a direct answer for an address
// inside it can only come from the override.
func TestPolicyOverrideActivatesThroughTheSettingsAPI(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	cfg.DataDir = t.TempDir()

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { vpnSvc.StopPolicyRouting() })
	t.Cleanup(vpn.SetWANDeviceFactoryForTest(func(string) (forwarder.PacketDevice, error) {
		return policyMutationDevice{}, nil
	}))

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = []string{"203.0.113.0/24"}
	settings.InventoryOverride = []string{"198.51.100.0/24"}
	if err := settings.Validate(); err != nil {
		t.Fatalf("fixture settings are invalid: %v", err)
	}
	// Activation needs a published snapshot; the seeded generation matches this
	// configuration, so activation proceeds on the verified policy.
	seedMatchingPolicyStore(t, cfg.DataDir, settings)

	target := netip.MustParseAddr("198.51.100.7")
	shipped, err := policy.ShippedInventory()
	if err != nil {
		t.Fatalf("ShippedInventory: %v", err)
	}
	if _, covered := shipped.Match(target); covered {
		t.Fatalf("the shipped allocation already contains %s, so this fixture cannot prove the override", target)
	}

	r := NewRouterWithDeps(handlers.Dependencies{Config: cfg, DB: db, VPNService: vpnSvc})
	payload, err := json.Marshal(map[string]any{
		"enabled":               settings.Enabled,
		"proxy_exceptions":      settings.ProxyExceptions,
		"inventory_override":    settings.InventoryOverride,
		"sync_interval_seconds": settings.SyncInterval,
	})
	if err != nil {
		t.Fatalf("marshal policy request: %v", err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", payload))
	if w.Code != http.StatusOK {
		t.Fatalf("saving the override answered %d: %s", w.Code, w.Body.String())
	}

	// The activated data path consults the operator's set: this is the assertion
	// the shipped-set-only build cannot satisfy.
	installed := vpnSvc.DestinationClassifierForTest()
	if installed == nil {
		t.Fatal("activation installed no classifier")
	}
	got := installed.Classify(target)
	if !got.InAllocation || !got.AllocationRoutesDirect() {
		t.Fatalf("activated classifier answered %+v for an override-covered destination, want allocation-matched direct", got)
	}
	if got.Source != policy.InventorySourceOverride {
		t.Fatalf("activated classifier reported source %q, want %q", got.Source, policy.InventorySourceOverride)
	}

	// The status surface names the same override, so an operator reading the
	// policy section sees which set is in force rather than only its effect.
	status := vpnSvc.PolicyStatusSnapshot().Inventory
	if status == nil {
		t.Fatal("policy status carries no inventory block")
	}
	if status.OverridePrefixCount != 1 {
		t.Fatalf("status override prefix count = %d, want 1", status.OverridePrefixCount)
	}
	override, err := settings.ParsedInventoryOverride()
	if err != nil {
		t.Fatalf("ParsedInventoryOverride: %v", err)
	}
	if status.OverrideSHA256 != override.Digest() {
		t.Fatalf("status override digest = %q, want %q", status.OverrideSHA256, override.Digest())
	}
}
