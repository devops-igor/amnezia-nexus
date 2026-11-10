package router

// The AWG status-provider wiring is easy to lose: it lives inside
// NewRouterWithDeps, and an entrypoint that builds its own handlers instance (so a
// background worker and the HTTP layer share one) has to apply it explicitly.
// These tests pin the helper that both paths now use, so the wiring cannot be
// silently dropped again.

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/handlers"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// TestEnsureAWGStatusProviderSetsItWhenAbsent proves the helper performs the wiring.
func TestEnsureAWGStatusProviderSetsItWhenAbsent(t *testing.T) {
	vpnSvc, err := vpn.NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("init vpn service: %v", err)
	}
	if vpnSvc.HasAWGStatusProvider() {
		t.Fatal("precondition: a fresh service should have no provider")
	}
	deps := handlers.Dependencies{
		VPNService: vpnSvc,
		AWGManager: awg.NewAWGManager(nil),
	}
	EnsureAWGStatusProvider(deps)
	if !vpnSvc.HasAWGStatusProvider() {
		t.Fatal("provider was not wired")
	}
}

// TestEnsureAWGStatusProviderIsIdempotentAndTolerant proves the helper does not
// overwrite an existing provider and does nothing when either side is absent.
func TestEnsureAWGStatusProviderIsIdempotentAndTolerant(t *testing.T) {
	vpnSvc, err := vpn.NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("init vpn service: %v", err)
	}
	first := awg.NewAWGManager(nil)
	vpnSvc.SetAWGStatusProvider(first)
	EnsureAWGStatusProvider(handlers.Dependencies{
		VPNService: vpnSvc,
		AWGManager: awg.NewAWGManager(nil),
	})
	// Still wired (the second call must not have cleared or replaced it).
	if !vpnSvc.HasAWGStatusProvider() {
		t.Fatal("an existing provider was removed")
	}

	// Neither side alone may panic or wire anything.
	EnsureAWGStatusProvider(handlers.Dependencies{})
	EnsureAWGStatusProvider(handlers.Dependencies{VPNService: vpnSvc})
	EnsureAWGStatusProvider(handlers.Dependencies{AWGManager: awg.NewAWGManager(nil)})
}
