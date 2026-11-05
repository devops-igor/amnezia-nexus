package vpn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestServiceSetProbeFunc_DefaultCanary(t *testing.T) {
	var absent *Service
	absent.SetProbeFunc(nil)
	(&Service{}).SetProbeFunc(nil)
	svc := &Service{prober: tunnel.NewHealthProber(nil, nil, tunnel.HealthConfig{})}
	svc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return time.Millisecond, nil
	})
	if err := svc.prober.ProbeCanary(t.Context(), &models.BackendTunnel{ID: 713}); err != nil {
		t.Fatalf("outer-only test fixture must have an offline canary: %v", err)
	}
}

func TestServiceSetProbeFunc_PreservesCustomCanary(t *testing.T) {
	for _, order := range []string{"before", "after", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			svc := &Service{prober: tunnel.NewHealthProber(nil, nil, tunnel.HealthConfig{})}
			want := errors.New("custom canary failure")
			setCanary := func() {
				svc.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error { return want })
			}
			setOuter := func() { svc.SetProbeFunc(nil) }
			switch order {
			case "before":
				setCanary()
				setOuter()
			case "after":
				setOuter()
				setCanary()
			case "concurrent":
				var wg sync.WaitGroup
				wg.Go(setOuter)
				wg.Go(setCanary)
				wg.Wait()
			}
			// Replacing the outer probe must not reset a custom inner failure.
			setOuter()
			if err := svc.prober.ProbeCanary(t.Context(), &models.BackendTunnel{ID: 713}); !errors.Is(err, want) {
				t.Fatalf("custom canary overwritten: got %v, want %v", err, want)
			}
		})
	}
}

func TestNewVPNService_RetainsRealCanary(t *testing.T) {
	svc, err := NewVPNService(setupTestDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	backend := &models.BackendTunnel{ID: 713}
	if svc.prober.HasCanaryProber(backend) {
		t.Fatal("production constructor pre-installed a canary override")
	}
	dev := &testCanaryDevice{}
	svc.SetBackendDeviceForTest(backend.ID, dev)
	if err := svc.prober.ProbeCanary(t.Context(), backend); err != nil {
		t.Fatalf("production canary must probe the attached device: %v", err)
	}
	if dev.canaryCalls != 1 {
		t.Fatalf("production canary bypassed the device: calls=%d", dev.canaryCalls)
	}
}
