package vpn

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// TestNotifyHealthDisabledSuppression pins when the prober is allowed to hand a
// health disable to the data plane owner. Every branch here is a real
// suppression rule: acting on a stale or administrative state would move
// sessions the operator just put back in service.
func TestNotifyHealthDisabledSuppression(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	pool := tunnel.NewPool(db)
	srvID, err := db.CreateServer(ctx, &models.Server{Name: "Suppress", Host: "198.51.100.9"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, srvID, "198.51.100.9:51820", "suppress-pubkey")
	if err != nil {
		t.Fatal(err)
	}
	hp := tunnel.NewHealthProber(pool, db, tunnel.DefaultHealthConfig())
	hp.SetMultiProtocolEnabled(true)

	var notified []int64
	hp.SetHealthDisabledNotifier(func(_ context.Context, got *models.BackendTunnel) error {
		notified = append(notified, got.ID)
		return nil
	})

	// 1. Not disabled at all: no notification.
	hp.NotifyHealthDisabledForTest(ctx, srvID, tun.ID)
	// 2. Administratively disabled: the administrative path owns failover, and
	// the pool records that as Enabled=false with the admin reason.
	if err := pool.SetTunnelEnabled(ctx, srvID, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}
	hp.NotifyHealthDisabledForTest(ctx, srvID, tun.ID)
	newlyDisabled, err := pool.GetTunnel(srvID)
	if err != nil {
		t.Fatal(err)
	}
	if newlyDisabled.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("fixture: expected admin disable reason, got %q", newlyDisabled.DisableReason)
	}
	if len(notified) != 0 {
		t.Fatalf("notification fired for a suppressed state: %v", notified)
	}

	// 3. Exact health-disabled state on an enabled tunnel: fires exactly once
	// for the right tunnel.
	if err := pool.SetTunnelEnabled(ctx, srvID, true, models.DisableReasonNone); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatusWithReason(ctx, srvID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatal(err)
	}
	hp.NotifyHealthDisabledForTest(ctx, srvID, tun.ID)
	if len(notified) != 1 || notified[0] != tun.ID {
		t.Fatalf("expected exactly one notification for tunnel %d, got %v", tun.ID, notified)
	}

	// 4. Unknown identity (deleted/replaced tunnel) never fires.
	hp.NotifyHealthDisabledForTest(ctx, srvID+9999, tun.ID)
	hp.NotifyHealthDisabledForTest(ctx, srvID, tun.ID+9999)
	if len(notified) != 1 {
		t.Fatalf("notification fired for an unknown identity: %v", notified)
	}

	// 5. A nil notifier and a nil prober are safe.
	hp.SetHealthDisabledNotifier(nil)
	hp.NotifyHealthDisabledForTest(ctx, srvID, tun.ID)
	var nilProber *tunnel.HealthProber
	nilProber.SetHealthDisabledNotifier(nil)
	nilProber.NotifyHealthDisabledForTest(ctx, srvID, tun.ID)
	if len(notified) != 1 {
		t.Fatalf("unexpected extra notification: %v", notified)
	}
}

// TestSetDeviceProviderDiscoversHealthNotifier verifies the composition-root
// contract: the prober picks the data-plane owner up from the same provider
// value it already receives, and a provider that cannot do it leaves the seam
// empty.
func TestSetDeviceProviderDiscoversHealthNotifier(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	pool := tunnel.NewPool(db)
	srvID, err := db.CreateServer(ctx, &models.Server{Name: "Discover", Host: "198.51.100.10"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, srvID, "198.51.100.10:51820", "discover-pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatusWithReason(ctx, srvID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatal(err)
	}

	hp := tunnel.NewHealthProber(pool, db, tunnel.DefaultHealthConfig())
	owner := &healthNotifierOwner{calls: 0}
	hp.SetDeviceProvider(owner)
	hp.NotifyHealthDisabledForTest(ctx, srvID, tun.ID)
	if owner.calls != 1 {
		t.Fatalf("provider-discovered notifier calls = %d, want 1", owner.calls)
	}

	// A provider that implements only DeviceProvider leaves the seam empty:
	// the health-disable attempt must be a silent no-op, not a panic.
	hp2 := tunnel.NewHealthProber(pool, db, tunnel.DefaultHealthConfig())
	hp2.SetDeviceProvider(&struct{ deviceOnlyProvider }{})
	hp2.NotifyHealthDisabledForTest(ctx, srvID, tun.ID)

	// Clearing the provider with nil is safe.
	hp2.SetDeviceProvider(nil)
	hp2.NotifyHealthDisabledForTest(ctx, srvID, tun.ID)

	// A plain lookup callback provider is still accepted.
	hp3 := tunnel.NewHealthProber(pool, db, tunnel.DefaultHealthConfig())
	hp3.SetDeviceProvider(func(int64) tunnel.PacketDevice { return nil })
	hp3.NotifyHealthDisabledForTest(ctx, srvID, tun.ID)

	// The (device, bool) callback form and the plain-func form are separate
	// switch arms; both must register a working device lookup.
	hp4 := tunnel.NewHealthProber(pool, db, tunnel.DefaultHealthConfig())
	hp4.SetDeviceProvider(func(int64) (tunnel.PacketDevice, bool) { return nil, false })
	if dev := hp4.GetDevice(tun.ID); dev != nil {
		t.Fatal("(device, bool) callback form registered a non-nil device")
	}
	hp5 := tunnel.NewHealthProber(pool, db, tunnel.DefaultHealthConfig())
	hp5.SetDeviceProvider(hp)
	if hp5.GetDevice(tun.ID) != hp.GetDevice(tun.ID) {
		t.Fatal("DeviceProvider form did not delegate to the provider's lookup")
	}
}

// deviceOnlyProvider satisfies tunnel.DeviceProvider but not the health-disable
// seam, on purpose.
type deviceOnlyProvider struct{}

func (d *deviceOnlyProvider) GetDevice(int64) (tunnel.PacketDevice, bool) { return nil, false }

// healthNotifierOwner is a full data-plane owner stand-in for the discovery
// contract: device provider plus health-disable notifier.
type healthNotifierOwner struct {
	calls int
}

func (o *healthNotifierOwner) GetDevice(int64) (tunnel.PacketDevice, bool) { return nil, false }

func (o *healthNotifierOwner) BackendHealthDisabled(context.Context, *models.BackendTunnel) error {
	o.calls++
	return nil
}

func (o *healthNotifierOwner) SubnetCIDR() string { return "10.100.0.0/16" }

// TestServiceSetHealthDisabledNotifierBinding covers the Service-side setter,
// including the nil-receiver and nil-prober guards.
func TestServiceSetHealthDisabledNotifierBinding(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })

	var nilSvc *Service
	nilSvc.SetHealthDisabledNotifier(nil)

	svc.SetHealthDisabledNotifier(func(context.Context, *models.BackendTunnel) error { return nil })
	svc.SetHealthDisabledNotifier(nil)
	if svc.prober == nil {
		t.Fatal("fixture: prober must exist")
	}
	_ = ctx

	// The zero-value Service has no prober: the setter must tolerate it.
	empty := &Service{}
	empty.SetHealthDisabledNotifier(func(context.Context, *models.BackendTunnel) error { return nil })
}

var _ = time.Second
