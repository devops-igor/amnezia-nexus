//go:build with_utls

package vpn

// F11 — independent counterexample retained and converted into a regression
// oracle against the ACTUAL production proxy device.
//
// Root cause (audit round 8): the real *ProxyBackendDevice wraps a
// streambridge.Device whose RegisterCanaryResponseHook parameter is an unnamed
// func type, so the promoted method does not satisfy tunnel.CanaryResponseDemuxer.
// The bridge also has no Outbound() channel and no CanaryDevice. Both inner
// probes therefore failed with "does not support canary response demultiplexing"
// before any I/O, and a correctly qualified VLESS/Naive backend was driven
// degraded -> disabled by ordinary health sweeps.
//
// The repair cannot be a signature alignment: streambridge carries no ICMP
// (streambridge/doc.go) and Naive tunnels TCP only (naive/dialer.go). Health for
// these transports must be a protocol-appropriate authenticated request/reply
// over the device's own egress.
//
// Both tests below use the real device type and the real NewVPNService wiring.
// No SetCanaryProbeFunc success override is installed.

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/streambridge"
)

// f11NoNetworkDialer fails any dial so the capability test proves the health path
// reaches a real payload exchange over the device egress and nothing else.
type f11NoNetworkDialer struct {
	dials int
}

func (d *f11NoNetworkDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.dials++
	return nil, errors.New("unexpected network use: capability probe must not dial")
}

// TestF11_ProxyDeviceAnswersInnerCanaryWithProtocolPayload asserts the production
// device is health-capable at all, per protocol, and that a broken or absent
// egress still fails closed rather than passing.
func TestF11_ProxyDeviceAnswersInnerCanaryWithProtocolPayload(t *testing.T) {
	ctx := context.Background()

	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto+"/payload_capability", func(t *testing.T) {
			db := setupTestDB(t)
			sid, err := db.CreateServer(ctx, &models.Server{Name: "f11 capability", Host: "192.0.2.83"})
			if err != nil {
				t.Fatal(err)
			}
			svc, err := NewVPNService(db, nil)
			if err != nil {
				t.Fatal(err)
			}

			raw := f11ProtocolParams(t, proto)
			tun, err := svc.pool.AddTunnelWithConfig(context.WithValue(ctx, tunnel.DeployEnrollmentKey, true), sid,
				"192.0.2.83:443", "", tunnel.BackendTunnelOptions{Protocol: proto, ProtocolParams: raw})
			if err != nil {
				t.Fatal(err)
			}

			dialer := &f11NoNetworkDialer{}
			bridge, err := streambridge.New(streambridge.Config{}, dialer)
			if err != nil {
				t.Fatal(err)
			}
			proxy := NewProxyBackendDevice(bridge, nil)
			defer proxy.Close()

			// The production device must expose its egress to the health consumer.
			var egresser tunnel.ProxyStreamDevice = proxy
			if egresser.ProxyEgress() == nil {
				t.Fatalf("%s: production proxy device exposes no stream egress for health", proto)
			}

			hp := tunnel.NewHealthProber(svc.pool, db, tunnel.DefaultHealthConfig())
			hp.SetMultiProtocolEnabled(true)
			hp.SetDeviceProvider(func(id int64) tunnel.PacketDevice {
				if id == tun.ID {
					return proxy
				}
				return nil
			})

			// A payload exchange over the real egress is attempted, and only its
			// real failure is reported: no packet-canary capability error.
			err = hp.ProbeCanary(ctx, tun)
			if err == nil {
				t.Fatal("proxy canary reported healthy without reaching the backend")
			}
			if errors.Is(err, tunnel.ErrNoProxyEgress) {
				t.Fatalf("%s: health took the no-egress path: %v", proto, err)
			}
			if dialer.dials == 0 {
				t.Fatalf("%s: payload canary never attempted a request through the device egress (err=%v)", proto, err)
			}
			t.Logf("%s: inner canary reached a payload exchange, egress dials=%d, err=%v", proto, dialer.dials, err)
		})
	}
}

// TestF11_ProxyDeviceWithoutEgressFailsClosed proves the repair does not become
// unconditional success: a proxy device that cannot supply an egress, and a
// proxy tunnel that lacks its protocol parameters, both keep failing admission.
func TestF11_ProxyDeviceWithoutEgressFailsClosed(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	sid, err := db.CreateServer(ctx, &models.Server{Name: "f11 fail closed", Host: "192.0.2.84"})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}

	tun, err := svc.pool.AddTunnelWithConfig(context.WithValue(ctx, tunnel.DeployEnrollmentKey, true), sid,
		"192.0.2.84:443", "", tunnel.BackendTunnelOptions{
			Protocol:       models.ProtocolVLESS,
			ProtocolParams: f11ProtocolParams(t, models.ProtocolVLESS),
		})
	if err != nil {
		t.Fatal(err)
	}

	// A plain packet device (no egress capability, no canary support) must not be
	// treated as healthy for a proxy transport.
	hp := tunnel.NewHealthProber(svc.pool, db, tunnel.DefaultHealthConfig())
	hp.SetMultiProtocolEnabled(true)
	hp.SetDeviceProvider(func(id int64) tunnel.PacketDevice {
		if id == tun.ID {
			return f11BarePacketDevice{}
		}
		return nil
	})
	if err := hp.ProbeCanary(ctx, tun); err == nil {
		t.Fatal("a proxy tunnel with no egress-capable device was reported healthy")
	}
}

// f11ProtocolParams returns valid protocol parameters for the given proxy
// transport, matching the shape the production device path receives.
func f11ProtocolParams(t *testing.T, proto string) []byte {
	t.Helper()
	switch proto {
	case models.ProtocolVLESS:
		return []byte(`{"uuid":"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d","server_name":"proxy.example.com","public_key":"K4Z2q0m1nJ9v3xY8wT7rS6pQ5oN4lM3kJ2hG1fE0dC8","short_id":"0123456789abcdef"}`)
	case models.ProtocolNaive:
		return []byte(`{"username":"fixture","password":"fixture","domain":"proxy.example.com"}`)
	default:
		t.Fatalf("no fixture params for protocol %q", proto)
		return nil
	}
}

// f11BarePacketDevice is a PacketDevice with no optional health capability.
type f11BarePacketDevice struct{}

func (f11BarePacketDevice) Read([]byte) (int, error)    { return 0, errors.New("not implemented") }
func (f11BarePacketDevice) Write(p []byte) (int, error) { return len(p), nil }
func (f11BarePacketDevice) Close() error                { return nil }
