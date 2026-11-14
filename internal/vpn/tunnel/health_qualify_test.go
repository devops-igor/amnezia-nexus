package tunnel

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// The qualification must be usable by tests and must never silently degrade to a
// handshake-only success.
func TestQualifyProxyTrafficDispatch(t *testing.T) {
	ctx := context.Background()

	t.Run("nil receivers are refused", func(t *testing.T) {
		var nilProber *HealthProber
		if _, err := nilProber.QualifyProxyTraffic(ctx, nil); err == nil {
			t.Fatal("nil prober must be refused")
		}
		hp := NewHealthProber(nil, nil, DefaultHealthConfig())
		if _, err := hp.QualifyProxyTraffic(ctx, nil); err == nil {
			t.Fatal("nil tunnel must be refused")
		}
	})

	t.Run("fixture override is used", func(t *testing.T) {
		hp := NewHealthProber(nil, nil, DefaultHealthConfig())
		hp.SetProxyTrafficProbeFunc(func(context.Context, *models.BackendTunnel) (int64, error) {
			return 9, nil
		})
		got, err := hp.QualifyProxyTraffic(ctx, &models.BackendTunnel{Protocol: models.ProtocolVLESS})
		if err != nil || got != 9 {
			t.Fatalf("expected fixture latency 9, got %d err=%v", got, err)
		}
	})

	t.Run("nil fixture setter is safe", func(t *testing.T) {
		var nilProber *HealthProber
		nilProber.SetProxyTrafficProbeFunc(nil)
	})

	t.Run("AWG has no proxy traffic qualification", func(t *testing.T) {
		hp := NewHealthProber(nil, nil, DefaultHealthConfig())
		if _, err := hp.QualifyProxyTraffic(ctx, &models.BackendTunnel{Protocol: models.ProtocolAWG}); err == nil {
			t.Fatal("AWG must not qualify through the proxy traffic path")
		}
	})

	t.Run("vless rejects missing and malformed params", func(t *testing.T) {
		hp := NewHealthProber(nil, nil, DefaultHealthConfig())
		if _, err := hp.QualifyProxyTraffic(ctx, &models.BackendTunnel{
			Protocol: models.ProtocolVLESS,
			Endpoint: "192.0.2.90:443",
		}); err == nil {
			t.Fatal("empty vless params must be rejected")
		}
		if _, err := hp.QualifyProxyTraffic(ctx, &models.BackendTunnel{
			Protocol:       models.ProtocolVLESS,
			Endpoint:       "192.0.2.90:443",
			ProtocolParams: json.RawMessage(`{invalid`),
		}); err == nil {
			t.Fatal("malformed vless params must be rejected")
		}
	})

	t.Run("zero configured timeout falls back to the default", func(t *testing.T) {
		hp := NewHealthProber(nil, nil, HealthConfig{})
		done := make(chan struct{})
		hp.SetProxyTrafficProbeFunc(func(ctx context.Context, _ *models.BackendTunnel) (int64, error) {
			close(done)
			return 1, nil
		})
		if _, err := hp.QualifyProxyTraffic(ctx, &models.BackendTunnel{Protocol: models.ProtocolNaive}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("fixture was not invoked")
		}
	})
}
