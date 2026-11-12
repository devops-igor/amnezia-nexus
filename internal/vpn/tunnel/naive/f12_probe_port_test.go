package naive

// F12 — the qualification exchange and the routine in-tunnel health exchange must
// address the same effective destination.
//
// Round 9 evidence (tasks/issue-703/evidence/audit-round-9/comparison.log) drove
// one ordinary parameter set through the qualifier and through the F11 inner
// health helper: qualification resolved proxy.example.com:8443 from the tunnel
// endpoint, while inner health fell back to proxy.example.com:443 because its
// private resolver only looked at params.Port. The helper now takes the endpoint
// and shares resolveProbePort with the qualifier, so the two cannot diverge.
//
// No sockets or servers: both exchanges record the address they were asked to
// dial and stop there, so this oracle is about destination selection only.

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type f12RecordingDialer struct {
	destinations []string
}

func (d *f12RecordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.destinations = append(d.destinations, address)
	return nil, errors.New("f12 recording dialer: no network executed")
}

func TestF12_QualificationAndInnerHealthUseSameEffectiveDestination(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		port     int
		want     string
	}{
		{name: "endpoint_port_omitted_param", endpoint: "192.0.2.83:8443", port: 0, want: "proxy.example.com:8443"},
		{name: "explicit_param_port_wins", endpoint: "192.0.2.83:9443", port: 8443, want: "proxy.example.com:8443"},
		{name: "ordinary_443", endpoint: "192.0.2.83:443", port: 0, want: "proxy.example.com:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := models.NaiveProxyParams{Username: "fixture", Password: "fixture", Domain: "proxy.example.com", Port: tc.port}

			qualifier := &f12RecordingDialer{}
			_, _ = ProbeNaiveProxyWithOptions(context.Background(), tc.endpoint, params, time.Second, WithSocks5Dialer(qualifier))

			inner := &f12RecordingDialer{}
			_, _ = ProbeNaiveTrafficViaDialer(context.Background(), inner, params, tc.endpoint, time.Second)

			if len(qualifier.destinations) != 1 || qualifier.destinations[0] != tc.want {
				t.Fatalf("qualification destination = %q, want [%q]", qualifier.destinations, tc.want)
			}
			if len(inner.destinations) != 1 || inner.destinations[0] != qualifier.destinations[0] {
				t.Fatalf("inner health destination = %q, want the qualification destination %q", inner.destinations, qualifier.destinations[0])
			}
		})
	}
}
