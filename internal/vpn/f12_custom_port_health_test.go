//go:build with_utls

package vpn

// F12 — effective-port fidelity of the Naive inner health destination.
//
// Round 9 finding: normal provisioning keeps the installed port on the tunnel
// endpoint but omits params.Port (internal/handlers/vpn.go extractor; Port is
// optional/omitempty). Qualification and the native-daemon readiness probe both
// resolve the port as "explicit params.Port, else endpoint port, else 443", but
// the F11 inner-health path re-derived a params-only rule defaulting to 443, so
// a correctly qualified 8443 backend was health-checked on 443 and swept
// degraded -> disabled.
//
// The oracles below go through the real production consumers: the real
// repository SQLite, NewVPNService wiring, the real *ProxyBackendDevice over a
// real streambridge, the production ProbeCanary/ProbeTunnel dispatch and the
// real health state machine. No packet canary override, no canary-destination
// override, no assertion on a private helper.
//
// Local execution is bounded and offline: the destination-recording case uses an
// egress that refuses without dialing, and the lifecycle case terminates a real
// TLS + HTTP exchange on loopback only (no external network, no native daemon,
// no container/VPS/browser E2E).

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/naive"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/streambridge"
)

// f12DestinationRecorder records the destination the production device egress is
// asked to dial and refuses it without touching the network.
type f12DestinationRecorder struct {
	mu           sync.Mutex
	destinations []string
}

func (d *f12DestinationRecorder) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.destinations = append(d.destinations, address)
	d.mu.Unlock()
	return nil, errors.New("f12 controlled egress refuses the attempted destination; no network executed")
}

func (d *f12DestinationRecorder) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.destinations...)
}

// TestF12_NaiveInnerHealthUsesQualifiedEndpointPort is the destination-fidelity
// oracle: the inner health exchange must address the same effective port the
// qualification exchange proved, for an existing Port 0 record.
func TestF12_NaiveInnerHealthUsesQualifiedEndpointPort(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name          string
		installedPort int
		paramsPort    int
		wantPort      int
	}{
		{name: "normal_custom_port_omitted", installedPort: 8443, paramsPort: 0, wantPort: 8443},
		{name: "explicit_port_control", installedPort: 8443, paramsPort: 8443, wantPort: 8443},
		{name: "ordinary_443_control", installedPort: 443, paramsPort: 0, wantPort: 443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDB(t)
			sid, err := db.CreateServer(ctx, &models.Server{
				Name: "f12 destination " + tc.name,
				Host: "127.0.0.1",
				Protocols: map[string]any{
					models.ProtocolNaive: map[string]any{
						"installed": true,
						"port":      tc.installedPort,
						"domain":    "proxy.example.com",
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			svc, err := NewVPNService(db, nil)
			if err != nil {
				t.Fatal(err)
			}

			params := map[string]any{"username": "fixture", "password": "fixture", "domain": "proxy.example.com"}
			if tc.paramsPort > 0 {
				params["port"] = tc.paramsPort
			}
			raw, err := json.Marshal(params)
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.EnableBackendWithConfig(context.WithValue(ctx, tunnel.DeployEnrollmentKey, true), sid,
				tunnel.BackendTunnelOptions{Protocol: models.ProtocolNaive, ProtocolParams: raw}); err != nil {
				t.Fatalf("EnableBackendWithConfig: %v", err)
			}
			tun, err := svc.GetTunnel(sid)
			if err != nil || tun == nil {
				t.Fatalf("GetTunnel: tun=%v err=%v", tun, err)
			}
			wantEndpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(tc.installedPort))
			if tun.Endpoint != wantEndpoint {
				t.Fatalf("endpoint = %q, want %q", tun.Endpoint, wantEndpoint)
			}

			rec := &f12DestinationRecorder{}
			bridge, err := streambridge.New(streambridge.Config{MTU: 1280}, rec)
			if err != nil {
				t.Fatal(err)
			}
			device := NewProxyBackendDevice(bridge, nil)
			t.Cleanup(func() { _ = device.Close() })
			svc.SetBackendDeviceForTest(tun.ID, device)

			_ = svc.prober.ProbeCanary(ctx, tun)

			want := net.JoinHostPort("proxy.example.com", strconv.Itoa(tc.wantPort))
			got := rec.snapshot()
			if len(got) != 1 || got[0] != want {
				t.Fatalf("inner health destinations = %q, want exactly [%q] (the effective destination qualification uses)", got, want)
			}
		})
	}
}

// f12MappedEgress forwards only the backend's effective destination to a loopback
// TLS origin and refuses everything else, so the pass/fail decision still comes
// from the real authenticated exchange on the address the production code chose.
type f12MappedEgress struct {
	mu       sync.Mutex
	dials    []string
	want     string
	originAd string
}

func (d *f12MappedEgress) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, address)
	d.mu.Unlock()
	if address != d.want {
		return nil, errors.New("f12 mapped egress: " + address + " is not the qualified destination")
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.originAd)
}

func (d *f12MappedEgress) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dials...)
}

// TestF12_NaiveCustomPortBackendStaysSelectable is the durable-lifecycle oracle:
// a backend qualified on a non-443 port with params.Port omitted must survive
// ordinary health sweeps as active/selectable/durable-active, and must still be
// removed from selection when the payload path genuinely breaks.
func TestF12_NaiveCustomPortBackendStaysSelectable(t *testing.T) {
	ctx := context.Background()

	caCert, caKey := setupE2ETestCA(t)
	originAddr, stopOrigin := f11TLSOrigin(t, caCert, caKey, "proxy.example.com")
	var originOnce sync.Once
	stopOriginOnce := func() { originOnce.Do(stopOrigin) }
	defer stopOriginOnce()

	_, originPort := f11MustPort(t, originAddr)

	dbPath := filepath.Join(t.TempDir(), "f12_custom_port.db")
	const dbSecret = "test-secret-key-1234567890123456"
	db, err := database.Open(dbPath, dbSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sid, err := db.CreateServer(ctx, &models.Server{
		Name: "f12 custom port lifecycle",
		Host: "127.0.0.1",
		Protocols: map[string]any{
			models.ProtocolNaive: map[string]any{
				"installed": true,
				"port":      originPort,
				"domain":    "proxy.example.com",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, tun := range svc.pool.ListTunnels() {
			if d := svc.GetBackendDeviceForTest(tun.ID); d != nil {
				_ = d.Close()
			}
		}
	})

	// The persisted params omit the port: the installed port is only on the
	// endpoint, exactly as the ordinary extractor produces.
	raw := []byte(`{"username":"fixture","password":"fixture","domain":"proxy.example.com","enable_h3":false}`)
	if err := svc.EnableBackendWithConfig(context.WithValue(ctx, tunnel.DeployEnrollmentKey, true), sid,
		tunnel.BackendTunnelOptions{Protocol: models.ProtocolNaive, ProtocolParams: raw}); err != nil {
		t.Fatalf("EnableBackendWithConfig: %v", err)
	}
	tun, err := svc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("GetTunnel: tun=%v err=%v", tun, err)
	}
	wantDestination := net.JoinHostPort("proxy.example.com", strconv.Itoa(originPort))
	if tun.Endpoint != net.JoinHostPort("127.0.0.1", strconv.Itoa(originPort)) {
		t.Fatalf("endpoint = %q, want the installed non-443 port", tun.Endpoint)
	}

	// Real device type over the real bridge; only the address is mapped to the
	// loopback origin.
	egress := &f12MappedEgress{want: wantDestination, originAd: originAddr}
	bridge, err := streambridge.New(streambridge.Config{MTU: 1280}, egress)
	if err != nil {
		t.Fatal(err)
	}
	device := NewProxyBackendDevice(bridge, nil)
	t.Cleanup(func() { _ = device.Close() })
	svc.SetBackendDeviceForTest(tun.ID, device)

	// Controlled preconditions (disclosed): the outer protocol probe succeeds and
	// the initial qualification is the real Naive qualifier (probeNaiveProxy) with
	// only its SOCKS transport injected. It resolves the destination from the same
	// endpoint the production code has, so it addresses the installed port exactly
	// as a deployment would. The subject of this oracle is the ordinary
	// inner-health destination, which is NOT overridden anywhere.
	svc.SetProxyProbeFuncsForTest(nil, func(context.Context, string, models.NaiveProxyParams, time.Duration) (int64, error) {
		return 5, nil
	})
	svc.SetProxyTrafficProbeFuncForTest(func(c context.Context, tn *models.BackendTunnel) (int64, error) {
		var p models.NaiveProxyParams
		if err := json.Unmarshal(tn.ProtocolParams, &p); err != nil {
			return 0, err
		}
		return naive.ProbeNaiveProxyWithOptions(c, tn.Endpoint, p, 5*time.Second, naive.WithSocks5Dialer(egress))
	})

	latencyMS, err := svc.QualifyProxyTraffic(ctx, tun)
	if err != nil {
		t.Fatalf("qualification through the real exchange failed: %v", err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, tun, latencyMS); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if svc.prober.GetCanaryProbeFunc() != nil {
		t.Fatal("health must use the production inner probe, not a canary override")
	}
	if svc.prober.IsPendingEnrollment(sid) {
		t.Fatal("qualified backend still marked as pending enrollment")
	}

	// Ordinary sweeps must keep the qualified custom-port backend available.
	for i := 0; i < 3; i++ {
		live, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.prober.ProbeTunnel(ctx, live); err != nil {
			t.Fatalf("sweep %d failed on a genuinely healthy custom-port backend: %v", i+1, err)
		}
		after, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		durable, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Status != models.TunnelStatusActive || durable.Status != models.TunnelStatusActive {
			t.Fatalf("sweep %d: runtime/durable status = %s/%s, want active (dials=%q)", i+1, after.Status, durable.Status, egress.snapshot())
		}
		if !after.Enabled || !durable.Enabled {
			t.Fatalf("sweep %d administratively disabled a healthy backend", i+1)
		}
		if n := len(svc.pool.GetActiveTunnels()); n != 1 {
			t.Fatalf("sweep %d left %d selectable backends, want 1", i+1, n)
		}
		if svc.prober.IsPendingEnrollment(sid) {
			t.Fatalf("sweep %d left the enrollment marker set on a qualified backend", i+1)
		}
		t.Logf("sweep=%d status=%s selectable=%d destinations=%q", i+1, after.Status, len(svc.pool.GetActiveTunnels()), egress.snapshot())
	}

	// Reconstruction: the same existing record, reloaded from a real SQLite
	// reopen by a fresh pool/prober, must stay available under the ordinary
	// destination rule — no migration may be needed for a Port 0 record.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := database.Open(dbPath, dbSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	pool2 := tunnel.NewPool(reopened)
	pool2.SetMultiProtocolEnabled(true)
	prober2 := tunnel.NewHealthProber(pool2, reopened, tunnel.DefaultHealthConfig())
	prober2.SetMultiProtocolEnabled(true)
	prober2.SetNaiveProbeFunc(func(context.Context, string, models.NaiveProxyParams, time.Duration) (int64, error) {
		return 5, nil
	})
	if err := pool2.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool2.ResetEnabledHealthForStartup(ctx); err != nil {
		t.Fatal(err)
	}
	reloaded, err := pool2.GetTunnel(sid)
	if err != nil || reloaded == nil {
		t.Fatalf("GetTunnel after reopen: tun=%v err=%v", reloaded, err)
	}
	var reloadedParams models.NaiveProxyParams
	if err := json.Unmarshal(reloaded.ProtocolParams, &reloadedParams); err != nil {
		t.Fatalf("reloaded protocol params are not valid Naive params: %v", err)
	}
	if reloadedParams.Port != 0 {
		t.Fatalf("reloaded params.Port = %d, want 0 (the existing-record shape under test)", reloadedParams.Port)
	}
	if reloadedParams.Domain != "proxy.example.com" {
		t.Fatalf("reloaded params.Domain = %q, want the TLS identity to be preserved", reloadedParams.Domain)
	}
	prober2.SetDeviceProvider(func(id int64) tunnel.PacketDevice {
		if id == reloaded.ID {
			return device
		}
		return nil
	})
	for i := 0; i < 2; i++ {
		live, err := pool2.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prober2.ProbeTunnel(ctx, live); err != nil {
			t.Fatalf("post-reconstruction sweep %d failed on the reloaded custom-port backend: %v", i+1, err)
		}
		after, err := pool2.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		if after.Status != models.TunnelStatusActive || len(pool2.GetActiveTunnels()) != 1 {
			t.Fatalf("post-reconstruction sweep %d: status=%s selectable=%d, want active/1 (dials=%q)",
				i+1, after.Status, len(pool2.GetActiveTunnels()), egress.snapshot())
		}
		t.Logf("post-reconstruction sweep=%d status=%s selectable=%d destinations=%q", i+1, after.Status, len(pool2.GetActiveTunnels()), egress.snapshot())
	}

	// Negative control: the same production path must still refuse a backend
	// whose payload path is genuinely broken. Uses the live reopened pool/prober
	// so the runtime state machine and durable record are both real.
	stopOriginOnce()
	for i := 0; i < 3; i++ {
		live, err := pool2.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = prober2.ProbeTunnel(ctx, live)
	}
	final, err := pool2.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status == models.TunnelStatusActive && len(pool2.GetActiveTunnels()) == 1 {
		t.Fatalf("a backend whose payload path is broken stayed active and selectable (status=%s)", final.Status)
	}
	durableFinal, err := reopened.GetBackendTunnel(ctx, reloaded.ID)
	if err != nil {
		t.Fatal(err)
	}
	if durableFinal.Status == models.TunnelStatusActive {
		t.Fatalf("a broken-payload backend kept durable status active")
	}
	t.Logf("broken payload: status=%s selectable=%d innerFailures=%d", final.Status, len(pool2.GetActiveTunnels()), prober2.CanaryFailureCount(final.ID))
}

// TestF12_AuthenticNaiveCustomPortKeepsQualifiedBackendAvailable is the authentic
// counterpart of the component oracle above: a real H2 CONNECT proxy bound to a
// non-443 port, a real TLS origin, the real production device and the real
// production health dispatch — with NO canary-destination override and NO probe
// override anywhere. The only fixture arrangement is the existing F11 proxy
// fixture, whose CONNECT target is its own configured echo origin.
//
// Executing gate: remote CI (the with_utls race suite). Authoring it here keeps
// the authentic case on the fixture the F11 repair already uses rather than a
// second harness.
func TestF12_AuthenticNaiveCustomPortKeepsQualifiedBackendAvailable(t *testing.T) {
	ctx := context.Background()

	caCert, caKey := setupE2ETestCA(t)
	originAddr, stopOrigin := f11TLSOrigin(t, caCert, caKey, "localhost")
	var originOnce sync.Once
	stopOriginOnce := func() { originOnce.Do(stopOrigin) }
	defer stopOriginOnce()

	proxyAddr, stopProxy := setupE2ETestH2Server(t, "127.0.0.1:0", "f12-user", "f12-pass", caCert, caKey, originAddr)
	var proxyOnce sync.Once
	stopProxyOnce := func() { proxyOnce.Do(stopProxy) }
	defer stopProxyOnce()

	proxyHost, proxyPort := f11MustPort(t, proxyAddr)
	if proxyPort == 443 {
		t.Skip("ephemeral listener bound the default port; not the custom-port case")
	}

	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, tun := range svc.pool.ListTunnels() {
			if d := svc.GetBackendDeviceForTest(tun.ID); d != nil {
				_ = d.Close()
			}
		}
	})

	sid, err := db.CreateServer(ctx, &models.Server{
		Name: "f12 authentic custom port",
		Host: proxyHost,
		Protocols: map[string]any{
			models.ProtocolNaive: map[string]any{"installed": true, "port": proxyPort, "domain": "localhost"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Exactly the ordinary provisioning shape: the installed port is on the
	// server metadata/endpoint, params carry only credentials and the domain.
	naiveParams := models.NaiveProxyParams{Username: "f12-user", Password: "f12-pass", Domain: "localhost"}
	raw, err := json.Marshal(naiveParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableBackendWithConfig(context.WithValue(ctx, tunnel.DeployEnrollmentKey, true), sid,
		tunnel.BackendTunnelOptions{Protocol: models.ProtocolNaive, ProtocolParams: raw}); err != nil {
		t.Fatalf("EnableBackendWithConfig: %v", err)
	}
	tun, err := svc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("GetTunnel: tun=%v err=%v", tun, err)
	}

	// Real device type over the real naive dialer against the real proxy. The
	// egress only ADMITS the CONNECT destination it is given — it never rewrites
	// it — so a wrong destination fails here instead of being silently satisfied
	// by the fixture's echo remap. The exchange itself stays the production one.
	naiveDialer, err := naive.New(proxyAddr, naiveParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = naiveDialer.Close() })
	qualifiedDestination := net.JoinHostPort("localhost", strconv.Itoa(proxyPort))
	egress := &f12AdmitOnlyEgress{inner: naiveDialer, want: qualifiedDestination}
	bridge, err := streambridge.New(streambridge.Config{MTU: 1280}, egress)
	if err != nil {
		t.Fatal(err)
	}
	device := NewProxyBackendDevice(bridge, nil)
	t.Cleanup(func() { _ = device.Close() })
	svc.SetBackendDeviceForTest(tun.ID, device)

	// Qualification and routine health both run the real Naive exchange; neither
	// the canary destination nor any probe function is overridden.
	latencyMS, err := svc.QualifyProxyTraffic(ctx, tun)
	if err != nil {
		t.Fatalf("authentic custom-port qualification failed: %v", err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, tun, latencyMS); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if svc.prober.GetCanaryProbeFunc() != nil {
		t.Fatal("health must use the production inner probe, not a canary override")
	}
	// No destination override is installed: every recorded dial below must be the
	// production-derived effective destination.

	f11AssertSweepsKeepHealthy(t, svc, db, sid, tun.ID, 3)

	if got := egress.snapshot(); len(got) < 3 {
		t.Fatalf("expected qualification plus three sweeps to reach the proxy, got %d dials: %q", len(got), got)
	}
	for i, d := range egress.snapshot() {
		if d != qualifiedDestination {
			t.Fatalf("dial %d destination = %q, want the qualified %q", i, d, qualifiedDestination)
		}
	}

	stopProxyOnce()
	f11AssertBrokenPayloadDenied(t, svc, sid)
}

// f12AdmitOnlyEgress forwards to the injected stream dialer unchanged and records
// every destination it was asked for. It refuses a destination other than the
// expected one so a wrong effective port fails loudly instead of being served by
// the fixture's own echo remap.
type f12AdmitOnlyEgress struct {
	mu    sync.Mutex
	inner naive.StreamDialer
	want  string
	dials []string
}

func (d *f12AdmitOnlyEgress) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, address)
	d.mu.Unlock()
	if address != d.want {
		return nil, errors.New("f12 admit-only egress: destination " + address + " is not the qualified " + d.want)
	}
	return d.inner.DialContext(ctx, network, address)
}

func (d *f12AdmitOnlyEgress) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dials...)
}
