package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/streambridge"
)

type dummyCloser struct {
	closed bool
	err    error
}

func (d *dummyCloser) Close() error {
	d.closed = true
	return d.err
}

type dummyStreamDialer struct{}

func (d *dummyStreamDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func TestProxyBackendDevice_Close(t *testing.T) {
	bridgeDev, err := streambridge.New(streambridge.Config{}, &dummyStreamDialer{})
	if err != nil {
		t.Fatalf("streambridge.New failed: %v", err)
	}

	dialerCloser := &dummyCloser{}
	proxyDev := NewProxyBackendDevice(bridgeDev, dialerCloser)

	if proxyDev.IsClosed() {
		t.Fatal("device should not be closed initially")
	}

	if err := proxyDev.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !proxyDev.IsClosed() {
		t.Fatal("bridge device should be marked closed")
	}
	if !dialerCloser.closed {
		t.Fatal("dialer closer should be closed")
	}

	// Idempotent close
	if err := proxyDev.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestProxyBackendDevice_CloseErrorsJoined(t *testing.T) {
	bridgeDev, err := streambridge.New(streambridge.Config{}, &dummyStreamDialer{})
	if err != nil {
		t.Fatalf("streambridge.New failed: %v", err)
	}

	expectedErr := errors.New("dialer pool close error")
	dialerCloser := &dummyCloser{err: expectedErr}
	proxyDev := NewProxyBackendDevice(bridgeDev, dialerCloser)

	err = proxyDev.Close()
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected joined error to contain %v, got: %v", expectedErr, err)
	}
}

func TestService_SelectTunnel_ProtocolFamily(t *testing.T) {
	caps := loadbalancer.CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 10,
	}
	lb := loadbalancer.NewRoundRobinBalancer(caps)

	awgTun := &models.BackendTunnel{
		ID:       1,
		Status:   "active",
		Enabled:  true,
		Protocol: models.ProtocolAWG,
	}
	vlessTun := &models.BackendTunnel{
		ID:       2,
		Status:   "active",
		Enabled:  true,
		Protocol: models.ProtocolVLESS,
	}

	lb.UpdateBackends([]*models.BackendTunnel{awgTun})

	svc := &Service{
		balancer: lb,
	}
	ctx := context.Background()

	// 1. Filter for AWG returns AWG
	res, err := svc.SelectTunnel(ctx, []*models.BackendTunnel{awgTun, vlessTun}, "awg")
	if err != nil || res.ID != 1 {
		t.Fatalf("expected AWG tunnel 1, got res=%+v err=%v", res, err)
	}

	// 2. Filter for VLESS returns VLESS
	res, err = svc.SelectTunnel(ctx, []*models.BackendTunnel{awgTun, vlessTun}, "vless")
	if err != nil || res.ID != 2 {
		t.Fatalf("expected VLESS tunnel 2, got res=%+v err=%v", res, err)
	}

	// 3. Filter for Naive with no Naive candidates returns ErrNoActiveBackends
	// (MUST NOT fall back to cached AWG tunnel 1!)
	_, err = svc.SelectTunnel(ctx, []*models.BackendTunnel{awgTun, vlessTun}, "naive")
	if !errors.Is(err, loadbalancer.ErrNoActiveBackends) {
		t.Fatalf("expected ErrNoActiveBackends, got err=%v", err)
	}
}

func TestService_MigrateSession_RejectsCrossProtocol(t *testing.T) {
	pool := tunnel.NewPool(nil)
	pool.SetMultiProtocolEnabled(true)
	ctx := context.Background()

	// Create source AWG tunnel
	t1, err := pool.AddTunnel(ctx, 10, "10.0.0.1:51820", "pub1")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	// Create target VLESS tunnel
	vlessRaw, _ := json.Marshal(models.VLESSRealityParams{UUID: "uuid1"})
	t2, err := pool.AddTunnelWithConfig(ctx, 20, "10.0.0.2:443", "", tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: vlessRaw,
	})
	if err != nil {
		t.Fatalf("AddTunnelWithConfig failed: %v", err)
	}
	_ = pool.SetTunnelStatus(ctx, 20, models.TunnelStatusActive, 10)

	sessionMgr := session.NewSessionManager(nil, nil)
	sess, err := sessionMgr.CreateSession(ctx, "u1", "peer1", "10.100.0.2", t1.ID, "client1")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	svc := &Service{
		pool:       pool,
		sessionMgr: sessionMgr,
		cfg: &models.VPNConfig{
			EnableMultiProtocolBackends: true,
		},
	}

	// Attempt cross-protocol migration: AWG -> VLESS
	err = svc.MigrateSession(ctx, sess.ID, t2.ID)
	if err == nil || !strings.Contains(err.Error(), "cross-protocol migration rejected") {
		t.Fatalf("expected cross-protocol migration rejection, got: %v", err)
	}

	// Verify session remained on source tunnel
	snapshotAfter, ok := sessionMgr.GetSessionSnapshotByID(sess.ID)
	if !ok || snapshotAfter.BackendTunnelID != t1.ID {
		t.Fatalf("session was corrupted by rejected migration: %+v", snapshotAfter)
	}
}

func TestService_UpdateConfig_MultiProtocolToggleRunningRejected(t *testing.T) {
	h := models.DegenerateHeaderRange(10)
	svc := &Service{
		running: true,
		cfg: &models.VPNConfig{
			EnableMultiProtocolBackends: false,
			ListenPort:                  51820,
			H1:                          h,
			H2:                          h,
			H3:                          h,
			H4:                          h,
			S1:                          15,
			S2:                          15,
			S3:                          15,
			S4:                          15,
		},
	}

	newCfg := &models.VPNConfig{
		EnableMultiProtocolBackends: true,
		ListenPort:                  51820,
		H1:                          h,
		H2:                          h,
		H3:                          h,
		H4:                          h,
		S1:                          15,
		S2:                          15,
		S3:                          15,
		S4:                          15,
	}

	err := svc.UpdateConfig(context.Background(), newCfg)
	if err == nil || !strings.Contains(err.Error(), "enable_multi_protocol_backends") {
		t.Fatalf("expected rejection of live multi-protocol toggle, got: %v", err)
	}
}

func TestService_AttachBackendForwarder_Proxy(t *testing.T) {
	fw := forwarder.NewForwarder(nil, "10.100.0.0/16")
	svc := &Service{
		forwarder:      fw,
		backendDevices: make(map[int64]BackendDevice),
	}

	// 1. Attach VLESS backend
	vlessParams := models.VLESSRealityParams{
		UUID:        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		PublicKey:   "e-JgU2X7X8aH1pQ1pZqUuWbWw5K2s6J8f8gH9jK1lM4",
		ShortID:     "0123456789abcdef",
		ServerName:  "example.com",
		Fingerprint: "chrome",
	}
	vlessRaw, _ := json.Marshal(vlessParams)
	vlessTun := &models.BackendTunnel{
		ID:             1,
		ServerID:       10,
		Protocol:       models.ProtocolVLESS,
		Endpoint:       "127.0.0.1:443",
		ProtocolParams: vlessRaw,
	}

	if err := svc.attachBackendForwarder(vlessTun, nil); err != nil {
		t.Fatalf("attachBackendForwarder(VLESS) failed: %v", err)
	}

	dev := svc.backendDevices[vlessTun.ID]
	if dev == nil {
		t.Fatal("expected VLESS device to be attached")
	}
	if _, ok := dev.(*ProxyBackendDevice); !ok {
		t.Fatalf("expected *ProxyBackendDevice, got %T", dev)
	}

	// 2. Attach Naive backend
	naiveParams := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   "example.com",
		EnableH3: false,
	}
	naiveRaw, _ := json.Marshal(naiveParams)
	naiveTun := &models.BackendTunnel{
		ID:             2,
		ServerID:       20,
		Protocol:       models.ProtocolNaive,
		Endpoint:       "127.0.0.1:443",
		ProtocolParams: naiveRaw,
	}

	if err := svc.attachBackendForwarder(naiveTun, nil); err != nil {
		t.Fatalf("attachBackendForwarder(Naive) failed: %v", err)
	}

	devNaive := svc.backendDevices[naiveTun.ID]
	if devNaive == nil {
		t.Fatal("expected Naive device to be attached")
	}
	if _, ok := devNaive.(*ProxyBackendDevice); !ok {
		t.Fatalf("expected *ProxyBackendDevice, got %T", devNaive)
	}

	// Cleanup
	_ = dev.Close()
	_ = devNaive.Close()
}

func TestService_EnableBackendWithConfig_ProxyBootstrapResolvesProtocol(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	cfg := &models.VPNConfig{
		EnableMultiProtocolBackends: true,
		ListenPort:                  51820,
	}
	svc, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	t.Cleanup(func() {
		ts, _ := svc.GetTunnels(ctx)
		for _, tun := range ts {
			if d := svc.GetBackendDeviceForTest(tun.ID); d != nil {
				_ = d.Close()
			}
		}
	})

	naiveParams := models.NaiveProxyParams{
		Domain:   "example.com",
		Username: "fixture-user",
		Password: "fixture-password",
		EnableH3: false,
	}
	paramsRaw, _ := json.Marshal(naiveParams)

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "proxy-only-server",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"naive": map[string]any{
				"installed": true,
				"port":      443,
				"domain":    "example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// 1. Enabling with explicit options succeeds
	err = svc.EnableBackendWithConfig(ctx, sid, tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolNaive,
		ProtocolParams: paramsRaw,
	})
	if err != nil {
		t.Fatalf("EnableBackendWithConfig with explicit options failed: %v", err)
	}

	tun, err := svc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("expected tunnel for server %d, got tun=%+v err=%v", sid, tun, err)
	}
	if tun.Protocol != models.ProtocolNaive {
		t.Fatalf("expected protocol %q, got %q", models.ProtocolNaive, tun.Protocol)
	}

	// Clean up for next check
	_ = svc.DeleteBackend(ctx, sid)

	// 2. Enabling without options resolves protocol from server.Protocols (Finding R1)
	// and auto-provisions client credentials from standard installer metadata (no pre-existing params).
	err = svc.EnableBackendWithConfig(ctx, sid)
	if err != nil {
		t.Fatalf("EnableBackendWithConfig without options failed to resolve proxy protocol: %v", err)
	}

	tunAfter, err := svc.GetTunnel(sid)
	if err != nil || tunAfter == nil {
		t.Fatalf("expected tunnel for server %d, got tun=%+v err=%v", sid, tunAfter, err)
	}
	if tunAfter.Protocol != models.ProtocolNaive {
		t.Fatalf("expected resolved protocol %q, got %q", models.ProtocolNaive, tunAfter.Protocol)
	}
	var provisionedNaive models.NaiveProxyParams
	if err := json.Unmarshal(tunAfter.ProtocolParams, &provisionedNaive); err != nil {
		t.Fatalf("failed to decode provisioned naive params: %v", err)
	}
	if provisionedNaive.Username == "" || provisionedNaive.Password == "" || provisionedNaive.Domain == "" {
		t.Fatalf("expected complete provisioned naive params, got %+v", provisionedNaive)
	}
	dbTun, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || dbTun == nil || len(dbTun.ProtocolParams) == 0 {
		t.Fatalf("expected encrypted protocol params persisted in db for server %d, got %+v err=%v", sid, dbTun, err)
	}
}

func TestService_EnableBackendWithConfig_ProxyBootstrapResolvesProtocol_VLESS(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	cfg := &models.VPNConfig{
		EnableMultiProtocolBackends: true,
		ListenPort:                  51820,
	}
	svc, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	t.Cleanup(func() {
		ts, _ := svc.GetTunnels(ctx)
		for _, tun := range ts {
			if d := svc.GetBackendDeviceForTest(tun.ID); d != nil {
				_ = d.Close()
			}
		}
	})

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "vless-only-server",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"vless": map[string]any{
				"installed":   true,
				"port":        443,
				"server_name": "gateway.icloud.com",
				"flow":        "xtls-rprx-vision",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// Enabling without options resolves VLESS and auto-provisions client credentials from standard installer metadata.
	err = svc.EnableBackendWithConfig(ctx, sid)
	if err != nil {
		t.Fatalf("EnableBackendWithConfig without options failed to resolve VLESS protocol: %v", err)
	}

	tunAfter, err := svc.GetTunnel(sid)
	if err != nil || tunAfter == nil {
		t.Fatalf("expected tunnel for server %d, got tun=%+v err=%v", sid, tunAfter, err)
	}
	if tunAfter.Protocol != models.ProtocolVLESS {
		t.Fatalf("expected resolved protocol %q, got %q", models.ProtocolVLESS, tunAfter.Protocol)
	}
	var provisionedVLESS models.VLESSRealityParams
	if err := json.Unmarshal(tunAfter.ProtocolParams, &provisionedVLESS); err != nil {
		t.Fatalf("failed to decode provisioned vless params: %v", err)
	}
	if provisionedVLESS.UUID == "" || provisionedVLESS.PublicKey == "" || provisionedVLESS.ShortID == "" || provisionedVLESS.ServerName == "" {
		t.Fatalf("expected complete provisioned vless params, got %+v", provisionedVLESS)
	}
	dbTun, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || dbTun == nil || len(dbTun.ProtocolParams) == 0 {
		t.Fatalf("expected encrypted protocol params persisted in db for server %d, got %+v err=%v", sid, dbTun, err)
	}
}
