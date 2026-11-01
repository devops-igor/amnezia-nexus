package vpn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/net/http2"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/naive"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/streambridge"
)

const e2eCamouflageDomain = "camouflage.e2e.example.com"

type e2eFlushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *e2eFlushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return
}

func (fw *e2eFlushWriter) Close() error {
	if c, ok := fw.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func setupE2ETestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Nexus E2E Test CA"},
			CommonName:   "Nexus E2E Root CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)
	naive.SetTestRootCAs(rootPool)
	t.Cleanup(func() {
		naive.SetTestRootCAs(nil)
	})

	return caCert, priv
}

func setupE2ETestH2Server(t *testing.T, listenAddr, authUser, authPass string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, echoAddr string) (string, func()) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: e2eCamouflageDomain,
		},
		DNSNames:              []string{e2eCamouflageDomain, "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		t.Fatalf("listen h2 tls on %s: %v", listenAddr, err)
	}

	expectedAuth := base64.StdEncoding.EncodeToString([]byte(authUser + ":" + authPass))

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}
			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader != "Basic "+expectedAuth {
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			if r.Host == net.JoinHostPort(e2eCamouflageDomain, "443") {
				w.WriteHeader(http.StatusOK)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				return
			}

			targetAddr := r.Host
			if echoAddr != "" {
				targetAddr = echoAddr
			}
			targetConn, err := net.DialTimeout("tcp", targetAddr, 3*time.Second)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			defer targetConn.Close()

			go func() {
				<-r.Context().Done()
				_ = targetConn.Close()
			}()

			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			if flusher != nil {
				flusher.Flush()
			}

			errc := make(chan error, 2)
			go func() {
				_, err := io.Copy(targetConn, r.Body)
				if tc, ok := targetConn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				errc <- err
			}()
			fw := &e2eFlushWriter{w: w, f: flusher}
			go func() {
				_, err := io.Copy(fw, targetConn)
				errc <- err
			}()
			<-errc
			_ = targetConn.Close()
			_ = fw.Close()
		}),
	}
	//nolint:staticcheck // SA1019: http2.ConfigureServer test fixture helper
	_ = http2.ConfigureServer(server, &http2.Server{})

	go func() {
		_ = server.Serve(ln)
	}()

	cleanup := func() {
		_ = server.Close()
		_ = ln.Close()
	}

	return ln.Addr().String(), cleanup
}

func setupE2ETestEchoServer(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	cleanup := func() {
		cancel()
		_ = ln.Close()
	}
	return port, cleanup
}

// TestE2E_AWG_To_IPv6_Naive_Backend_And_Failover exercises the complete end-to-end data path:
// 1. Real AWG UDP listener handling simulated AWG client handshake and encrypted packet ingress.
// 2. Streambridge forwarding to an LB-selected IPv6 Naive H2 backend.
// 3. IPv4 response returning through the tunnel to the AWG client.
// 4. Health check failover after IPv6 connectivity is dropped.
func TestE2E_AWG_To_IPv6_Naive_Backend_And_Failover(t *testing.T) {
	ctx := t.Context()

	// 1. TCP Echo Server on IPv4 loopback
	echoPort, cleanupEcho := setupE2ETestEchoServer(t)
	defer cleanupEcho()
	echoAddr := fmt.Sprintf("127.0.0.1:%d", echoPort)
	echoTarget := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.99"), uint16(echoPort))

	// 2. Certificate authority for Naive H2 TLS
	caCert, caKey := setupE2ETestCA(t)

	// 3. IPv6 Naive H2 backend listening on [::1]:port
	proxyAddrIPv6, cleanupIPv6 := setupE2ETestH2Server(t, "[::1]:0", "user-ipv6", "pass-ipv6", caCert, caKey, echoAddr)
	defer cleanupIPv6()

	// 4. IPv4 Naive H2 backend listening on 127.0.0.1:port
	proxyAddrIPv4, cleanupIPv4 := setupE2ETestH2Server(t, "127.0.0.1:0", "user-ipv4", "pass-ipv4", caCert, caKey, echoAddr)
	defer cleanupIPv4()

	// 5. Build test VPN service with real UDP portal listener
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db, func(cfg *models.VPNConfig) {
		cfg.EnableMultiProtocolBackends = true
	})
	svc.pool.SetMultiProtocolEnabled(true)

	// Deactivate default AWG test tunnels so only Naive backends are active
	for _, tun := range svc.pool.ListTunnels() {
		_ = svc.pool.SetTunnelEnabled(ctx, tun.ServerID, false, models.DisableReasonAdmin)
	}

	// Create Server 1 (IPv6)
	srv1ID, err := db.CreateServer(ctx, &models.Server{
		Name:      "e2e-srv-naive-ipv6",
		Host:      "::1",
		Protocols: map[string]any{"naive": map[string]any{"installed": true}},
	})
	if err != nil {
		t.Fatalf("create server 1: %v", err)
	}

	// Create Server 2 (IPv4)
	srv2ID, err := db.CreateServer(ctx, &models.Server{
		Name:      "e2e-srv-naive-ipv4",
		Host:      "127.0.0.1",
		Protocols: map[string]any{"naive": map[string]any{"installed": true}},
	})
	if err != nil {
		t.Fatalf("create server 2: %v", err)
	}

	pIPv6 := models.NaiveProxyParams{
		Username: "user-ipv6",
		Password: "pass-ipv6",
		Domain:   e2eCamouflageDomain,
		EnableH3: false,
	}
	pBytesIPv6, _ := json.Marshal(pIPv6)

	pIPv4 := models.NaiveProxyParams{
		Username: "user-ipv4",
		Password: "pass-ipv4",
		Domain:   e2eCamouflageDomain,
		EnableH3: false,
	}
	pBytesIPv4, _ := json.Marshal(pIPv4)

	// Create Tunnel 1 (IPv6)
	tun1 := &models.BackendTunnel{
		ServerID:       srv1ID,
		InterfaceName:  "naive-be-ipv6",
		Protocol:       models.ProtocolNaive,
		Endpoint:       proxyAddrIPv6,
		Status:         models.TunnelStatusActive,
		Enabled:        true,
		ProtocolParams: pBytesIPv6,
	}
	tun1ID, err := db.CreateBackendTunnel(ctx, tun1)
	if err != nil {
		t.Fatalf("create backend tunnel 1: %v", err)
	}
	tun1.ID = tun1ID

	// Create Tunnel 2 (IPv4)
	tun2 := &models.BackendTunnel{
		ServerID:       srv2ID,
		InterfaceName:  "naive-be-ipv4",
		Protocol:       models.ProtocolNaive,
		Endpoint:       proxyAddrIPv4,
		Status:         models.TunnelStatusActive,
		Enabled:        true,
		ProtocolParams: pBytesIPv4,
	}
	tun2ID, err := db.CreateBackendTunnel(ctx, tun2)
	if err != nil {
		t.Fatalf("create backend tunnel 2: %v", err)
	}
	tun2.ID = tun2ID

	// Construct Naive dialers and streambridge devices for both backends
	dIPv6, err := naive.New(tun1.Endpoint, pIPv6)
	if err != nil {
		t.Fatalf("naive.New IPv6: %v", err)
	}
	bridgeIPv6, err := streambridge.New(streambridge.Config{MTU: 1280}, dIPv6)
	if err != nil {
		t.Fatalf("streambridge.New IPv6: %v", err)
	}
	devIPv6 := NewProxyBackendDevice(bridgeIPv6, dIPv6)
	svc.forwarder.AttachBackendDevice(tun1.ID, devIPv6)
	go svc.pumpBackendReturns(tun1.ID, srv1ID, devIPv6)

	dIPv4, err := naive.New(tun2.Endpoint, pIPv4)
	if err != nil {
		t.Fatalf("naive.New IPv4: %v", err)
	}
	bridgeIPv4, err := streambridge.New(streambridge.Config{MTU: 1280}, dIPv4)
	if err != nil {
		t.Fatalf("streambridge.New IPv4: %v", err)
	}
	devIPv4 := NewProxyBackendDevice(bridgeIPv4, dIPv4)
	svc.forwarder.AttachBackendDevice(tun2.ID, devIPv4)
	go svc.pumpBackendReturns(tun2.ID, srv2ID, devIPv4)

	// Sync pool and start forwarder pumps
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("pool.SyncFromDB: %v", err)
	}
	svc.forwarder.StartPumps(ctx)
	t.Cleanup(svc.forwarder.StopPumps)

	// 6. Enroll AWG client peer
	peer, savedConfig := newEnginePeer(t, svc, db, "awg-e2e-user")

	// Assign initial sticky affinity to IPv6 tunnel
	svc.stickyMgr.AssignPeerAffinity(peer.publicKey, tun1.ID)

	// 7. Start production IngressEngine (portal with real localhost UDP listener)
	engine, err := svc.NewIngressEngine(ctx, "e2e-awg-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(netip.MustParseAddr(peer.assignedIP), 32)},
	})
	if err != nil {
		t.Fatalf("NewIngressEngine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	if err := engine.Start(); err != nil {
		t.Fatalf("engine.Start: %v", err)
	}

	// 8. Start real upstream AWG client engine with netstack
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(peer.assignedIP)}, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	clientDev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "e2e-awg-client"))
	t.Cleanup(clientDev.Close)
	if err := clientDev.IpcSet(configToUAPI(t, savedConfig)); err != nil {
		t.Fatalf("IpcSet client config: %v", err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatalf("clientDev.Up: %v", err)
	}

	// 9. Full Path 1: Client -> Real AWG UDP Ingress -> Streambridge -> LB Selection -> IPv6 Naive -> IPv4 Echo -> Client
	dialCtx1, cancel1 := context.WithTimeout(ctx, 15*time.Second)
	defer cancel1()

	conn1, err := stack.DialContextTCPAddrPort(dialCtx1, echoTarget)
	if err != nil {
		pStatus, pErr := engine.Portal().Status()
		t.Logf("Portal Status: %+v (err=%v)", pStatus, pErr)
		qFull, noRoute, total := svc.forwarder.DropStats()
		t.Logf("Forwarder DropStats: qFull=%d noRoute=%d total=%d", qFull, noRoute, total)
		t.Logf("Router Stats: %+v", engine.Router().StatsSnapshot())
		t.Logf("BridgeIPv6 FlowStats: %+v", bridgeIPv6.FlowStats())
		sess, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
		t.Logf("Session: ok=%v %+v", ok, sess)
		t.Fatalf("DialContextTCPAddrPort over IPv6 Naive backend failed: %v", err)
	}
	defer conn1.Close()

	payload1 := []byte("hello-real-awg-ipv6-naive-e2e-qualification-roundtrip")
	if _, err := conn1.Write(payload1); err != nil {
		t.Fatalf("conn1.Write: %v", err)
	}

	recv1 := make([]byte, len(payload1))
	if _, err := io.ReadFull(conn1, recv1); err != nil {
		t.Fatalf("conn1 ReadFull: %v", err)
	}
	if !bytes.Equal(payload1, recv1) {
		t.Fatalf("payload mismatch over IPv6 Naive: got %q, want %q", recv1, payload1)
	}

	// Verify session snapshot routes to IPv6 backend
	sess1, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
	if !ok || sess1.BackendTunnelID != tun1.ID {
		t.Fatalf("expected session to route to IPv6 backend %d, got ok=%v sess=%+v", tun1.ID, ok, sess1)
	}

	_ = conn1.Close()

	// 10. Health check failover: drop IPv6 connectivity and disable backend
	cleanupIPv6()
	if err := svc.DisableBackend(ctx, srv1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	// Verify sticky affinity migrated to IPv4 Naive backend
	aff, ok := svc.stickyMgr.GetPeerAffinity(peer.publicKey)
	if !ok || aff != tun2.ID {
		t.Fatalf("expected affinity migrated to IPv4 backend %d, got %d (ok=%v)", tun2.ID, aff, ok)
	}

	// 11. Full Path 2: Subsequent connection after failover routes to alternate healthy IPv4 Naive backend
	dialCtx2, cancel2 := context.WithTimeout(ctx, 15*time.Second)
	defer cancel2()

	conn2, err := stack.DialContextTCPAddrPort(dialCtx2, echoTarget)
	if err != nil {
		t.Fatalf("DialContextTCPAddrPort after failover to IPv4 backend failed: %v", err)
	}
	defer conn2.Close()

	payload2 := []byte("hello-failover-healthy-ipv4-naive-e2e-verified")
	if _, err := conn2.Write(payload2); err != nil {
		t.Fatalf("conn2.Write: %v", err)
	}

	recv2 := make([]byte, len(payload2))
	if _, err := io.ReadFull(conn2, recv2); err != nil {
		t.Fatalf("conn2 ReadFull: %v", err)
	}
	if !bytes.Equal(payload2, recv2) {
		t.Fatalf("failover payload mismatch: got %q, want %q", recv2, payload2)
	}

	// Verify both backends handled their respective flows
	if statsIPv6 := bridgeIPv6.FlowStats(); statsIPv6.Total != 1 {
		t.Errorf("expected 1 flow on IPv6 bridge, got %d", statsIPv6.Total)
	}
	if statsIPv4 := bridgeIPv4.FlowStats(); statsIPv4.Total != 1 {
		t.Errorf("expected 1 flow on IPv4 bridge after failover, got %d", statsIPv4.Total)
	}
}
