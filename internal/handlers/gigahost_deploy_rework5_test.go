package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func rework5Keypair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(key, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return key, pub
}

func rework5HandshakeOnlyServer(t *testing.T, h1, h2 uint32, s1, s2 int, onPacket ...func([]byte)) (net.PacketConn, []byte, string, int) {
	serverPriv, serverPub := rework5Keypair(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}

	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)

	done := make(chan struct{})
	t.Cleanup(func() {
		_ = pc.Close()
		<-done
	})

	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, clientAddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if len(onPacket) > 0 && onPacket[0] != nil {
				pktCopy := make([]byte, n)
				copy(pktCopy, buf[:n])
				onPacket[0](pktCopy)
			}
			if n < s1+116 {
				continue
			}

			msgBody := buf[s1 : s1+116]
			msgType := binary.LittleEndian.Uint32(msgBody[0:4])
			if msgType != h1 {
				continue
			}
			senderIdx := binary.LittleEndian.Uint32(msgBody[4:8])
			clientEPub := msgBody[8:40]
			encryptedStatic := msgBody[40:88]
			encryptedTimestamp := msgBody[88:116]

			serverHSum := blake2s.Sum256(append(health.InitialHash[:], serverPub...))
			serverH := serverHSum[:]
			serverCK := health.InitialChainKey[:]

			serverHSum = blake2s.Sum256(append(serverH, clientEPub...))
			serverH = serverHSum[:]
			serverCK = health.KDF1(serverCK, clientEPub)

			serverSS1, _ := curve25519.X25519(serverPriv, clientEPub)
			var serverKey1 []byte
			serverCK, serverKey1 = health.KDF2(serverCK, serverSS1)

			serverAead1, _ := chacha20poly1305.New(serverKey1)
			nonce0 := make([]byte, 12)
			clientStaticPub, _ := serverAead1.Open(nil, nonce0, encryptedStatic, serverH)
			serverHSum = blake2s.Sum256(append(serverH, encryptedStatic...))
			serverH = serverHSum[:]

			serverSS2, _ := curve25519.X25519(serverPriv, clientStaticPub)
			var serverKey2 []byte
			serverCK, serverKey2 = health.KDF2(serverCK, serverSS2)

			serverAead2, _ := chacha20poly1305.New(serverKey2)
			_, _ = serverAead2.Open(nil, nonce0, encryptedTimestamp, serverH)
			serverHSum = blake2s.Sum256(append(serverH, encryptedTimestamp...))
			serverH = serverHSum[:]

			serverEPriv, serverEPub := rework5Keypair(t)
			serverHSum = blake2s.Sum256(append(serverH, serverEPub...))
			serverH = serverHSum[:]
			serverCK = health.KDF1(serverCK, serverEPub)

			serverSS3, _ := curve25519.X25519(serverEPriv, clientEPub)
			serverCK = health.KDF1(serverCK, serverSS3)

			serverSS4, _ := curve25519.X25519(serverEPriv, clientStaticPub)
			serverCK = health.KDF1(serverCK, serverSS4)

			var serverTau, serverKey3 []byte
			_, serverTau, serverKey3 = health.KDF3(serverCK, make([]byte, 32))
			serverHSum = blake2s.Sum256(append(serverH, serverTau...))
			serverH = serverHSum[:]

			serverAead3, _ := chacha20poly1305.New(serverKey3)
			encryptedEmpty := serverAead3.Seal(nil, nonce0, []byte{}, serverH)

			respMsgType := make([]byte, 4)
			binary.LittleEndian.PutUint32(respMsgType, h2)
			serverSenderIdx := make([]byte, 4)
			binary.LittleEndian.PutUint32(serverSenderIdx, 12345)
			respReceiverIdx := make([]byte, 4)
			binary.LittleEndian.PutUint32(respReceiverIdx, senderIdx)

			var respMsgBody []byte
			respMsgBody = append(respMsgBody, respMsgType...)
			respMsgBody = append(respMsgBody, serverSenderIdx...)
			respMsgBody = append(respMsgBody, respReceiverIdx...)
			respMsgBody = append(respMsgBody, serverEPub...)
			respMsgBody = append(respMsgBody, encryptedEmpty...)

			mac1KeySum := blake2s.Sum256(append(health.LabelMAC1, clientStaticPub...))
			hMac1, _ := blake2s.New128(mac1KeySum[:])
			hMac1.Write(respMsgBody)
			respMac1 := hMac1.Sum(nil)
			respMac2 := make([]byte, 16)

			var respPacket []byte
			if s2 > 0 {
				pad := make([]byte, s2)
				_, _ = rand.Read(pad)
				respPacket = append(respPacket, pad...)
			}
			respPacket = append(respPacket, respMsgBody...)
			respPacket = append(respPacket, respMac1...)
			respPacket = append(respPacket, respMac2...)

			_, _ = pc.WriteTo(respPacket, clientAddr)
		}
	}()

	return pc, serverPub, host, port
}

// TestRework5_HandshakeOnlyFailsTrafficQualification tests Finding F8:
// An AWG backend that passes outer handshake but cannot pass data-plane payload forwarding
// MUST NOT enter the healthy pool as ready/active. It must fail closed with HTTP 502,
// status failed, and be excluded from FilterHealthy.
func TestRework5_HandshakeOnlyFailsTrafficQualification(t *testing.T) {
	h, r, provider := setupDeployTestEnv(t)
	var packets atomic.Int32
	_, pub, host, port := rework5HandshakeOnlyServer(t, health.DefaultH1, health.DefaultH2, health.DefaultS1, health.DefaultS2, func([]byte) {
		packets.Add(1)
	})

	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			ServerID:   2001,
			Status:     gigahost.StatusReady,
			AssignedIP: host,
		}, nil
	}

	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolAWG,
		installFn: func(_ context.Context, s *models.Server, _ map[string]any) error {
			s.Protocols["awg"] = map[string]any{
				"port":       strconv.Itoa(port),
				"public_key": base64.StdEncoding.EncodeToString(pub),
				"awg_params": map[string]any{
					"H1": strconv.FormatUint(uint64(health.DefaultH1), 10),
					"H2": strconv.FormatUint(uint64(health.DefaultH2), 10),
					"S1": strconv.Itoa(health.DefaultS1),
					"S2": strconv.Itoa(health.DefaultS2),
				},
			}
			return nil
		},
	})

	h.vpnSvc.SetProbeFunc(health.ProbeAWGEndpointRange)

	req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/rework5-handshake-only/setup", strings.NewReader(`{"ssh_password":"fixture-only"}`))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	backends, err := h.vpnSvc.GetBackends(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	eligible := len(loadbalancer.FilterHealthy(backends, 0))

	t.Logf("packets=%d eligible=%d HTTP=%d body=%s", packets.Load(), eligible, w.Code, w.Body.String())

	if packets.Load() == 0 {
		t.Fatal("expected outer Noise handshake to be exercised")
	}
	if w.Code != 502 {
		t.Fatalf("expected HTTP 502 Bad Gateway on data-plane failure, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), `"status":"ready"`) {
		t.Fatal("handshake-only responder admitted as ready without data plane forwarding")
	}
	if !strings.Contains(w.Body.String(), "data-plane payload verification failed") {
		t.Fatalf("expected clear diagnostics mentioning data-plane payload verification failed, got: %s", w.Body.String())
	}
	if eligible != 0 {
		t.Fatalf("expected 0 healthy backends after data-plane failure, got %d", eligible)
	}

	// Verify deploy record in DB transitioned to failed
	status, err := h.GetGigahostDeployStatus(context.Background(), "rework5-handshake-only")
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != DeployStatusFailed {
		t.Fatalf("expected deploy status failed in database, got %s", status.Status)
	}
	if !strings.Contains(status.Error, "data-plane payload verification failed") {
		t.Fatalf("expected database error to contain data-plane failure diagnostics, got: %s", status.Error)
	}
}

// TestRework5_CanaryProbeCustomErrorDiagnostics tests that custom data-plane errors
// propagate with exact diagnostics and keep the backend disabled and excluded.
func TestRework5_CanaryProbeCustomErrorDiagnostics(t *testing.T) {
	h, r, provider := setupDeployTestEnv(t)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			ServerID:   2002,
			Status:     gigahost.StatusReady,
			AssignedIP: "198.51.100.30",
		}, nil
	}

	// Outer probe succeeds
	h.vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	})
	// Inner canary probe fails with custom diagnostic error
	h.vpnSvc.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		return errors.New("packet transit dropped by remote firewall")
	})

	req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/rework5-custom-fail/setup", strings.NewReader(`{"ssh_password":"fixture-only"}`))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 502 {
		t.Fatalf("expected HTTP 502, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "data-plane payload verification failed: packet transit dropped by remote firewall") {
		t.Fatalf("expected diagnostics to propagate custom error, got: %s", w.Body.String())
	}

	backends, err := h.vpnSvc.GetBackends(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(loadbalancer.FilterHealthy(backends, 0)) != 0 {
		t.Fatal("expected 0 healthy backends on canary failure")
	}
}

// TestRework5_PositiveQualification_HandshakeAndDataPlaneSuccess verifies the positive path:
// when outer handshake AND data-plane payload forwarding both succeed, the backend is admitted as ready
// and enters the healthy pool.
func TestRework5_PositiveQualification_HandshakeAndDataPlaneSuccess(t *testing.T) {
	h, r, provider := setupDeployTestEnv(t)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			ServerID:   2003,
			Status:     gigahost.StatusReady,
			AssignedIP: "198.51.100.40",
		}, nil
	}

	outerProbed := false
	h.vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		outerProbed = true
		return 12 * time.Millisecond, nil
	})
	canaryProbed := false
	h.vpnSvc.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		canaryProbed = true
		return nil
	})

	req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/rework5-positive/setup", strings.NewReader(`{"ssh_password":"fixture-only"}`))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected HTTP 200 on positive qualification, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
		Deploy struct {
			Status string `json:"status"`
		} `json:"deploy"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" || resp.Deploy.Status != "ready" {
		t.Fatalf("expected status ok / deploy ready, got %+v", resp)
	}
	if !outerProbed {
		t.Fatal("expected outer handshake probe to run")
	}
	if !canaryProbed {
		t.Fatal("expected canary data-plane probe to run")
	}

	backends, err := h.vpnSvc.GetBackends(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(loadbalancer.FilterHealthy(backends, 0)) != 1 {
		t.Fatalf("expected exactly 1 healthy backend after positive qualification, got %d", len(loadbalancer.FilterHealthy(backends, 0)))
	}
}
