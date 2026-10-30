//go:build with_utls

package handlers

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/xray"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	vlessdialer "github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/vless"
	"github.com/go-chi/chi/v5"
)

func setupVLESSPipelineTestRouter(t *testing.T) (*chi.Mux, *Handlers, map[string][]byte) {
	t.Helper()
	h, db, _ := setupTestHandlers(t)
	cfg := &models.VPNConfig{
		EnableMultiProtocolBackends: true,
		ListenPort:                  51820,
	}
	svc, err := vpn.NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	h.vpnSvc = svc

	priv, _, err := xray.GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	doc, err := xray.RenderXrayConfig(443, 54321, "example.com", "example.com:443", priv, []string{"0123456789abcdef"}, nil)
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	files := map[string][]byte{xray.XrayConfigPath: doc}

	remote := &testMockSSHClient{
		cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
			switch {
			case strings.Contains(cmd, "docker --version"):
				return "Docker version 25.0.3", "", 0, nil
			case strings.HasPrefix(cmd, "cat "):
				return string(files[xray.XrayConfigPath]), "", 0, nil
			case strings.Contains(cmd, "docker inspect"):
				return "true false 123", "", 0, nil
			case strings.Contains(cmd, "xray version"):
				return "Xray 26.10.29", "", 0, nil
			default:
				return "OK", "", 0, nil
			}
		},
		downloadFn: func(ctx context.Context, path string) ([]byte, error) {
			return append([]byte(nil), files[path]...), nil
		},
		uploadFn: func(ctx context.Context, path string, b []byte) error {
			files[path] = append([]byte(nil), b...)
			return nil
		},
	}

	mgr := xray.NewXrayManagerWithServerLocks(&testMockSSHPool{client: remote}, awg.NewServerLockRegistry())
	h.registry.Register(mgr)

	router := chi.NewRouter()
	router.Post("/api/servers/{server_id}/install", h.InstallProtocolHandler)
	router.Post("/api/vpn/backends/{server_id}/enable", h.VPNEnableBackendHandler)

	return router, h, files
}

func postJSON(t *testing.T, router *chi.Mux, path, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "audit-admin",
		Role:   models.RoleAdmin,
	}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s HTTP %d: %s", path, rec.Code, rec.Body.String())
	}
}

func captureClientHelloGroups(t *testing.T, p models.VLESSRealityParams) []uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	out := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			out <- nil
			return
		}
		bodyLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(c, body); err != nil {
			out <- nil
			return
		}
		out <- body
	}()

	d, err := vlessdialer.New(ln.Addr().String(), p)
	if err != nil {
		t.Fatalf("vlessdialer.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, _ := d.DialContext(ctx, "tcp", "127.0.0.1:80")
	if conn != nil {
		_ = conn.Close()
	}

	var b []byte
	select {
	case b = <-out:
	case <-ctx.Done():
		t.Fatal("capture timeout")
	}

	if len(b) < 39 {
		t.Fatalf("truncated ClientHello: %d bytes", len(b))
	}
	// Skip record header, handshake header (4), version (2), random (32), sessionID
	i := 4 + 2 + 32
	i += 1 + int(b[i]) // skip session ID
	cipherSuitesLen := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2 + cipherSuitesLen
	compMethodsLen := int(b[i])
	i += 1 + compMethodsLen
	if i+2 > len(b) {
		t.Fatal("ClientHello missing extensions length")
	}
	extensionsEnd := i + 2 + int(binary.BigEndian.Uint16(b[i:i+2]))
	i += 2

	for i+4 <= extensionsEnd && i+4 <= len(b) {
		extType := binary.BigEndian.Uint16(b[i : i+2])
		extLen := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		i += 4
		if extType == 51 { // key_share extension
			var groups []uint16
			for k := i + 2; k+4 <= i+extLen; {
				g := binary.BigEndian.Uint16(b[k : k+2])
				size := int(binary.BigEndian.Uint16(b[k+2 : k+4]))
				groups = append(groups, g)
				k += 4 + size
			}
			return groups
		}
		i += extLen
	}
	t.Fatal("missing key_share extension in ClientHello")
	return nil
}

func containsGroup(groups []uint16, target uint16) bool {
	for _, g := range groups {
		if g == target {
			return true
		}
	}
	return false
}

func TestModernProfileHTTPToPersistedClientHello(t *testing.T) {
	ctx := context.Background()
	router, h, _ := setupVLESSPipelineTestRouter(t)

	id, err := h.db.CreateServer(ctx, &models.Server{
		Name:      "test-modern-pipeline",
		Host:      "127.0.0.1",
		SSHPort:   22,
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	postJSON(t, router, fmt.Sprintf("/api/servers/%d/install", id), `{"protocol":"vless","port":"443","engine_profile":"modern_pq"}`)

	server, err := h.db.GetServer(ctx, id)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	vlessMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok || vlessMeta["engine_profile"] != "modern_pq" {
		t.Fatalf("server vless metadata missing modern_pq profile: %#v", vlessMeta)
	}

	postJSON(t, router, fmt.Sprintf("/api/vpn/backends/%d/enable", id), "")

	backend, err := h.db.GetBackendTunnelByServerID(ctx, id)
	if err != nil || backend == nil {
		t.Fatalf("GetBackendTunnelByServerID: %v", err)
	}
	var params models.VLESSRealityParams
	if err := json.Unmarshal(backend.ProtocolParams, &params); err != nil {
		t.Fatalf("unmarshal backend protocol params: %v", err)
	}
	if params.EngineProfile != "modern_pq" {
		t.Fatalf("auto-enrolled backend params EngineProfile = %q, want modern_pq", params.EngineProfile)
	}

	groups := captureClientHelloGroups(t, params)
	if !containsGroup(groups, 4588) { // 4588 = X25519MLKEM768
		t.Fatalf("ClientHello missing hybrid X25519MLKEM768 (4588) key share: %v", groups)
	}
	if !containsGroup(groups, 29) { // 29 = X25519
		t.Fatalf("ClientHello missing classical X25519 (29) key share: %v", groups)
	}
}

func TestLegacyProfileHTTPToPersistedClientHello(t *testing.T) {
	ctx := context.Background()
	router, h, _ := setupVLESSPipelineTestRouter(t)

	id, err := h.db.CreateServer(ctx, &models.Server{
		Name:      "test-legacy-pipeline",
		Host:      "127.0.0.1",
		SSHPort:   22,
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	postJSON(t, router, fmt.Sprintf("/api/servers/%d/install", id), `{"protocol":"vless","port":"443","engine_profile":"legacy"}`)

	postJSON(t, router, fmt.Sprintf("/api/vpn/backends/%d/enable", id), "")

	backend, err := h.db.GetBackendTunnelByServerID(ctx, id)
	if err != nil || backend == nil {
		t.Fatalf("GetBackendTunnelByServerID: %v", err)
	}
	var params models.VLESSRealityParams
	if err := json.Unmarshal(backend.ProtocolParams, &params); err != nil {
		t.Fatalf("unmarshal backend protocol params: %v", err)
	}
	if params.EngineProfile != "legacy" {
		t.Fatalf("auto-enrolled backend params EngineProfile = %q, want legacy", params.EngineProfile)
	}

	groups := captureClientHelloGroups(t, params)
	if containsGroup(groups, 4588) {
		t.Fatalf("legacy ClientHello should NOT contain X25519MLKEM768 (4588): %v", groups)
	}
	if !containsGroup(groups, 29) {
		t.Fatalf("legacy ClientHello missing classical X25519 (29) key share: %v", groups)
	}
}

func TestProfileSwitch_KeepsBackendParamsConsistent(t *testing.T) {
	ctx := context.Background()
	router, h, _ := setupVLESSPipelineTestRouter(t)

	id, err := h.db.CreateServer(ctx, &models.Server{
		Name:      "test-switch-pipeline",
		Host:      "127.0.0.1",
		SSHPort:   22,
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	// 1. Initial install modern_pq
	postJSON(t, router, fmt.Sprintf("/api/servers/%d/install", id), `{"protocol":"vless","port":"443","engine_profile":"modern_pq"}`)
	postJSON(t, router, fmt.Sprintf("/api/vpn/backends/%d/enable", id), "")

	b1, err := h.db.GetBackendTunnelByServerID(ctx, id)
	if err != nil || b1 == nil {
		t.Fatalf("backend lookup 1: %v", err)
	}
	var p1 models.VLESSRealityParams
	if err := json.Unmarshal(b1.ProtocolParams, &p1); err != nil {
		t.Fatalf("unmarshal p1: %v", err)
	}
	if p1.EngineProfile != "modern_pq" {
		t.Fatalf("expected modern_pq initially, got %q", p1.EngineProfile)
	}

	// 2. Switch server profile to legacy
	postJSON(t, router, fmt.Sprintf("/api/servers/%d/install", id), `{"protocol":"vless","port":"443","engine_profile":"legacy"}`)

	// 3. Re-enable backend
	postJSON(t, router, fmt.Sprintf("/api/vpn/backends/%d/enable", id), "")

	b2, err := h.db.GetBackendTunnelByServerID(ctx, id)
	if err != nil || b2 == nil {
		t.Fatalf("backend lookup 2: %v", err)
	}
	var p2 models.VLESSRealityParams
	if err := json.Unmarshal(b2.ProtocolParams, &p2); err != nil {
		t.Fatalf("unmarshal p2: %v", err)
	}
	if p2.EngineProfile != "legacy" {
		t.Fatalf("re-enabled backend params EngineProfile = %q, want legacy", p2.EngineProfile)
	}
	groups2 := captureClientHelloGroups(t, p2)
	if containsGroup(groups2, 4588) {
		t.Fatalf("switched legacy ClientHello should NOT contain 4588: %v", groups2)
	}
	if !containsGroup(groups2, 29) {
		t.Fatalf("switched legacy ClientHello missing X25519: %v", groups2)
	}
}
