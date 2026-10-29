package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/go-chi/chi/v5"
)

func TestVPNEnableBackendHandler_ProxyBootstrap(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	vpnCfg := &models.VPNConfig{
		EnableMultiProtocolBackends: true,
		ListenPort:                  51820,
	}
	vpnSvc, err := vpn.NewVPNService(db, vpnCfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	t.Cleanup(func() {
		ts, _ := vpnSvc.GetTunnels(ctx)
		for _, tun := range ts {
			if d := vpnSvc.GetBackendDeviceForTest(tun.ID); d != nil {
				_ = d.Close()
			}
		}
	})
	h.vpnSvc = vpnSvc

	r := chi.NewRouter()
	r.Post("/api/vpn/backends/{server_id}/enable", h.VPNEnableBackendHandler)

	naiveParams := models.NaiveProxyParams{
		Domain:   "example.com",
		Username: "user1",
		Password: "pass1",
		EnableH3: false,
	}
	paramsRaw, _ := json.Marshal(naiveParams)

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "proxy-node-http",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"naive": map[string]any{
				"installed": true,
				"port":      443,
				"params":    naiveParams,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// 1. Enable with JSON body specifying protocol and protocol_params (Finding R1)
	body, _ := json.Marshal(map[string]any{
		"protocol":        "naive",
		"protocol_params": json.RawMessage(paramsRaw),
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with proxy body, got %d: %s", w.Code, w.Body.String())
	}

	tun, err := vpnSvc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("expected tunnel for server %d, got %+v err=%v", sid, tun, err)
	}
	if tun.Protocol != models.ProtocolNaive {
		t.Fatalf("expected protocol %q, got %q", models.ProtocolNaive, tun.Protocol)
	}

	// Clean up for omitted options check
	_ = vpnSvc.DeleteBackend(ctx, sid)

	// 2. Enable without body resolves installed proxy from server.Protocols (Finding R1)
	reqEmpty := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), nil)
	wEmpty := httptest.NewRecorder()
	r.ServeHTTP(wEmpty, reqEmpty)

	if wEmpty.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with omitted body, got %d: %s", wEmpty.Code, wEmpty.Body.String())
	}

	tunAfter, err := vpnSvc.GetTunnel(sid)
	if err != nil || tunAfter == nil {
		t.Fatalf("expected tunnel for server %d, got %+v err=%v", sid, tunAfter, err)
	}
	if tunAfter.Protocol != models.ProtocolNaive {
		t.Fatalf("expected resolved protocol %q, got %q", models.ProtocolNaive, tunAfter.Protocol)
	}
}
