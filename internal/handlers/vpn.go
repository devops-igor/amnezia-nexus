package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn"
)

// VPNStatusHandler returns operational metrics for the VPN subsystem.
func (h *Handlers) VPNStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var status *vpn.Status
	var err error

	if h.vpnSvc != nil {
		status, err = h.vpnSvc.GetStatus(ctx)
	}

	if err != nil || status == nil {
		status = &vpn.Status{
			ListenerRunning:   false,
			ActiveTunnels:     0,
			ConnectedSessions: 0,
		}
	}

	h.JSON(w, http.StatusOK, status)
}

// VPNBackendsHandler returns all configured VPN backend tunnels.
func (h *Handlers) VPNBackendsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var backends []*models.BackendTunnel

	if h.vpnSvc != nil {
		backends, _ = h.vpnSvc.GetBackends(ctx)
	}
	if backends == nil {
		backends = make([]*models.BackendTunnel, 0)
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"backends": backends,
	})
}

// VPNEnableBackendHandler activates a backend server for load balancing.
func (h *Handlers) VPNEnableBackendHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	ctx := r.Context()
	if h.vpnSvc != nil {
		if err := h.vpnSvc.EnableBackend(ctx, serverID); err != nil {
			if errors.Is(err, vpn.ErrAWGNotInstalled) {
				h.JSONError(w, http.StatusBadRequest, "awg_not_installed", "Server does not have AmneziaWG installed or configured")
				return
			}
			if errors.Is(err, vpn.ErrServerNotFound) {
				h.JSONError(w, http.StatusNotFound, "server_not_found", fmt.Sprintf("Server %d not found", serverID))
				return
			}
			// #nosec G706 -- Internal server audit log for failed backend enable
			log.Printf("[vpn/handlers] failed to enable backend %d: %v", serverID, err)
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to enable backend")
			return
		}
	}

	h.audit(r, "vpn.backend_enable", map[string]any{"server_id": serverID})
	h.JSONOK(w)
}

// VPNDisableBackendHandler deactivates a backend server and initiates peer draining.
func (h *Handlers) VPNDisableBackendHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	ctx := r.Context()
	if h.vpnSvc != nil {
		if err := h.vpnSvc.DisableBackend(ctx, serverID); err != nil {
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to disable backend: "+err.Error())
			return
		}
	}

	h.audit(r, "vpn.backend_disable", map[string]any{"server_id": serverID})
	h.JSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"draining": true,
	})
}

// VPNTunnelsHandler returns all active VPN tunnels (alias for backends).
func (h *Handlers) VPNTunnelsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var tunnels []*models.BackendTunnel

	if h.vpnSvc != nil {
		tunnels, _ = h.vpnSvc.GetTunnels(ctx)
	}
	if tunnels == nil {
		tunnels = make([]*models.BackendTunnel, 0)
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"tunnels": tunnels,
	})
}

// VPNGetConfigHandler returns dynamic routing and load balancer configuration.
func (h *Handlers) VPNGetConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var cfg *models.VPNConfig
	var err error

	if h.vpnSvc != nil {
		cfg, err = h.vpnSvc.GetConfig(ctx)
	}
	if err != nil || cfg == nil {
		cfg = &models.VPNConfig{
			Algorithm:          models.LBLeastConnections,
			HealthThresholdMS:  500,
			ListenPort:         51820,
			SubnetCIDR:         "10.100.0.0/16",
			MaxTotalPeers:      1000,
			MaxPeersPerBackend: 250,
			Weights:            make(map[int64]int),
		}
	}

	h.JSON(w, http.StatusOK, cfg)
}

func mergeVPNConfig(current *models.VPNConfig, cfg *models.VPNConfig, hasPublicEndpoint bool) {
	if current == nil || cfg == nil {
		return
	}
	if cfg.H1.IsZero() && cfg.S1 == 0 {
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = current.H1, current.H2, current.H3, current.H4
		cfg.S1, cfg.S2, cfg.S3, cfg.S4 = current.S1, current.S2, current.S3, current.S4
		cfg.ServerPrivateKey = current.ServerPrivateKey
		cfg.ServerPublicKey = current.ServerPublicKey
	}
	if !hasPublicEndpoint {
		cfg.PublicEndpoint = current.PublicEndpoint
	}
	if cfg.Algorithm == "" {
		cfg.Algorithm = current.Algorithm
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = current.ListenPort
	}
	if cfg.SubnetCIDR == "" {
		cfg.SubnetCIDR = current.SubnetCIDR
	}
	if cfg.MaxTotalPeers == 0 {
		cfg.MaxTotalPeers = current.MaxTotalPeers
	}
	if cfg.MaxPeersPerBackend == 0 {
		cfg.MaxPeersPerBackend = current.MaxPeersPerBackend
	}
	if cfg.Weights == nil {
		cfg.Weights = current.Weights
	}
	if cfg.HealthThresholdMS == 0 {
		cfg.HealthThresholdMS = current.HealthThresholdMS
	}
	if cfg.HeaderProtectionKey == "" {
		cfg.HeaderProtectionKey = current.HeaderProtectionKey
	}
	if cfg.ContentPaddingAddition == "" {
		cfg.ContentPaddingAddition = current.ContentPaddingAddition
	}
}

// VPNUpdateConfigHandler applies new routing policy and rebalances existing pools.
func (h *Handlers) VPNUpdateConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Request body is empty")
		return
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil || len(bodyBytes) == 0 {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}
	defer r.Body.Close()

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	var cfg models.VPNConfig
	if err := json.Unmarshal(bodyBytes, &cfg); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	_, hasPublicEndpoint := raw["public_endpoint"]

	ctx := r.Context()
	if h.vpnSvc != nil {
		if current, err := h.vpnSvc.GetConfig(ctx); err == nil && current != nil {
			mergeVPNConfig(current, &cfg, hasPublicEndpoint)
		}
		if err := h.vpnSvc.UpdateConfig(ctx, &cfg); err != nil {
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update VPN configuration")
			return
		}
	} else if h.db != nil {
		if current, err := h.db.GetVPNConfig(ctx); err == nil && current != nil {
			mergeVPNConfig(current, &cfg, hasPublicEndpoint)
		}
		_ = h.db.SaveVPNConfig(ctx, &cfg)
	}

	h.audit(r, "vpn.config_update", map[string]any{"algorithm": string(cfg.Algorithm), "listen_port": cfg.ListenPort, "public_endpoint": cfg.PublicEndpoint})
	h.JSONOK(w)
}

// VPNMyConnectionHandler returns real-time VPN connection state for the session user.
func (h *Handlers) VPNMyConnectionHandler(w http.ResponseWriter, r *http.Request) {
	sess := h.GetSession(r)
	if sess == nil || !sess.IsAuthenticated() {
		h.JSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	ctx := r.Context()
	var state *vpn.UserVPNState
	if h.vpnSvc != nil {
		state, _ = h.vpnSvc.GetUserConnectionState(ctx, sess.UserID)
	}
	if state == nil {
		state = &vpn.UserVPNState{Connected: false}
	}

	h.JSON(w, http.StatusOK, state)
}

// VPNMyConfigHandler generates a portal VPN configuration file for the session user.
func (h *Handlers) VPNMyConfigHandler(w http.ResponseWriter, r *http.Request) {
	sess := h.GetSession(r)
	if sess == nil || !sess.IsAuthenticated() {
		h.JSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	ctx := r.Context()
	configStr, filename, err := "", "portal-awg.conf", error(nil)
	if h.vpnSvc != nil {
		configStr, filename, err = h.vpnSvc.GenerateClientConfig(ctx, sess.UserID)
	} else {
		configStr = "[Interface]\n# VPN subsystem offline\n"
	}

	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to generate VPN configuration")
		return
	}

	vpnLink := GenerateVPNLink(configStr)
	h.JSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"config":   configStr,
		"filename": filename,
		"vpn_link": vpnLink,
	})
}

// VPNDisconnectHandler terminates active user or session VPN connections.
func (h *Handlers) VPNDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		UserID    string `json:"user_id"`
	}
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	ctx := r.Context()
	if h.vpnSvc != nil {
		if req.SessionID != "" {
			_ = h.vpnSvc.DisconnectSession(ctx, req.SessionID)
		} else if req.UserID != "" {
			_ = h.vpnSvc.DisconnectUser(ctx, req.UserID)
		}
	}

	h.audit(r, "vpn.disconnect", map[string]any{"session_id": req.SessionID, "user_id": req.UserID})
	h.JSONOK(w)
}
