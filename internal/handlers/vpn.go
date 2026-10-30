package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
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
			SchemaVersion:      vpn.VPNStatusSchemaVersion,
			ConfiguredEngine:   vpn.ClientAWGEngineUpstream,
			ActiveEngine:       "none",
			ReturnRouteOwner:   "none",
			ListenerRunning:    false,
			EngineRunning:      false,
			ActiveTunnels:      0,
			ConnectedSessions:  0,
			ForwarderAvailable: false,
		}
	}

	h.JSON(w, http.StatusOK, status)
}

// VPNSessionsHandler returns active VPN sessions enriched with user and
// backend server identity (admin/support only; enforcement by the
// RequireAdminOrSupport route middleware). (issue #189)
// Row membership derives from the live session set (Service.SessionsLive):
// the same in-memory connected set the active-sessions card counts, so the
// card and the table agree by construction (issue #189 improvement round);
// traffic and last_seen come from the accounting pipeline — DB cumulative
// totals plus un-flushed buffered deltas, continuous across flushes.
func (h *Handlers) VPNSessionsHandler(w http.ResponseWriter, r *http.Request) {
	var sessions []models.EnrichedVPNSession
	if h.vpnSvc != nil {
		got, err := h.vpnSvc.SessionsLive(r.Context())
		if err != nil {
			// #nosec G706 -- Internal server audit log for failed session listing
			log.Printf("[vpn/handlers] failed to list enriched sessions: %v", err)
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		sessions = got
	}
	if sessions == nil {
		sessions = []models.EnrichedVPNSession{}
	}
	h.JSON(w, http.StatusOK, map[string]any{"sessions": sessions})
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

func extractProxyParamsFromManagerResult(proto string, res map[string]any) json.RawMessage {
	switch proto {
	case models.ProtocolVLESS:
		uid, _ := res["uuid"].(string)
		if uid == "" {
			uid, _ = res["client_id"].(string)
		}
		if uid == "" {
			return nil
		}
		flow, _ := res["flow"].(string)
		pubKey, _ := res["public_key"].(string)
		shortID, _ := res["short_id"].(string)
		serverName, _ := res["server_name"].(string)
		if serverName == "" {
			serverName = "gateway.icloud.com"
		}
		p := models.VLESSRealityParams{
			UUID:        uid,
			Flow:        flow,
			PublicKey:   pubKey,
			ShortID:     shortID,
			ServerName:  serverName,
			Fingerprint: "chrome",
			Transport:   "tcp",
		}
		b, _ := json.Marshal(p)
		return b

	case models.ProtocolNaive:
		username, _ := res["username"].(string)
		if username == "" {
			username, _ = res["client_id"].(string)
		}
		password, _ := res["password"].(string)
		if username == "" || password == "" {
			return nil
		}
		domain, _ := res["domain"].(string)
		p := models.NaiveProxyParams{
			Username: username,
			Password: password,
			Domain:   domain,
			EnableH3: false,
		}
		// #nosec G117 -- Typed internal backend proxy credentials marshaled for encrypted persistence
		b, _ := json.Marshal(p)
		return b
	}
	return nil
}

func detectServerProxyProtocol(srv *models.Server) string {
	if srv == nil || srv.Protocols == nil {
		return ""
	}
	if awgInfo, ok := srv.Protocols["awg"].(map[string]any); ok {
		if inst, _ := awgInfo["installed"].(bool); inst {
			return ""
		}
		if pub, _ := awgInfo["public_key"].(string); pub != "" {
			return ""
		}
	}
	for _, p := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		if pInfo, ok := srv.Protocols[p].(map[string]any); ok {
			if inst, _ := pInfo["installed"].(bool); inst {
				return p
			}
		}
	}
	return ""
}

func (h *Handlers) resolveInstalledProxyParamsForProto(ctx context.Context, srv *models.Server, proto string) (json.RawMessage, string, manager.ProtocolManager, error) {
	if srv == nil || srv.Protocols == nil {
		return nil, "", nil, errors.New("server protocols not available")
	}
	normProto := models.NormalizeTunnelProtocol(proto)
	pInfo, ok := srv.Protocols[normProto].(map[string]any)
	if !ok || pInfo == nil {
		return nil, "", nil, fmt.Errorf("protocol %s not configured on server", normProto)
	}

	// 1. If explicit credentials already exist in server metadata, reuse them.
	if pVal, ok := pInfo["params"]; ok && pVal != nil {
		if b, err := json.Marshal(pVal); err == nil && len(bytes.TrimSpace(b)) > 2 && string(bytes.TrimSpace(b)) != "null" {
			return b, "", nil, nil
		}
	}
	if pVal, ok := pInfo["protocol_params"]; ok && pVal != nil {
		if b, err := json.Marshal(pVal); err == nil && len(bytes.TrimSpace(b)) > 2 && string(bytes.TrimSpace(b)) != "null" {
			return b, "", nil, nil
		}
	}

	// 2. Try protocol manager if available and configured
	protoMgr, err := h.GetProtocolManager(normProto)
	if err != nil || protoMgr == nil {
		return nil, "", nil, fmt.Errorf("protocol manager for %s not available: %w", normProto, err)
	}
	clientParams := map[string]any{"name": fmt.Sprintf("vpn-backend-%d", srv.ID)}
	res, err := protoMgr.AddClient(ctx, srv, clientParams)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to provision proxy client on server %d: %w", srv.ID, err)
	}
	if res == nil {
		return nil, "", nil, errors.New("protocol manager returned empty client provisioning result")
	}
	clientID := extractClientIDFromManagerResult(normProto, res)
	params := extractProxyParamsFromManagerResult(normProto, res)
	if len(params) == 0 {
		_ = h.rollbackClient(ctx, protoMgr, srv, res, clientID)
		if h.db != nil && clientID != "" {
			_ = h.db.SetPeerLifecycleStatus(ctx, srv.ID, normProto, clientID, "failed")
		}
		return nil, "", nil, errors.New("failed to extract proxy parameters from manager result")
	}

	// Tie backend_active strictly to successful registration: record "pending" during enrollment.
	// Status becomes "backend_active" ONLY after EnableBackendWithConfig succeeds.
	if h.db != nil && clientID != "" {
		if err := h.db.RecordPeerLifecycle(ctx, srv.ID, normProto, clientID, clientParams["name"].(string), "", "pending"); err != nil {
			slog.Warn("failed to record pending backend proxy peer lifecycle", "server_id", srv.ID, "protocol", normProto, "client_id", clientID, "err", err)
		}
	}

	return params, clientID, protoMgr, nil
}

func extractClientIDFromManagerResult(proto string, res map[string]any) string {
	if res == nil {
		return ""
	}
	switch proto {
	case models.ProtocolVLESS:
		if uid, ok := res["uuid"].(string); ok && uid != "" {
			return uid
		}
	case models.ProtocolNaive:
		if username, ok := res["username"].(string); ok && username != "" {
			return username
		}
	}
	if cid, ok := res["client_id"].(string); ok && cid != "" {
		return cid
	}
	if cid, ok := res["clientId"].(string); ok && cid != "" {
		return cid
	}
	return ""
}

func extractClientIDFromProtocolParams(proto string, params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	switch proto {
	case models.ProtocolVLESS:
		var vless models.VLESSRealityParams
		if err := json.Unmarshal(params, &vless); err == nil && vless.UUID != "" {
			return vless.UUID
		}
	case models.ProtocolNaive:
		var naive models.NaiveProxyParams
		if err := json.Unmarshal(params, &naive); err == nil && naive.Username != "" {
			return naive.Username
		}
	}
	var raw map[string]any
	if err := json.Unmarshal(params, &raw); err == nil {
		for _, k := range []string{"username", "client_id", "clientId", "uuid"} {
			if v, ok := raw[k].(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

func (h *Handlers) isMultiProtocolEnabled(ctx context.Context) bool {
	if h.vpnSvc != nil {
		if h.vpnSvc.MultiProtocolEnabled() {
			return true
		}
		if _, err := h.vpnSvc.GetConfig(ctx); err == nil {
			return false
		}
	}
	if h.db != nil {
		if cfg, err := h.db.GetVPNConfig(ctx); err == nil && cfg != nil {
			return cfg.EnableMultiProtocolBackends
		}
	}
	return false
}

// VPNEnableBackendHandler activates a backend server for load balancing.
//
//nolint:gocyclo // transactional enable, protocol dispatch, and error handling are centralized.
func (h *Handlers) VPNEnableBackendHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req struct {
		Protocol       string          `json:"protocol"`
		ProtocolParams json.RawMessage `json:"protocol_params"`
	}
	if r.Body != nil && r.Body != http.NoBody {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1048576))
		if err == nil && len(bytes.TrimSpace(bodyBytes)) > 0 {
			if err := json.Unmarshal(bodyBytes, &req); err != nil {
				h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid JSON payload")
				return
			}
		}
	}
	if req.Protocol == "" {
		req.Protocol = r.URL.Query().Get("protocol")
	}

	bgCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 45*time.Second)
	defer cancel()

	var existingTunnel *models.BackendTunnel
	var srv *models.Server
	var newlyProvisionedClientID string
	var newlyProvisionedMgr manager.ProtocolManager

	if h.db != nil {
		existingTunnel, _ = h.db.GetBackendTunnelByServerID(bgCtx, serverID)
	}

	if existingTunnel != nil {
		// R2-B1: Protected proxy credentials (VLESS, NaiveProxy) require Admin authorization.
		hasCustomParams := len(req.ProtocolParams) > 0
		hasProtoChange := req.Protocol != "" && models.NormalizeTunnelProtocol(req.Protocol) != models.NormalizeTunnelProtocol(existingTunnel.Protocol)
		if hasCustomParams || (hasProtoChange && models.NormalizeTunnelProtocol(req.Protocol) != models.ProtocolAWG) {
			sess := h.GetSession(r)
			if sess == nil || sess.Role != models.RoleAdmin {
				h.JSONError(w, http.StatusForbidden, "forbidden", "forbidden: admin role required to configure protected proxy credentials")
				return
			}
		}

		// R2-H1: Existing backend re-enables preserving stored configuration
		if req.Protocol == "" {
			req.Protocol = existingTunnel.Protocol
		}
		if len(req.ProtocolParams) == 0 {
			req.ProtocolParams = existingTunnel.ProtocolParams
		}

		normProto := models.NormalizeTunnelProtocol(req.Protocol)
		if normProto == models.ProtocolVLESS || normProto == models.ProtocolNaive {
			if !h.isMultiProtocolEnabled(bgCtx) {
				middleware.WriteJSONError(w, http.StatusBadRequest, "multi_protocol_disabled", "multi-protocol backends are disabled")
				return
			}
		}
	} else {
		// R4-B1: First-time enrollment: determine effective protocol BEFORE calling any manager or mutating state
		effectiveProto := ""
		if req.Protocol != "" {
			effectiveProto = models.NormalizeTunnelProtocol(req.Protocol)
		}
		if effectiveProto == "" && h.db != nil {
			srv, _ = h.db.GetServer(bgCtx, serverID)
			effectiveProto = detectServerProxyProtocol(srv)
		}

		isProxy := effectiveProto == models.ProtocolVLESS || effectiveProto == models.ProtocolNaive
		if isProxy || len(req.ProtocolParams) > 0 {
			sess := h.GetSession(r)
			if sess == nil || sess.Role != models.RoleAdmin {
				middleware.WriteJSONError(w, http.StatusForbidden, "forbidden", "forbidden: admin role required to enroll proxy backends")
				return
			}
		}

		if req.Protocol == "" && effectiveProto != "" {
			req.Protocol = effectiveProto
		}

		normProto := models.NormalizeTunnelProtocol(req.Protocol)
		if normProto == models.ProtocolVLESS || normProto == models.ProtocolNaive {
			if !h.isMultiProtocolEnabled(bgCtx) {
				middleware.WriteJSONError(w, http.StatusBadRequest, "multi_protocol_disabled", "multi-protocol backends are disabled")
				return
			}
		}

		if (normProto == models.ProtocolVLESS || normProto == models.ProtocolNaive) && len(req.ProtocolParams) == 0 {
			if srv == nil && h.db != nil {
				srv, _ = h.db.GetServer(bgCtx, serverID)
			}
			if srv == nil {
				h.JSONError(w, http.StatusNotFound, "server_not_found", fmt.Sprintf("Server %d not found", serverID))
				return
			}
			params, provCID, provMgr, provErr := h.resolveInstalledProxyParamsForProto(bgCtx, srv, normProto)
			if provErr != nil {
				// #nosec G706 -- Internal server audit log for failed backend proxy client provisioning
				log.Printf("[vpn/handlers] failed to provision proxy client for server %d: %v", serverID, provErr)
				h.JSONError(w, http.StatusBadGateway, "provisioning_failed", fmt.Sprintf("Failed to provision proxy client: %v", provErr))
				return
			}
			newlyProvisionedClientID = provCID
			newlyProvisionedMgr = provMgr
			req.ProtocolParams = params
		}
	}

	normProto := models.NormalizeTunnelProtocol(req.Protocol)
	if h.vpnSvc != nil {
		var opts []tunnel.BackendTunnelOptions
		if req.Protocol != "" || len(req.ProtocolParams) > 0 {
			opts = append(opts, tunnel.BackendTunnelOptions{
				Protocol:       normProto,
				ProtocolParams: req.ProtocolParams,
			})
		}
		if err := h.vpnSvc.EnableBackendWithConfig(bgCtx, serverID, opts...); err != nil {
			if newlyProvisionedClientID != "" && newlyProvisionedMgr != nil {
				if srv == nil && h.db != nil {
					srv, _ = h.db.GetServer(bgCtx, serverID)
				}
				if rbErr := h.rollbackClient(bgCtx, newlyProvisionedMgr, srv, nil, newlyProvisionedClientID); rbErr != nil {
					slog.Warn("failed to rollback remote client after enable backend failure", "server_id", serverID, "client_id", newlyProvisionedClientID, "err", rbErr)
					if h.db != nil {
						_ = h.db.SetPeerLifecycleStatus(bgCtx, serverID, normProto, newlyProvisionedClientID, "failed")
					}
				} else if h.db != nil {
					_ = h.db.DeletePeerLifecycle(bgCtx, serverID, normProto, newlyProvisionedClientID)
				}
			}
			if errors.Is(err, vpn.ErrAWGNotInstalled) {
				h.JSONError(w, http.StatusBadRequest, "awg_not_installed", "Server does not have AmneziaWG installed or configured")
				return
			}
			if errors.Is(err, vpn.ErrServerNotFound) {
				h.JSONError(w, http.StatusNotFound, "server_not_found", fmt.Sprintf("Server %d not found", serverID))
				return
			}
			if errors.Is(err, vpn.ErrMultiProtocolBackendsDisabled) || strings.Contains(err.Error(), "multi-protocol backends are disabled") {
				h.JSONError(w, http.StatusBadRequest, "multi_protocol_disabled", "multi-protocol backends are disabled")
				return
			}
			// #nosec G706 -- Internal server audit log for failed backend enable
			log.Printf("[vpn/handlers] failed to enable backend %d: %v", serverID, err)
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to enable backend")
			return
		}
	}

	if (normProto == models.ProtocolVLESS || normProto == models.ProtocolNaive) && h.db != nil {
		cid := extractClientIDFromProtocolParams(normProto, req.ProtocolParams)
		if cid != "" {
			_ = vpn.RecordBackendProxyPeerLifecycle(bgCtx, h.db, serverID, normProto, cid, fmt.Sprintf("vpn-backend-%d", serverID))
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

// VPNDeleteBackendHandler permanently removes a backend tunnel from the
// load-balancing pool (issue #29). The server itself and its AWG protocol
// configuration are untouched; only the tunnel registration, its DB row and
// any live session routing are drained and deleted.
func (h *Handlers) VPNDeleteBackendHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	ctx := r.Context()
	if h.vpnSvc != nil {
		if err := h.vpnSvc.DeleteBackend(ctx, serverID); err != nil {
			if errors.Is(err, vpn.ErrBackendTunnelNotFound) {
				h.JSONError(w, http.StatusNotFound, "backend_not_found", fmt.Sprintf("Backend %d not found", serverID))
				return
			}
			// #nosec G706 -- Internal server audit log for failed backend delete
			log.Printf("[vpn/handlers] failed to delete backend %d: %v", serverID, err)
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to delete backend")
			return
		}
	}

	h.audit(r, "vpn.backend_delete", map[string]any{"server_id": serverID})
	h.JSONOK(w)
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
type vpnConfigResponse struct {
	models.VPNConfig
	ServerPrivateKey string `json:"-"`
}

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

	visible := *cfg
	visible.ServerPrivateKey = ""
	h.JSON(w, http.StatusOK, vpnConfigResponse{VPNConfig: visible})
}

// vpnConfigPresence records which keys the caller actually SENT, as opposed
// to which ones merely decoded to a zero value. It is what makes a partial
// update a PATCH for booleans: a bool cannot distinguish "explicitly false"
// from "omitted", so absent `random_trailers` would otherwise be persisted as
// false and silently erase the stored protocol flag
// (issue #391 round 4b, finding 3).
type vpnConfigPresence struct {
	publicEndpoint              bool
	randomTrailers              bool
	disableCookies              bool
	dataPlaneI1                 bool
	enableMultiProtocolBackends bool
}

// hasRawKey reports whether the caller sent the named JSON key, matching the
// encoding/json field lookup case-insensitively (json.Unmarshal applies field
// names case-insensitively, so presence must be tracked the same way or
// `{"RandomTrailers": true}` would decode into the field while registering as
// absent here).
func hasRawKey(raw map[string]json.RawMessage, name string) bool {
	if _, ok := raw[name]; ok {
		return true
	}
	for key := range raw {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func mergeVPNConfig(current *models.VPNConfig, cfg *models.VPNConfig, present vpnConfigPresence) {
	if current == nil || cfg == nil {
		return
	}
	if !present.dataPlaneI1 {
		cfg.VPNDataPlaneI1Protocol = current.VPNDataPlaneI1Protocol
	}
	if cfg.H1.IsZero() && cfg.S1 == 0 {
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = current.H1, current.H2, current.H3, current.H4
		cfg.S1, cfg.S2, cfg.S3, cfg.S4 = current.S1, current.S2, current.S3, current.S4
	}
	// Portal identity must be preserved even when the caller supplies H/S.
	cfg.ServerPrivateKey = current.ServerPrivateKey
	cfg.ServerPublicKey = current.ServerPublicKey
	if !present.publicEndpoint {
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
	if cfg.AffinityTTLMinutes == 0 {
		cfg.AffinityTTLMinutes = current.AffinityTTLMinutes
	}
	if cfg.MinRebalanceSessions == 0 {
		cfg.MinRebalanceSessions = current.MinRebalanceSessions
	}
	if cfg.ClientQueueSize == 0 {
		cfg.ClientQueueSize = current.ClientQueueSize
	}
	// Protocol-parameter booleans follow PRESENCE semantics, not zero-value
	// semantics (issue #391 round 4b, finding 3): absent preserves the stored
	// value, present applies the caller's value verbatim. Without this an
	// unrelated partial update such as {"health_threshold_ms": 750} unmarshals
	// both flags to false and SaveVPNConfig persists false — and, with a peer
	// synchronizer active, that omission is indistinguishable from a
	// prohibited protocol-parameter change and rejects the update outright.
	if !present.randomTrailers {
		cfg.RandomTrailers = current.RandomTrailers
	}
	if !present.disableCookies {
		cfg.DisableCookies = current.DisableCookies
	}
	if !present.enableMultiProtocolBackends {
		cfg.EnableMultiProtocolBackends = current.EnableMultiProtocolBackends
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
	for name := range raw {
		if strings.EqualFold(name, "server_private_key") || strings.EqualFold(name, "server_public_key") ||
			strings.EqualFold(name, "ServerPrivateKey") || strings.EqualFold(name, "ServerPublicKey") {
			h.JSONError(w, http.StatusBadRequest, "validation_failed", "Portal key fields cannot be updated")
			return
		}
	}

	var cfg models.VPNConfig
	if err := json.Unmarshal(bodyBytes, &cfg); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	present := vpnConfigPresence{
		publicEndpoint:              hasRawKey(raw, "public_endpoint"),
		randomTrailers:              hasRawKey(raw, "random_trailers"),
		disableCookies:              hasRawKey(raw, "disable_cookies"),
		dataPlaneI1:                 hasRawKey(raw, "vpn_data_plane_i1_protocol"),
		enableMultiProtocolBackends: hasRawKey(raw, "enable_multi_protocol_backends"),
	}

	ctx := r.Context()
	if present.dataPlaneI1 {
		if cfg.VPNDataPlaneI1Protocol == "" {
			h.JSONError(w, http.StatusBadRequest, "validation_failed", "invalid vpn_data_plane_i1_protocol: expected sip or dns")
			return
		}
		if err := cfg.ValidateDataPlaneI1Protocol(); err != nil {
			h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
			return
		}
	}
	if h.vpnSvc != nil {
		if current, err := h.vpnSvc.GetConfig(ctx); err == nil && current != nil {
			mergeVPNConfig(current, &cfg, present)
		}
		if err := h.vpnSvc.UpdateConfig(ctx, &cfg); err != nil {
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update VPN configuration")
			return
		}
	} else if h.db != nil {
		if current, err := h.db.GetVPNConfig(ctx); err == nil && current != nil {
			mergeVPNConfig(current, &cfg, present)
		}
		if err := h.db.SaveVPNConfig(ctx, &cfg); err != nil {
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update VPN configuration")
			return
		}
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
		h.handleVPNMyConfigError(w, err)
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

// handleVPNMyConfigError writes a sanitized error response for VPNMyConfigHandler (/api/vpn/my-config),
// preserving 400/403/404/409/500 status and code mappings without leaking internal error details (CWE-209).
func (h *Handlers) handleVPNMyConfigError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	slog.Error("failed to generate VPN configuration", "error", err)

	switch {
	case errors.Is(err, vpn.ErrConnectionCreatedConcurrently):
		h.JSONError(w, http.StatusConflict, "conflict", "Connection was created concurrently; please retry")
	case errors.Is(err, vpn.ErrUserNotFound):
		h.JSONError(w, http.StatusNotFound, "not_found", "Client configuration not found")
	case errors.Is(err, vpn.ErrAccessDenied):
		h.JSONError(w, http.StatusForbidden, "forbidden", "Access denied")
	case errors.Is(err, vpn.ErrInvalidParameter):
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid configuration parameter")
	case errors.Is(err, vpn.ErrBadRequest):
		h.JSONError(w, http.StatusBadRequest, "bad_request", "Invalid configuration request")
	default:
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to generate VPN configuration")
	}
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
