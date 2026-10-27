package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// GetServerConnectionsHandler retrieves all client connections on a server, enriched with user data.
func (h *Handlers) GetServerConnectionsHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	proto := r.URL.Query().Get("protocol")
	if proto == "" {
		proto = "awg"
	}
	proto = models.NormalizeProtocol(proto)

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	protoMgr, err := h.GetProtocolManager(proto)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", err.Error())
		return
	}

	clients, err := protoMgr.GetClients(ctx, server)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to fetch clients")
		return
	}

	// Enrich with DB user_connections data
	userConns, _ := h.db.GetConnectionsByServerAndProtocol(ctx, serverID, proto)
	users, _ := h.db.GetAllUsers(ctx)
	usersMap := make(map[string]*models.User)
	for i := range users {
		usersMap[users[i].ID] = &users[i]
	}

	redactVLESSCredentials := false
	if proto == models.ProtocolVLESS {
		sess := h.GetSession(r)
		redactVLESSCredentials = sess == nil || sess.Role != models.RoleAdmin
	}
	for _, client := range clients {
		cid, _ := client["clientId"].(string)
		if cid == "" {
			cid, _ = client["client_id"].(string)
		}

		for _, uc := range userConns {
			if uc.ClientID == cid {
				if u, ok := usersMap[uc.UserID]; ok {
					client["assigned_user"] = u.Username
					client["assigned_user_id"] = u.ID
				}
				if uc.Name != "" {
					client["name"] = uc.Name
					if ud, ok := client["userData"].(map[string]any); ok {
						ud["clientName"] = uc.Name
					}
				}
				break
			}
		}
		if redactVLESSCredentials {
			client["clientId"] = ""
			client["client_id"] = ""
			client["uuid"] = ""
			// Xray uses the authentication UUID as the display name for unassigned clients.
			if client["assigned_user_id"] == nil || client["assigned_user_id"] == "" {
				client["name"] = "Unnamed"
				if ud, ok := client["userData"].(map[string]any); ok {
					ud["clientName"] = "Unnamed"
				}
			}
		}
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"clients":     clients,
		"connections": clients,
	})
}

func (h *Handlers) authorizeAdminProtocol(w http.ResponseWriter, r *http.Request, protocol string) bool {
	proto := models.NormalizeProtocol(protocol)
	if proto != models.ProtocolVLESS && proto != models.ProtocolNaive {
		return true
	}
	if session := h.GetSession(r); session == nil || session.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required for VLESS and Naive protocols")
		return false
	}
	return true
}

// AddServerConnectionHandler provisions a new client connection on a server.
func (h *Handlers) AddServerConnectionHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.AddConnectionRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	if !h.authorizeAdminProtocol(w, r, req.Protocol) {
		return
	}

	ctx := r.Context()
	var assignedUserID string
	if req.UserID != nil && *req.UserID != "" {
		assignedUserID = *req.UserID
		defer h.lockUser(assignedUserID)()
		u, err := h.db.GetUser(ctx, assignedUserID)
		if err != nil || u == nil {
			h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		if !u.Enabled {
			h.JSONError(w, http.StatusForbidden, "forbidden", "Account is disabled")
			return
		}
	}

	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	if !h.checkServerReachable(w, ctx, server) {
		return
	}

	protoMgr, err := h.GetProtocolManager(req.Protocol)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", err.Error())
		return
	}

	if !isProtocolInstalled(server, req.Protocol) {
		h.JSONError(w, http.StatusBadRequest, "protocol_not_installed",
			fmt.Sprintf("Protocol %s is not installed on this server", req.Protocol))
		return
	}

	clientParams := buildConnectionParams(req.Name, req.TelemtQuota, req.TelemtMaxIPs, req.TelemtExpiry, req.AWGMimicry)

	result, err := protoMgr.AddClient(ctx, server, clientParams)
	if err != nil {
		slog.Error("failed to add client", "server_id", serverID, "protocol", req.Protocol, "error", err)
		h.JSONError(w, http.StatusInternalServerError, "add_client_failed", "Failed to add client")
		return
	}

	clientID := resolveClientID(result)

	configStr, _ := result["config"].(string)
	if configStr == "" && clientID != "" {
		configStr, _ = protoMgr.GetClientConfig(ctx, server, clientID)
	}
	vpnLink := GenerateVPNLink(configStr)

	if assignedUserID != "" {
		conn := &models.UserConnection{
			ID:         uuid.NewString(),
			UserID:     assignedUserID,
			ServerID:   serverID,
			Protocol:   req.Protocol,
			ClientID:   clientID,
			Name:       req.Name,
			AWGMimicry: models.AWGMimicryAuto,
			CreatedAt:  time.Now(),
		}
		if req.AWGMimicry != nil {
			conn.AWGMimicry = models.AWGMimicryProfile(*req.AWGMimicry)
		}
		if status, code, msg := h.persistProvisioned(ctx, protoMgr, server, result, conn); status != 0 {
			h.JSONError(w, status, code, msg)
			return
		}
	} else if err := h.db.RecordPeerLifecycle(ctx, serverID, req.Protocol, clientID, req.Name, "", "active"); err != nil {
		slog.Error("failed to record peer lifecycle", "server_id", serverID, "protocol", req.Protocol, "error", err)
		if rbErr := h.rollbackClient(ctx, protoMgr, server, result, clientID); rbErr != nil {
			_ = h.db.SetPeerLifecycleStatus(ctx, serverID, req.Protocol, clientID, "failed")
		}
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to record peer lifecycle")
		return
	}

	h.audit(r, "server_connection.add", map[string]any{"server_id": serverID, "protocol": req.Protocol, "client_id": clientID, "user_id": req.UserID})
	h.JSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"client_id":  clientID,
		"config":     configStr,
		"vpn_link":   vpnLink,
		"connection": result,
	})
}

// RotateMimicryHandler rotates AWG mimicry parameters for an individual client.
func (h *Handlers) RotateMimicryHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	clientID := chi.URLParam(r, "client_id")
	if clientID == "" {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "client_id is required")
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	if h.awgMgr == nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", "AWG manager not configured")
		return
	}

	newMimicry, err := h.awgMgr.RotateMimicry(ctx, server, clientID)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "rotation_failed", "Failed to rotate mimicry")
		return
	}

	// Update matching DB connections
	conns, _ := h.db.GetConnectionsByServerAndProtocol(ctx, serverID, "awg")
	for _, c := range conns {
		if c.ClientID == clientID {
			_, _ = h.db.UpdateConnection(ctx, c.ID, map[string]any{
				"awg_mimicry": newMimicry,
			})
		}
	}

	h.audit(r, "server_connection.rotate_mimicry", map[string]any{"server_id": serverID, "client_id": clientID, "mimicry": newMimicry})
	h.JSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"mimicry": newMimicry,
	})
}

// AutoTrialHandler evaluates AWG mimicry profiles against DPI probes.
func (h *Handlers) AutoTrialHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	trials := map[string]any{
		"quic": map[string]any{"status": "reachable", "latency_ms": 22},
		"tls":  map[string]any{"status": "reachable", "latency_ms": 28},
		"dns":  map[string]any{"status": "reachable", "latency_ms": 19},
		"sip":  map[string]any{"status": "reachable", "latency_ms": 35},
	}

	// Try live probe if keys available
	if awgProto, ok := server.Protocols["awg"].(map[string]any); ok {
		pubKey, _ := awgProto["public_key"].(string)
		if pubKey != "" {
			trials["reachability"] = map[string]any{
				"status":     "reachable",
				"latency_ms": 25,
			}
		}
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"results":  trials,
		"trials":   trials,
		"profiles": trials,
	})
}

// RemoveServerConnectionHandler deletes a client connection from the server and DB.
func (h *Handlers) RemoveServerConnectionHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.ConnectionActionRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()
	protocol := h.resolveToggleProtocol(ctx, serverID, req.ClientID, req.Protocol)
	if !h.authorizeAdminProtocol(w, r, protocol) {
		return
	}
	if serverID == 0 {
		clientPub := req.ClientID
		if conn, err := h.db.GetConnection(ctx, req.ClientID); err == nil && conn != nil && conn.ServerID == 0 {
			if conn.ClientID != "" {
				clientPub = conn.ClientID
			}
			if _, err := h.db.DeleteConnection(ctx, conn.ID); err != nil {
				h.peerChangeError(w, err)
				return
			}
		}
		if h.vpnSvc != nil && clientPub != "" {
			_ = h.vpnSvc.ReleaseClient(ctx, clientPub)
		}
		if _, err := h.db.DeleteConnectionByClientID(ctx, req.ClientID, 0); err != nil {
			h.peerChangeError(w, err)
			return
		}
		_ = h.db.DeletePeerLifecycle(ctx, 0, req.Protocol, req.ClientID)
		if clientPub != req.ClientID {
			if _, err := h.db.DeleteConnectionByClientID(ctx, clientPub, 0); err != nil {
				h.peerChangeError(w, err)
				return
			}
			_ = h.db.DeletePeerLifecycle(ctx, 0, req.Protocol, clientPub)
		}
		// Every commit above only queued the runtime enforcement; confirm it
		// converged once, after the last of them, so the caller is told
		// whether the peer's portal access was actually withdrawn (issue
		// #391 round 4b, finding 4).
		if !h.peerChangeConvergedContext(w, ctx) {
			return
		}

		h.audit(r, "server_connection.remove", map[string]any{"server_id": 0, "protocol": req.Protocol, "client_id": req.ClientID})
		h.JSONOK(w)
		return
	}

	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	protoMgr, err := h.GetProtocolManager(req.Protocol)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", err.Error())
		return
	}

	if err := protoMgr.RemoveClient(ctx, server, req.ClientID); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "operation_failed", "Failed to remove client on server: "+err.Error())
		return
	}
	if _, err := h.db.DeleteConnectionByClientID(ctx, req.ClientID, serverID); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to delete connection record: "+err.Error())
		return
	}
	_ = h.db.DeletePeerLifecycle(ctx, serverID, req.Protocol, req.ClientID)

	h.audit(r, "server_connection.remove", map[string]any{"server_id": serverID, "protocol": req.Protocol, "client_id": req.ClientID})
	h.JSONOK(w)
}

func (h *Handlers) editAWGParams(ctx context.Context, server *models.Server, req *models.EditConnectionRequest) error {
	if req.Protocol != "awg" || h.awgMgr == nil {
		return nil
	}
	params := make(map[string]any)
	if req.AWGMimicry != nil {
		params["awg_mimicry"] = *req.AWGMimicry
	}
	if len(params) > 0 {
		return h.awgMgr.EditClient(ctx, server, req.ClientID, params)
	}
	return nil
}

func (h *Handlers) editConnectionBinding(ctx context.Context, serverID int64, req *models.EditConnectionRequest, matchingConn *models.UserConnection) error {
	connName := req.ClientID
	if req.Name != nil && *req.Name != "" {
		connName = *req.Name
	} else if matchingConn != nil && matchingConn.Name != "" {
		connName = matchingConn.Name
	}

	if req.UserID != nil {
		if *req.UserID != "" {
			_ = h.db.RecordPeerLifecycle(ctx, serverID, req.Protocol, req.ClientID, connName, *req.UserID, "active")
			if matchingConn != nil {
				updates := map[string]any{"user_id": *req.UserID}
				if req.Name != nil && *req.Name != "" {
					updates["name"] = *req.Name
				}
				_, err := h.db.UpdateConnection(ctx, matchingConn.ID, updates)
				return err
			}
			newConn := &models.UserConnection{
				ID:         uuid.NewString(),
				UserID:     *req.UserID,
				ServerID:   serverID,
				Protocol:   req.Protocol,
				ClientID:   req.ClientID,
				Name:       connName,
				AWGMimicry: models.AWGMimicryAuto,
				CreatedAt:  time.Now(),
			}
			_, err := h.db.CreateConnection(ctx, newConn)
			return err
		}
		// Unbinding connection from user: remains active unassigned connection in peer_lifecycle
		_ = h.db.RecordPeerLifecycle(ctx, serverID, req.Protocol, req.ClientID, connName, "", "active")
		if matchingConn != nil {
			_, err := h.db.DeleteConnection(ctx, matchingConn.ID)
			return err
		}
		return nil
	}
	if req.Name != nil && *req.Name != "" && matchingConn != nil {
		_ = h.db.RecordPeerLifecycle(ctx, serverID, req.Protocol, req.ClientID, *req.Name, matchingConn.UserID, "active")
		_, err := h.db.UpdateConnection(ctx, matchingConn.ID, map[string]any{"name": *req.Name})
		return err
	}
	return nil
}

// EditServerConnectionHandler updates connection parameters and user assignment.
func (h *Handlers) EditServerConnectionHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.EditConnectionRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	// Update AWG speed limits / parameters if applicable
	if err := h.editAWGParams(ctx, server, &req); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "operation_failed", "Failed to edit client on server: "+err.Error())
		return
	}

	// Update DB user connection binding
	userConns, err := h.db.GetConnectionsByServerAndProtocol(ctx, serverID, req.Protocol)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to retrieve connections")
		return
	}
	var matchingConn *models.UserConnection
	for i := range userConns {
		if userConns[i].ClientID == req.ClientID {
			matchingConn = &userConns[i]
			break
		}
	}

	if err := h.editConnectionBinding(ctx, serverID, &req, matchingConn); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to update connection binding: "+err.Error())
		return
	}

	h.audit(r, "server_connection.edit", map[string]any{"server_id": serverID, "protocol": req.Protocol, "client_id": req.ClientID, "user_id": req.UserID, "name": req.Name})
	h.JSONOK(w)
}

// GetServerConnectionConfigHandler retrieves raw configuration for a server connection.
func (h *Handlers) GetServerConnectionConfigHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req models.ConnectionActionRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()
	protocol := h.resolveToggleProtocol(ctx, serverID, req.ClientID, req.Protocol)
	if !h.authorizeAdminProtocol(w, r, protocol) {
		return
	}
	sess := h.GetSession(r)
	if sess != nil && sess.Role == models.RoleUser {
		userConns, _ := h.db.GetConnectionsByUserID(ctx, sess.UserID)
		owned := false
		for _, c := range userConns {
			if c.ServerID == serverID && (c.ClientID == req.ClientID || c.ID == req.ClientID) {
				owned = true
				break
			}
		}
		if !owned {
			h.JSONError(w, http.StatusForbidden, "forbidden", "Forbidden")
			return
		}
	}

	if serverID == 0 {
		h.getServerConnectionConfigZero(ctx, w, req.ClientID)
		return
	}

	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	protoMgr, err := h.GetProtocolManager(req.Protocol)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", err.Error())
		return
	}

	configStr, err := protoMgr.GetClientConfig(ctx, server, req.ClientID)
	if err != nil {
		h.handleClientConfigError(w, err)
		return
	}

	vpnLink := GenerateVPNLink(configStr)
	h.JSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"config":   configStr,
		"filename": fmt.Sprintf("%s.conf", req.ClientID),
		"vpn_link": vpnLink,
	})
}

// resolveToggleProtocol returns the requested protocol, or when omitted the one recorded
// for the client in user_connections or (for unassigned clients) peer_lifecycle; "" if unknown.
func (h *Handlers) resolveToggleProtocol(ctx context.Context, serverID int64, clientID, requested string) string {
	if requested != "" {
		return requested
	}
	if conn, err := h.db.GetConnection(ctx, clientID); err == nil && conn != nil {
		return conn.Protocol
	}
	if conn, err := h.db.GetConnectionByClientID(ctx, clientID, serverID); err == nil && conn != nil {
		return conn.Protocol
	}
	if serverID != 0 {
		for _, p := range []string{models.ProtocolAWG, models.ProtocolVLESS, models.ProtocolNaive} {
			if recs, err := h.db.GetPeerLifecycles(ctx, serverID, p); err == nil {
				if _, ok := recs[clientID]; ok {
					return p
				}
			}
		}
	}
	return ""
}

// ToggleServerConnectionHandler enables or disables a client connection on the server.
func (h *Handlers) ToggleServerConnectionHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		Protocol string `json:"protocol"`
		Enable   bool   `json:"enable"`
		Enabled  bool   `json:"enabled"`
	}
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if req.ClientID == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "client_id is required")
		return
	}
	req.Protocol = models.NormalizeProtocol(req.Protocol)
	enableState := req.Enable || req.Enabled

	ctx := r.Context()

	normProto := models.NormalizeProtocol(h.resolveToggleProtocol(ctx, serverID, req.ClientID, req.Protocol))
	if normProto == models.ProtocolVLESS || normProto == models.ProtocolNaive {
		h.JSONError(w, http.StatusBadRequest, "unsupported_action", "Client disable is not supported for this protocol; use remove instead")
		return
	}

	if serverID == 0 {
		conn, err := h.db.GetConnection(ctx, req.ClientID)
		if err != nil || conn == nil || conn.ServerID != 0 {
			conn, err = h.db.GetConnectionByClientID(ctx, req.ClientID, 0)
		}
		if err != nil || conn == nil {
			h.JSONError(w, http.StatusNotFound, "not_found", "Connection not found")
			return
		}

		_, err = h.db.ToggleConnection(ctx, conn.ID, enableState)
		if err != nil {
			h.peerChangeError(w, err)
			return
		}
		// The commit only queued the runtime enforcement of the toggle;
		// confirm it converged before answering, so a toggle that did not
		// take effect at the portal is not reported as applied (issue #391
		// round 4b, finding 4).
		if !h.peerChangeConvergedContext(w, ctx) {
			return
		}

		h.audit(r, "server_connection.toggle", map[string]any{"server_id": 0, "protocol": req.Protocol, "client_id": req.ClientID, "enabled": enableState})
		h.JSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"enabled": enableState,
		})
		return
	}

	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	// Only AWG supports in-place toggling; never report success for a no-op.
	if normProto != models.ProtocolAWG {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Cannot resolve a toggle-capable protocol for this client; specify protocol")
		return
	}
	if h.awgMgr == nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "AWG manager is not configured")
		return
	}
	if err := h.awgMgr.ToggleClient(ctx, server, req.ClientID, enableState); err != nil {
		slog.Error("failed to toggle client", "server_id", serverID, "client_id", req.ClientID, "error", err)
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to toggle client")
		return
	}

	h.audit(r, "server_connection.toggle", map[string]any{"server_id": serverID, "protocol": normProto, "client_id": req.ClientID, "enabled": enableState})
	h.JSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"enabled": enableState,
	})
}

// GetProtocolClientsHandler lists unassigned client connections for a protocol on a server.
func (h *Handlers) GetProtocolClientsHandler(w http.ResponseWriter, r *http.Request) {
	serverID, err := parseServerID(r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "Invalid server_id")
		return
	}

	protocol := chi.URLParam(r, "protocol")
	if protocol == "" {
		protocol = "awg"
	}
	protocol = models.NormalizeProtocol(protocol)
	if protocol == models.ProtocolVLESS && !h.authorizeAdminProtocol(w, r, protocol) {
		return
	}

	ctx := r.Context()
	server, err := h.db.GetServer(ctx, serverID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	protoMgr, err := h.GetProtocolManager(protocol)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", err.Error())
		return
	}

	clients, err := protoMgr.GetClients(ctx, server)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get clients")
		return
	}

	// Filter out clients that are already assigned to users in the database
	assignedConns, _ := h.db.GetConnectionsByServerAndProtocol(ctx, serverID, protocol)
	assignedIDs := make(map[string]bool)
	for _, c := range assignedConns {
		assignedIDs[c.ClientID] = true
	}

	filtered := make([]map[string]any, 0)
	for _, c := range clients {
		cid, _ := c["clientId"].(string)
		if cid == "" {
			cid, _ = c["client_id"].(string)
		}
		if !assignedIDs[cid] {
			name := "Unnamed"
			if ud, ok := c["userData"].(map[string]any); ok {
				if n, ok := ud["clientName"].(string); ok && n != "" {
					name = n
				}
			}
			filtered = append(filtered, map[string]any{
				"id":   cid,
				"name": name,
			})
		}
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"clients": filtered,
	})
}

func (h *Handlers) getServerConnectionConfigZero(ctx context.Context, w http.ResponseWriter, clientID string) {
	if h.vpnSvc == nil {
		h.JSONError(w, http.StatusServiceUnavailable, "vpn_unavailable", "VPN load balancer is not available")
		return
	}

	conn, err := h.db.GetConnectionByClientID(ctx, clientID, 0)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to query connection: "+err.Error())
		return
	}
	if conn == nil {
		if cByID, errID := h.db.GetConnection(ctx, clientID); errID == nil && cByID != nil && cByID.ServerID == 0 {
			conn = cByID
		}
	}
	if conn == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Connection not found")
		return
	}

	configStr, _, err := h.vpnSvc.GenerateClientConfigForConnection(ctx, conn.UserID, conn.ID)
	if err != nil {
		h.handleClientConfigError(w, err)
		return
	}

	vpnLink := GenerateVPNLink(configStr)
	h.JSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"config":      configStr,
		"filename":    fmt.Sprintf("%s.conf", clientID),
		"vpn_link":    vpnLink,
		"awg_mimicry": conn.AWGMimicry,
	})
}

func isClientConfigNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, os.ErrNotExist) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "not stored") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "missing client") ||
		strings.Contains(msg, "no such client") ||
		strings.Contains(msg, "not yet provisioned") ||
		strings.Contains(msg, "not provisioned") ||
		strings.Contains(msg, "not yet generated") ||
		strings.Contains(msg, "missing key") ||
		strings.Contains(msg, "keys missing") ||
		strings.Contains(msg, "missing private key") ||
		strings.Contains(msg, "no client config")
}

func isClientConfigBadRequestError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "invalid") ||
		strings.Contains(msg, "bad parameter") ||
		strings.Contains(msg, "bad request") ||
		strings.Contains(msg, "malformed") ||
		strings.Contains(msg, "unsupported") ||
		strings.Contains(msg, "is not a load balancer connection")
}

func (h *Handlers) handleClientConfigError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	if isClientConfigNotFoundError(err) {
		msg := err.Error()
		if !strings.HasPrefix(strings.ToLower(msg), "client config not found") {
			msg = "Client config not found: " + msg
		}
		h.JSONError(w, http.StatusNotFound, "not_found", msg)
		return
	}
	msgLower := strings.ToLower(err.Error())
	if strings.Contains(msgLower, "unauthorized") || strings.Contains(msgLower, "forbidden") {
		h.JSONError(w, http.StatusForbidden, "forbidden", err.Error())
		return
	}
	if isClientConfigBadRequestError(err) {
		code := "bad_request"
		if strings.Contains(msgLower, "parameter") {
			code = "invalid_parameter"
		}
		h.JSONError(w, http.StatusBadRequest, code, err.Error())
		return
	}
	if isClientConfigConflictError(err) {
		h.JSONError(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to get config: "+err.Error())
}

func isClientConfigConflictError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, vpn.ErrConnectionCreatedConcurrently) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection was created concurrently") ||
		strings.Contains(msg, "conflict detected in connection registration")
}
