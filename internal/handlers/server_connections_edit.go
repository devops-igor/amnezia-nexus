package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/google/uuid"
)

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
	if models.NormalizeProtocol(req.Protocol) == models.ProtocolVLESS {
		connName = "Unnamed"
	}
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

// lockConnectionUsers serializes ownership changes with deletion in stable order.
func (h *Handlers) lockConnectionUsers(sourceUserID, destUserID string) func() {
	if sourceUserID == "" && destUserID == "" {
		return func() {}
	}
	if sourceUserID == "" || sourceUserID == destUserID {
		return h.lockUser(destUserID)
	}
	if destUserID == "" {
		return h.lockUser(sourceUserID)
	}
	if sourceUserID > destUserID {
		sourceUserID, destUserID = destUserID, sourceUserID
	}
	unlockFirst := h.lockUser(sourceUserID)
	unlockSecond := h.lockUser(destUserID)
	return func() {
		unlockSecond()
		unlockFirst()
	}
}

// validateConnectionDestination checks assignment eligibility while caller locks are held.
func (h *Handlers) validateConnectionDestination(w http.ResponseWriter, ctx context.Context, userID string) bool {
	if userID == "" {
		return true
	}
	user, err := h.db.GetUser(ctx, userID)
	if err != nil || user == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
		return false
	}
	if !user.Enabled {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Account is disabled")
		return false
	}
	return true
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
	protocol := h.resolveToggleProtocol(ctx, serverID, req.ClientID, req.Protocol)
	if !h.authorizeAdminProtocol(w, r, protocol) {
		return
	}
	if req.Protocol != "" && protocol != req.Protocol {
		h.JSONError(w, http.StatusBadRequest, "protocol_mismatch", "Protocol does not match the recorded connection")
		return
	}
	req.Protocol = protocol
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

	if req.UserID != nil {
		sourceUserID := ""
		if matchingConn != nil {
			sourceUserID = matchingConn.UserID
		}
		destUserID := *req.UserID
		defer h.lockConnectionUsers(sourceUserID, destUserID)()

		if sourceUserID != "" && destUserID != "" && sourceUserID != destUserID {
			current, err := h.db.GetConnection(ctx, matchingConn.ID)
			if err != nil {
				h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to verify connection ownership")
				return
			}
			if current == nil || current.UserID != sourceUserID {
				h.JSONError(w, http.StatusConflict, "connection_changed", "Connection ownership changed; retry the request")
				return
			}
			matchingConn = current
		}

		if !h.validateConnectionDestination(w, ctx, destUserID) {
			return
		}
	}

	if err := h.editConnectionBinding(ctx, serverID, &req, matchingConn); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to update connection binding: "+err.Error())
		return
	}

	h.audit(r, "server_connection.edit", map[string]any{"server_id": serverID, "protocol": req.Protocol, "client_id": req.ClientID, "user_id": req.UserID, "name": req.Name})
	h.JSONOK(w)
}
