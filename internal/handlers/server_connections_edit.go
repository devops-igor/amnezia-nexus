package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/google/uuid"
)

// errClientAlreadyAssigned reports that a user_connections row already exists for the client.
var errClientAlreadyAssigned = errors.New("client is already assigned")

// clientLocks holds one mutex per (server, protocol, client) credential. Entries are
// never evicted (shortcut: one small mutex per edited client; add eviction if that grows).
var clientLocks sync.Map

// lockClient serializes ownership changes of a single credential and returns the unlock func.
// Lock order is client first, then users (lockConnectionUsers); no path takes them reversed.
func lockClient(serverID int64, protocol, clientID string) func() {
	key := fmt.Sprintf("%d|%s|%s", serverID, models.NormalizeProtocol(protocol), clientID)
	mu, _ := clientLocks.LoadOrStore(key, &sync.Mutex{})
	m := mu.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

// findClientConnection returns the connection row bound to the client, or nil if unassigned.
func (h *Handlers) findClientConnection(ctx context.Context, serverID int64, protocol, clientID string) (*models.UserConnection, error) {
	conns, err := h.db.GetConnectionsByServerAndProtocol(ctx, serverID, protocol)
	if err != nil {
		return nil, err
	}
	for i := range conns {
		if conns[i].ClientID == clientID {
			return &conns[i], nil
		}
	}
	return nil, nil
}

func verifyRemoteClientExists(
	ctx context.Context,
	protoMgr manager.ProtocolManager,
	server *models.Server,
	clientID string,
) (bool, error) {
	_, err := protoMgr.GetClientConfig(ctx, server, clientID)
	if err == nil {
		return true, nil
	}
	// AWG clients without a stored private key exist, but their config cannot be reconstructed.
	if strings.Contains(err.Error(), "client private key not stored") {
		return true, nil
	}
	clients, getErr := protoMgr.GetClients(ctx, server)
	if getErr == nil {
		for _, c := range clients {
			if id, ok := c["clientId"].(string); ok && id == clientID {
				return true, nil
			}
			if id, ok := c["client_id"].(string); ok && id == clientID {
				return true, nil
			}
		}
	}
	return false, err
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
			if existing, err := h.findClientConnection(ctx, serverID, req.Protocol, req.ClientID); err != nil {
				return err
			} else if existing != nil {
				return errClientAlreadyAssigned
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
		ok, err := h.db.UpdateConnection(ctx, matchingConn.ID, map[string]any{"name": *req.Name})
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("connection record not found")
		}
		_ = h.db.RecordPeerLifecycle(ctx, serverID, req.Protocol, req.ClientID, *req.Name, matchingConn.UserID, "active")
		return nil
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

// lockAssignment takes the client lock, then the user locks, and re-validates the binding
// under them. On failure it writes the error response; otherwise the caller must call unlock.
func (h *Handlers) lockAssignment(w http.ResponseWriter, ctx context.Context, serverID int64, req *models.EditConnectionRequest, matchingConn *models.UserConnection, protoMgr manager.ProtocolManager, server *models.Server) (*models.UserConnection, func(), bool) {
	// Serialize on the credential itself: user locks alone let two admins bind one
	// unassigned client to different users concurrently.
	unlockClient := lockClient(serverID, req.Protocol, req.ClientID)
	unlock := unlockClient
	// Remote existence must be probed under the client lock: two concurrent edits on
	// an unassigned client otherwise both pass the probe and both create a binding.
	exists, probeErr := verifyRemoteClientExists(ctx, protoMgr, server, req.ClientID)
	if probeErr != nil {
		unlock()
		h.JSONError(w, http.StatusInternalServerError, "operation_failed", "Failed to verify client on remote server: "+probeErr.Error())
		return nil, nil, false
	}
	if !exists {
		unlock()
		h.JSONError(w, http.StatusNotFound, "client_not_found", "Client configuration not found on remote server")
		return nil, nil, false
	}
	current, err := h.findClientConnection(ctx, serverID, req.Protocol, req.ClientID)
	if err != nil {
		unlock()
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to retrieve connections")
		return nil, nil, false
	}
	switch {
	case matchingConn == nil && current != nil:
		unlock()
		h.JSONError(w, http.StatusConflict, "connection_already_assigned", "Client is already assigned to another user")
		return nil, nil, false
	case matchingConn != nil && (current == nil || current.ID != matchingConn.ID):
		unlock()
		h.JSONError(w, http.StatusConflict, "connection_changed", "Connection ownership changed; retry the request")
		return nil, nil, false
	}

	sourceUserID := ""
	if current != nil {
		sourceUserID = current.UserID
	}
	destUserID := *req.UserID
	unlockUsers := h.lockConnectionUsers(sourceUserID, destUserID)
	unlock = func() {
		unlockUsers()
		unlockClient()
	}

	if sourceUserID != "" && destUserID != "" && sourceUserID != destUserID {
		fresh, err := h.db.GetConnection(ctx, current.ID)
		if err != nil {
			unlock()
			h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to verify connection ownership")
			return nil, nil, false
		}
		if fresh == nil || fresh.UserID != sourceUserID {
			unlock()
			h.JSONError(w, http.StatusConflict, "connection_changed", "Connection ownership changed; retry the request")
			return nil, nil, false
		}
		current = fresh
	}

	if !h.validateConnectionDestination(w, ctx, destUserID) {
		unlock()
		return nil, nil, false
	}
	return current, unlock, true
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

	protoMgr, err := h.GetProtocolManager(req.Protocol)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", err.Error())
		return
	}

	// Update AWG speed limits / parameters if applicable
	if err := h.editAWGParams(ctx, server, &req); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "operation_failed", "Failed to edit client on server: "+err.Error())
		return
	}

	// Update DB user connection binding
	matchingConn, err := h.findClientConnection(ctx, serverID, req.Protocol, req.ClientID)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to retrieve connections")
		return
	}

	if req.UserID != nil {
		var unlock func()
		var ok bool
		if matchingConn, unlock, ok = h.lockAssignment(w, ctx, serverID, &req, matchingConn, protoMgr, server); !ok {
			return
		}
		defer unlock()
	} else {
		unlockClient := lockClient(serverID, req.Protocol, req.ClientID)
		defer unlockClient()
		matchingConn, err = h.findClientConnection(ctx, serverID, req.Protocol, req.ClientID)
		if err != nil {
			h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to retrieve connections")
			return
		}
		if matchingConn == nil {
			h.JSONError(w, http.StatusNotFound, "connection_not_found", "Connection record not found")
			return
		}

		unlockUser := h.lockUser(matchingConn.UserID)
		defer unlockUser()
		current, err := h.db.GetConnection(ctx, matchingConn.ID)
		if err != nil {
			h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to verify connection ownership")
			return
		}
		if current == nil {
			h.JSONError(w, http.StatusNotFound, "connection_not_found", "Connection record not found")
			return
		}
		if current.UserID != matchingConn.UserID {
			h.JSONError(w, http.StatusConflict, "connection_changed", "Connection ownership changed; retry the request")
			return
		}
		matchingConn = current
	}

	if err := h.editConnectionBinding(ctx, serverID, &req, matchingConn); err != nil {
		if errors.Is(err, errClientAlreadyAssigned) {
			h.JSONError(w, http.StatusConflict, "connection_already_assigned", "Client is already assigned to another user")
			return
		}
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to update connection binding: "+err.Error())
		return
	}

	h.audit(r, "server_connection.edit", map[string]any{"server_id": serverID, "protocol": req.Protocol, "client_id": req.ClientID, "user_id": req.UserID, "name": req.Name})
	h.JSONOK(w)
}
