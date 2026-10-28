package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func matchUser(u *models.User, search, roleFilter string) bool {
	if roleFilter != "" && roleFilter != "all" && strings.ToLower(string(u.Role)) != roleFilter {
		return false
	}
	if search == "" {
		return true
	}
	if strings.Contains(strings.ToLower(u.Username), search) {
		return true
	}
	if u.Email != nil && strings.Contains(strings.ToLower(*u.Email), search) {
		return true
	}
	if u.TelegramID != nil && strings.Contains(strings.ToLower(*u.TelegramID), search) {
		return true
	}
	return strings.Contains(strings.ToLower(string(u.Role)), search)
}

// ListUsersHandler returns a paginated and filtered list of users.
func (h *Handlers) ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
	roleFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("role")))
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	size := 12
	if s, err := strconv.Atoi(r.URL.Query().Get("size")); err == nil && s > 0 && s <= 100 {
		size = s
	}

	ctx := r.Context()
	allUsers, err := h.db.GetAllUsers(ctx)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve users")
		return
	}

	allConns, _ := h.db.GetAllConnections(ctx)
	connsCountMap := make(map[string]int)
	for _, c := range allConns {
		connsCountMap[c.UserID]++
	}

	filtered := make([]models.User, 0)
	for _, u := range allUsers {
		if matchUser(&u, search, roleFilter) {
			filtered = append(filtered, u)
		}
	}

	total := len(filtered)
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}

	items := filtered[start:end]
	userItems := make([]models.UserItemResponse, len(items))
	for i, u := range items {
		source := "Local"

		var expStr, expiresStr *string
		if u.ExpirationDate != nil {
			s := u.ExpirationDate.Format(time.RFC3339)
			expStr = &s
		}
		if u.ExpiresAt != nil {
			s := u.ExpiresAt.Format(time.RFC3339)
			expiresStr = &s
		}

		mimicryStr := string(u.AWGMimicry)
		userItems[i] = models.UserItemResponse{
			ID:                   u.ID,
			Username:             u.Username,
			Role:                 string(u.Role),
			Enabled:              u.Enabled,
			CreatedAt:            u.CreatedAt.Format(time.RFC3339),
			TelegramID:           u.TelegramID,
			Email:                u.Email,
			Description:          u.Description,
			ConnectionsCount:     connsCountMap[u.ID],
			TrafficUsed:          u.TrafficUsed,
			TrafficTotal:         u.TrafficTotal,
			TrafficLimit:         u.TrafficLimit,
			TrafficResetStrategy: string(u.TrafficResetStrategy),
			LastResetAt:          u.LastResetAt,
			ExpirationDate:       expStr,
			ExpiresAt:            expiresStr,
			AWGMimicry:           &mimicryStr,
			ShareEnabled:         u.ShareEnabled,
			ShareToken:           u.ShareToken,
			HasSharePassword:     u.SharePasswordHash != nil && *u.SharePasswordHash != "",
			Source:               source,
		}
	}

	pages := 0
	if size > 0 {
		pages = (total + size - 1) / size
	}

	h.JSON(w, http.StatusOK, models.PaginatedUsersResponse{
		Users: userItems,
		Total: total,
		Page:  page,
		Size:  size,
		Pages: pages,
	})
}

// AddUserHandler creates a new user account and optionally provisions an initial connection.
func (h *Handlers) AddUserHandler(w http.ResponseWriter, r *http.Request) {
	var req models.AddUserRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	if req.Protocol != nil && *req.Protocol != "" && !h.authorizeAdminProtocol(w, r, *req.Protocol) {
		return
	}

	ctx := r.Context()
	existing, err := h.db.GetUserByUsername(ctx, req.Username)
	if err == nil && existing != nil {
		h.JSONError(w, http.StatusBadRequest, "user_exists", h.Translate(r, "user_exists"))
		return
	}

	hash, err := security.HashPassword(req.Password)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to hash password")
		return
	}

	role := req.Role
	if role == "" {
		role = models.RoleUser
	}

	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	shareToken := generateRandomToken(16)

	user := &models.User{
		ID:                     uuid.NewString(),
		Username:               req.Username,
		PasswordHash:           hash,
		Role:                   role,
		Email:                  req.Email,
		TelegramID:             req.TelegramID,
		Description:            req.Description,
		TrafficLimit:           int64(req.TrafficLimit * 1024 * 1024 * 1024),
		TrafficResetStrategy:   models.TrafficResetStrategy(req.TrafficResetStrategy),
		LastResetAt:            &nowStr,
		AWGMimicry:             models.AWGMimicryAuto,
		Enabled:                true,
		ShareEnabled:           false,
		ShareToken:             &shareToken,
		PasswordChangeRequired: false,
		CreatedAt:              now,
	}

	if user.TrafficResetStrategy == "" {
		user.TrafficResetStrategy = models.ResetStrategyNever
	}
	if req.AWGMimicry != nil {
		user.AWGMimicry = models.AWGMimicryProfile(*req.AWGMimicry)
	}
	h.applyUserExpiry(user, req)

	if _, err := h.db.CreateUser(ctx, user); err != nil {
		if errors.Is(err, database.ErrUserAlreadyExists) || strings.Contains(err.Error(), "user already exists") || strings.Contains(err.Error(), "UNIQUE constraint") {
			h.JSONError(w, http.StatusBadRequest, "user_exists", h.Translate(r, "user_exists"))
			return
		}
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to create user")
		return
	}

	resp := map[string]any{
		"status":  "ok",
		"user_id": user.ID,
	}

	h.provisionInitialConnection(ctx, user, req, resp)

	h.audit(r, "user.add", map[string]any{"user_id": user.ID, "username": user.Username, "role": string(user.Role)})
	h.JSON(w, http.StatusOK, resp)
}

// applyUserExpiry parses and applies expiration fields onto a new user.
func (h *Handlers) applyUserExpiry(user *models.User, req models.AddUserRequest) {
	if req.ExpiresAt != nil {
		if t, err := time.Parse(time.RFC3339, *req.ExpiresAt); err == nil {
			user.ExpiresAt = &t
			user.ExpirationDate = &t
		}
		return
	}
	if req.ExpirationDate != nil {
		if t, err := time.Parse(time.RFC3339, *req.ExpirationDate); err == nil {
			user.ExpiresAt = &t
			user.ExpirationDate = &t
		}
	}
}

// provisionInitialConnection auto-creates an initial connection for a new user when requested.
func (h *Handlers) provisionInitialConnection(ctx context.Context, user *models.User, req models.AddUserRequest, resp map[string]any) {
	if req.ServerID == nil || req.Protocol == nil || *req.Protocol == "" {
		return
	}
	defer h.lockUser(user.ID)()
	curUser, err := h.db.GetUser(ctx, user.ID)
	if err != nil || curUser == nil || !curUser.Enabled {
		resp["connection_created"] = false
		resp["connection_error"] = "user is disabled"
		return
	}
	server, err := h.db.GetServer(ctx, *req.ServerID)
	if err != nil || server == nil {
		resp["connection_created"] = false
		if err != nil {
			resp["connection_error"] = err.Error()
		} else {
			resp["connection_error"] = "server not found"
		}
		return
	}
	status, err := h.db.GetServerStatus(ctx, server.ID)
	if (err == nil && status == models.ReachabilityOffline) || server.Status == models.ReachabilityOffline {
		resp["connection_created"] = false
		resp["connection_error"] = "server is currently unavailable or offline"
		return
	}
	protoMgr, err := h.GetProtocolManager(*req.Protocol)
	if err != nil || protoMgr == nil {
		resp["connection_created"] = false
		if err != nil {
			resp["connection_error"] = err.Error()
		} else {
			resp["connection_error"] = "protocol manager not found"
		}
		return
	}

	connName := fmt.Sprintf("%s_vpn", user.Username)
	if req.ConnectionName != nil && *req.ConnectionName != "" {
		connName = *req.ConnectionName
	}
	params := map[string]any{"name": connName}
	if req.AWGMimicry != nil {
		params["awg_mimicry"] = *req.AWGMimicry
	}

	connRes, err := protoMgr.AddClient(ctx, server, params)
	if err != nil {
		resp["connection_created"] = false
		resp["connection_error"] = err.Error()
		return
	}
	clientID, _ := connRes["client_id"].(string)
	if clientID == "" {
		clientID, _ = connRes["clientId"].(string)
	}
	configStr, _ := connRes["config"].(string)
	if configStr == "" && clientID != "" {
		configStr, _ = protoMgr.GetClientConfig(ctx, server, clientID)
	}

	_ = h.db.RecordPeerLifecycle(ctx, server.ID, *req.Protocol, clientID, connName, user.ID, "active")

	newConn := &models.UserConnection{
		ID:         uuid.NewString(),
		UserID:     user.ID,
		ServerID:   server.ID,
		Protocol:   *req.Protocol,
		ClientID:   clientID,
		Name:       connName,
		AWGMimicry: user.AWGMimicry,
		CreatedAt:  time.Now(),
	}
	if status, _, msg := h.persistProvisioned(ctx, protoMgr, server, connRes, newConn); status != 0 {
		resp["connection_created"] = false
		resp["connection_error"] = msg
		return
	}

	resp["connection_created"] = true
	resp["config"] = configStr
	resp["vpn_link"] = GenerateVPNLink(configStr)
}

func applyExpirationUpdate(req *models.UpdateUserRequest, updates map[string]any) {
	if req.ExpiresAt != nil {
		if t, err := time.Parse(time.RFC3339, *req.ExpiresAt); err == nil {
			updates["expires_at"] = t
			updates["expiration_date"] = t
		}
	} else if req.ExpirationDate != nil {
		if t, err := time.Parse(time.RFC3339, *req.ExpirationDate); err == nil {
			updates["expires_at"] = t
			updates["expiration_date"] = t
		}
	}
}

func buildUserUpdates(req *models.UpdateUserRequest) (map[string]any, bool, error) {
	updates := make(map[string]any)
	if req.TelegramID != nil {
		updates["telegramId"] = *req.TelegramID
	}
	if req.Email != nil {
		updates["email"] = *req.Email
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.TrafficLimit != nil {
		updates["traffic_limit"] = int64(*req.TrafficLimit * 1024 * 1024 * 1024)
	}
	if req.TrafficResetStrategy != nil {
		updates["traffic_reset_strategy"] = *req.TrafficResetStrategy
		updates["last_reset_at"] = time.Now().Format(time.RFC3339)
	}
	applyExpirationUpdate(req, updates)
	if req.AWGMimicry != nil {
		updates["awg_mimicry"] = *req.AWGMimicry
	}
	var passwordUpdated bool
	if req.Password != nil && *req.Password != "" {
		hash, err := security.HashPassword(*req.Password)
		if err != nil {
			return nil, false, err
		}
		updates["password_hash"] = hash
		passwordUpdated = true
	}
	return updates, passwordUpdated, nil
}

func (h *Handlers) refreshSelfSessionCookie(w http.ResponseWriter, r *http.Request, userID string, newVer int) error {
	sess := h.GetSession(r)
	if sess != nil && sess.UserID == userID {
		sess.SessionVersion = newVer
		if h.cfg != nil {
			if err := middleware.SetSessionCookieForRequest(w, r, sess, h.cfg.SecretKey, middleware.DefaultSessionMaxAge); err != nil {
				slog.Error("failed to set session cookie on password reset", "error", err, "user_id", userID)
				return err
			}
		}
	}
	return nil
}

// UpdateUserHandler updates user attributes and resets limits if modified.
func (h *Handlers) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "user_id is required")
		return
	}

	var req models.UpdateUserRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()
	user, err := h.db.GetUser(ctx, userID)
	if err != nil || user == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	updates, passwordUpdated, err := buildUserUpdates(&req)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to hash password")
		return
	}

	if passwordUpdated {
		ok, newVer, err := h.db.UpdateUserAndBumpSession(ctx, userID, updates)
		if err != nil {
			h.peerChangeError(w, err)
			return
		}
		if !ok {
			h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		if err := h.refreshSelfSessionCookie(w, r, userID, newVer); err != nil {
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update session cookie")
			return
		}
	} else if len(updates) > 0 {
		ok, err := h.db.UpdateUser(ctx, userID, updates)
		if err != nil {
			h.peerChangeError(w, err)
			return
		}
		if !ok {
			h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
	}

	// The commit only queued the runtime enforcement of this user's access
	// change; confirm it converged before reporting success (issue #391
	// round 4b, finding 4). An access change is exactly the case where a
	// silent unenforced commit would leave a revoked user connected.
	if !h.peerChangeConvergedContext(w, ctx) {
		return
	}

	h.audit(r, "user.update", map[string]any{"user_id": userID, "username": user.Username, "fields": len(updates)})
	h.JSONOK(w)
}

// DeleteUserHandler removes a user and their client connections across all servers.
func (h *Handlers) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "user_id is required")
		return
	}

	sess := h.GetSession(r)
	if sess != nil && sess.UserID == userID {
		h.JSONError(w, http.StatusBadRequest, "cannot_delete_self", h.Translate(r, "cannot_delete_self"))
		return
	}

	// Serialize the connection snapshot, remote revocation and user deletion
	// with provisioning so no new credential can escape the deletion snapshot.
	defer h.lockUser(userID)()

	ctx := r.Context()
	user, err := h.db.GetUser(ctx, userID)
	if err != nil || user == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	// Delete client connections on servers only after their remote credentials
	// are removed, preserving failed records so account deletion can be retried.
	conns, err := h.db.GetConnectionsByUserID(ctx, userID)
	if err != nil {
		h.peerChangeError(w, err)
		return
	}
	for _, c := range conns {
		proto := models.NormalizeProtocol(c.Protocol)
		if proto == models.ProtocolVLESS || proto == models.ProtocolNaive {
			if !h.authorizeAdminProtocol(w, r, proto) {
				return
			}
			break
		}
	}
	for _, c := range conns {
		current, err := h.db.GetConnection(ctx, c.ID)
		if err != nil {
			h.peerChangeError(w, err)
			return
		}
		if current == nil || current.UserID != userID {
			continue
		}
		if err := h.removeRemoteClient(ctx, current); err != nil {
			h.JSONError(w, http.StatusInternalServerError, "remote_removal_failed",
				"Failed to remove remote client credentials: "+err.Error())
			return
		}
		if _, err := h.db.DeleteConnection(ctx, current.ID); err != nil {
			h.peerChangeError(w, err)
			return
		}
		_ = h.db.DeletePeerLifecycle(ctx, current.ServerID, current.Protocol, current.ClientID)
	}

	if _, err := h.db.DeleteUser(ctx, userID); err != nil {
		h.peerChangeError(w, err)
		return
	}
	// The commits only queued the runtime enforcement; confirm the deleted
	// user's live access was actually withdrawn before reporting success
	// (issue #391 round 4b, finding 4). The convergence wait is placed after
	// the user row is gone, so it observes the enforcement of the full
	// deletion rather than a partial one.
	if !h.peerChangeConvergedContext(w, ctx) {
		return
	}
	_ = h.db.DeletePeerLifecycleByUserID(ctx, userID)

	h.audit(r, "user.delete", map[string]any{"user_id": userID, "username": user.Username})
	h.JSONOK(w)
}

// removeRemoteClient revokes a connection's credential on its server. Server-less
// (ServerID 0, load-balanced) connections have no remote credential to remove.
func (h *Handlers) removeRemoteClient(ctx context.Context, c *models.UserConnection) error {
	if c.ServerID == 0 {
		return nil
	}
	server, err := h.db.GetServer(ctx, c.ServerID)
	if err != nil {
		return fmt.Errorf("load server %d: %w", c.ServerID, err)
	}
	if server == nil {
		return fmt.Errorf("server %d not found", c.ServerID)
	}
	protoMgr, err := h.GetProtocolManager(c.Protocol)
	if err != nil {
		return fmt.Errorf("protocol manager %q: %w", c.Protocol, err)
	}
	if protoMgr == nil {
		return fmt.Errorf("protocol manager %q not found", c.Protocol)
	}
	if err := protoMgr.RemoveClient(ctx, server, c.ClientID); err != nil {
		return fmt.Errorf("remove client %q: %w", c.ClientID, err)
	}
	return nil
}

// ToggleUserHandler enables or disables a user and toggles their server client connections.
func (h *Handlers) ToggleUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "user_id is required")
		return
	}

	var req models.ToggleUserRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	// Hold the per-user lock across snapshot, revocation and commit so an in-flight
	// credential creation either lands in the snapshot or sees the user disabled.
	defer h.lockUser(userID)()

	ctx := r.Context()
	user, err := h.db.GetUser(ctx, userID)
	if err != nil || user == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	conns, err := h.db.GetConnectionsByUserID(ctx, userID)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to retrieve user connections")
		return
	}
	if !req.Enabled {
		for i := range conns {
			c := &conns[i]
			proto := models.NormalizeProtocol(c.Protocol)
			if proto == models.ProtocolVLESS || proto == models.ProtocolNaive {
				if !h.authorizeAdminProtocol(w, r, proto) {
					return
				}
				break
			}
		}
		// VLESS/Naive cannot be toggled in place: revoke the remote credential
		// first (fail closed, user stays enabled), then drop the row like userops does.
		for i := range conns {
			c := &conns[i]
			if proto := models.NormalizeProtocol(c.Protocol); proto != models.ProtocolVLESS && proto != models.ProtocolNaive {
				continue
			}
			if err := h.removeRemoteClient(ctx, c); err != nil {
				slog.Error("failed to revoke remote client on user disable", "user_id", userID, "client_id", c.ClientID, "error", err)
				h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to revoke remote client credential")
				return
			}
			if _, err := h.db.DeleteConnection(ctx, c.ID); err != nil {
				h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to delete revoked connection")
				return
			}
			_ = h.db.DeletePeerLifecycle(ctx, c.ServerID, c.Protocol, c.ClientID)
		}
	}

	if _, err := h.db.UpdateUser(ctx, userID, map[string]any{
		"enabled": req.Enabled,
	}); err != nil {
		h.peerChangeError(w, err)
		return
	}
	// Disabling a user revokes access: the commit only queued that
	// enforcement, so confirm it converged before reporting success and
	// before toggling the per-server clients (issue #391 round 4b,
	// finding 4).
	if !h.peerChangeConvergedContext(w, ctx) {
		return
	}

	// Toggle clients on servers
	conns, _ = h.db.GetConnectionsByUserID(ctx, userID)
	for _, c := range conns {
		if c.Protocol == "awg" && h.awgMgr != nil {
			if server, err := h.db.GetServer(ctx, c.ServerID); err == nil && server != nil {
				_ = h.awgMgr.ToggleClient(ctx, server, c.ClientID, req.Enabled)
			}
		}
	}

	h.audit(r, "user.toggle", map[string]any{"user_id": userID, "username": user.Username, "enabled": req.Enabled})
	h.JSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"enabled": req.Enabled,
	})
}

// AddUserConnectionHandler assigns a new or existing connection to a specific user.
func (h *Handlers) AddUserConnectionHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "user_id is required")
		return
	}

	var req models.AddUserConnectionRequest
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

	defer h.lockUser(userID)()

	ctx := r.Context()
	user, err := h.db.GetUser(ctx, userID)
	if err != nil || user == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	if !user.Enabled {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Account is disabled")
		return
	}

	server, err := h.db.GetServer(ctx, req.ServerID)
	if err != nil || server == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "Server not found")
		return
	}

	protoMgr, err := h.GetProtocolManager(req.Protocol)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_protocol", err.Error())
		return
	}

	if !h.checkServerReachable(w, ctx, server) {
		return
	}

	var clientID, configStr string
	var addResult map[string]any
	clientCreated := false
	if req.ClientID != nil && *req.ClientID != "" {
		clientID = *req.ClientID
		configStr, _ = protoMgr.GetClientConfig(ctx, server, clientID)
	} else {
		params := buildConnectionParams(req.Name, req.TelemtQuota, req.TelemtMaxIPs, req.TelemtExpiry, req.AWGMimicry)

		res, err := protoMgr.AddClient(ctx, server, params)
		if err != nil {
			h.JSONError(w, http.StatusInternalServerError, "add_client_failed", "Failed to add client")
			return
		}
		addResult = res
		clientID = resolveClientID(res)
		configStr, _ = res["config"].(string)
		if configStr == "" && clientID != "" {
			configStr, _ = protoMgr.GetClientConfig(ctx, server, clientID)
		}
		clientCreated = true
	}

	vpnLink := GenerateVPNLink(configStr)
	newConn := &models.UserConnection{
		ID:         uuid.NewString(),
		UserID:     userID,
		ServerID:   req.ServerID,
		Protocol:   req.Protocol,
		ClientID:   clientID,
		Name:       req.Name,
		AWGMimicry: user.AWGMimicry,
		CreatedAt:  time.Now(),
	}
	if req.AWGMimicry != nil {
		newConn.AWGMimicry = models.AWGMimicryProfile(*req.AWGMimicry)
	}

	if clientCreated {
		if status, code, msg := h.persistProvisioned(ctx, protoMgr, server, addResult, newConn); status != 0 {
			h.JSONError(w, status, code, msg)
			return
		}
	} else if _, err := h.db.CreateConnection(ctx, newConn); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to save connection record")
		return
	}

	h.audit(r, "user.connection_add", map[string]any{"user_id": userID, "server_id": req.ServerID, "protocol": req.Protocol, "client_id": clientID})
	h.JSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"connection": newConn,
		"config":     configStr,
		"vpn_link":   vpnLink,
	})
}

// GetUserConnectionsHandler lists all connections belonging to a user.
func (h *Handlers) GetUserConnectionsHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "user_id is required")
		return
	}

	sess := h.GetSession(r)
	if sess == nil {
		h.JSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	if sess.Role == models.RoleUser && sess.UserID != userID {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Forbidden")
		return
	}

	ctx := r.Context()
	conns, err := h.db.GetConnectionsByUserID(ctx, userID)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve connections")
		return
	}

	servers, _ := h.db.GetAllServers(ctx)
	serversMap := make(map[int64]string)
	for _, s := range servers {
		serversMap[s.ID] = s.Name
	}

	enriched := make([]map[string]any, len(conns))
	for i, c := range conns {
		srvName := serversMap[c.ServerID]
		if srvName == "" {
			if c.ServerID == 0 {
				srvName = "Cluster (Auto)"
			} else {
				srvName = fmt.Sprintf("Server #%d", c.ServerID)
			}
		}
		clientID := c.ClientID
		connName := c.Name
		if models.NormalizeProtocol(c.Protocol) == models.ProtocolVLESS && sess.Role != models.RoleAdmin {
			clientID = ""
			connName = safeVLESSDisplayName(connName, c.ClientID)
		}
		enriched[i] = map[string]any{
			"id":               c.ID,
			"user_id":          c.UserID,
			"server_id":        c.ServerID,
			"server_name":      srvName,
			"protocol":         c.Protocol,
			"client_id":        clientID,
			"name":             connName,
			"awg_mimicry":      c.AWGMimicry,
			"traffic_total_rx": c.TrafficTotalRx,
			"traffic_total_tx": c.TrafficTotalTx,
			"traffic_total":    c.TrafficTotal,
			"created_at":       c.CreatedAt.Format(time.RFC3339),
		}
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"connections": enriched,
	})
}

// SetupUserShareHandler configures public share link credentials and availability.
func (h *Handlers) SetupUserShareHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		h.JSONError(w, http.StatusBadRequest, "invalid_parameter", "user_id is required")
		return
	}

	var req struct {
		Enabled  *bool   `json:"enabled"`
		Password *string `json:"password"`
	}
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	ctx := r.Context()
	user, err := h.db.GetUser(ctx, userID)
	if err != nil || user == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	updates := make(map[string]any)
	if req.Enabled != nil {
		updates["share_enabled"] = *req.Enabled
	} else {
		updates["share_enabled"] = true
	}

	token := ""
	if user.ShareToken != nil && *user.ShareToken != "" {
		token = *user.ShareToken
	} else {
		token = generateRandomToken(16)
		updates["share_token"] = token
	}

	if req.Password != nil {
		if *req.Password != "" {
			if hash, err := security.HashPassword(*req.Password); err == nil {
				updates["share_password_hash"] = hash
			}
		} else {
			updates["share_password_hash"] = ""
		}
	}

	_, _ = h.db.UpdateUser(ctx, userID, updates)

	h.audit(r, "user.share_setup", map[string]any{"user_id": userID, "username": user.Username, "enabled": updates["share_enabled"]})
	h.JSON(w, http.StatusOK, map[string]any{
		"status":      "success",
		"share_token": token,
	})
}

func generateRandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
