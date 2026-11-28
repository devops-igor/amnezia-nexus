package handlers

// The HTTP surface of immediate Gigahost deployment.
//
// It lives beside the orchestration rather than inside it so the request/response mapping
// - which is a policy about status codes and closed-set codes, not about provisioning -
// stays separable from the steps that touch a host. The two routes that reach it
// (POST /deploy and POST /orders/{order_id}/setup) are one entry: the administrator may be
// looking at either surface, and a guard in one of them would leave the other reachable.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	"github.com/go-chi/chi/v5"
)

// GigahostDeployHandler handles POST /api/admin/hosting/gigahost/deploy.
func (h *Handlers) GigahostDeployHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

	var req GigahostDeployRequest
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req); err != nil {
			h.JSONError(w, http.StatusBadRequest, "invalid_payload", "Failed to parse request JSON")
			return
		}
	}

	if req.OrderID == "" {
		req.OrderID = chi.URLParam(r, "order_id")
	}
	if req.OrderID == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "order_id is required")
		return
	}

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(middleware.InstallRequestTimeout))

	status, err := h.DeployGigahostOrder(r.Context(), req)
	if err != nil {
		h.writeGigahostDeployFailure(w, status, err)
		return
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"deploy": status,
	})
}

// writeGigahostDeployFailure maps a deployment error to its HTTP response.
//
// The first cases are refusals and identity decisions rather than failures: an ended order
// has no deployment left to set up, an unnamed host key must be confirmed by the
// administrator, and a missing managed credential is a pause with instructions. Everything
// else is a real failure, and the ordering below keeps the most specific cause first.
func (h *Handlers) writeGigahostDeployFailure(w http.ResponseWriter, status *GigahostDeployStatus, err error) {
	if errors.Is(err, ErrOrderEnded) {
		// The order the request names is over. It is a refusal, not an upstream fault:
		// the deployment no longer exists at the provider and nothing was attempted, so
		// reporting it as a bad gateway would describe a network problem instead.
		h.JSON(w, http.StatusConflict, map[string]any{
			"status": DeployStatusFailed,
			"code":   orderEndedCode,
			"error":  err.Error(),
			"deploy": status,
		})
		return
	}
	if errors.Is(err, tunnel.ErrProviderAbsent) {
		h.serverNotMeasured(w)
		return
	}
	var confirmation *ssh.ErrFingerprintRequired
	if errors.As(err, &confirmation) {
		h.JSON(w, http.StatusConflict, map[string]any{
			"status":      "host_key_confirmation_required",
			"host":        confirmation.Host,
			"fingerprint": confirmation.Fingerprint,
			"deploy":      status,
		})
		return
	}
	if errors.Is(err, errMissingOrderCredential) {
		h.JSON(w, http.StatusConflict, map[string]any{
			"status": DeployStatusFailed,
			"code":   codeCredentialMissing,
			"error":  errMissingOrderCredential.Error(),
			"deploy": status,
		})
		return
	}
	if errors.Is(err, ErrDuplicateServerID) {
		h.JSONError(w, http.StatusConflict, "duplicate_server_id", err.Error())
		return
	}
	if strings.Contains(err.Error(), "already in progress") {
		h.JSONError(w, http.StatusConflict, "in_progress", err.Error())
		return
	}
	if isDeployValidationError(err) {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	h.JSON(w, http.StatusBadGateway, map[string]any{
		"status": DeployStatusFailed,
		"error":  err.Error(),
		"deploy": status,
	})
}

// isDeployValidationError reports the request-shape failures that must not be
// reported as an upstream fault.
func isDeployValidationError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "validation") || strings.Contains(msg, "required") ||
		strings.Contains(msg, "unsupported protocol")
}

// GigahostDeployStatusHandler handles GET /api/admin/hosting/gigahost/deploy/{order_id}.
func (h *Handlers) GigahostDeployStatusHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

	orderID := chi.URLParam(r, "order_id")
	if orderID == "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "order_id is required")
		return
	}

	status, err := h.GetGigahostDeployStatus(r.Context(), orderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "not found") {
			h.JSONError(w, http.StatusNotFound, "not_found", fmt.Sprintf("order %s not found", orderID))
			return
		}
		h.JSONError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"deploy": status,
	})
}
