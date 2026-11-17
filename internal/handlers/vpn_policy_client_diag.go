package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// This file implements the read-only per-client diagnosis of issue #861:
// GET /api/vpn/policy/clients and POST /api/vpn/policy/client-diagnosis.
//
// Authorization and CSRF are deliberately not re-implemented here. Both routes
// are mounted inside the /api/vpn/policy group, so an unauthenticated caller gets
// the neighboring 401, a support operator the neighboring 403 and a request
// without the CSRF pair the neighboring refusal. They are NOT mounted next to
// GET /api/vpn/sessions, which admins and support share: browsing metadata stays
// admin-only.
//
// Read-only is structural, not a promise: this file reads a request body and
// calls two Service methods that only copy already-retained state. See
// internal/vpn/vpn_pbr_client_diag.go for the per-store argument (no scope
// allocation, no lastSeen refresh, no flow retirement, no observation, no
// resolver).

const (
	// clientDiagnosisMaxBodyBytes bounds the request body. The accepted body is
	// one session id and an optional route generation.
	clientDiagnosisMaxBodyBytes = 4 << 10
	// clientDiagnosisMaxSessionID bounds the session selector. Session ids are
	// UUIDv4 strings, so this is a transport bound, not a format guess.
	clientDiagnosisMaxSessionID = 128
	// clientDiagnosisTimeout bounds the whole request. Every read is in memory,
	// so the deadline exists to stop a wedged caller, not to divide a budget.
	clientDiagnosisTimeout = 5 * time.Second
)

// clientDiagnosisBody is the accepted request body.
type clientDiagnosisBody struct {
	SessionID string `json:"session_id"`
	// RouteGeneration is a pointer so an omitted generation differs from 0.
	// Supplying it pins the incarnation the operator selected.
	RouteGeneration *uint64 `json:"route_generation"`
}

// ClientDiagnosisClientsHandler serves GET /api/vpn/policy/clients.
func (h *Handlers) ClientDiagnosisClientsHandler(w http.ResponseWriter, r *http.Request) {
	if h.vpnSvc == nil {
		h.JSONError(w, http.StatusServiceUnavailable, "unavailable", "VPN data plane is not available")
		return
	}
	h.JSON(w, http.StatusOK, h.vpnSvc.ClientDiagnosisTargets())
}

// ClientDiagnosisHandler serves POST /api/vpn/policy/client-diagnosis.
func (h *Handlers) ClientDiagnosisHandler(w http.ResponseWriter, r *http.Request) {
	if h.vpnSvc == nil {
		h.JSONError(w, http.StatusServiceUnavailable, "unavailable", "VPN data plane is not available")
		return
	}

	req, ok := h.decodeClientDiagnosis(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), clientDiagnosisTimeout)
	defer cancel()

	answer, err := h.vpnSvc.ClientDiagnosis(ctx, req)
	switch {
	case errors.Is(err, vpn.ErrClientDiagnosisBusy):
		// One snapshot at a time. Saying "busy" is truthful and recoverable; it
		// is not a validation failure and not a server error.
		h.JSONError(w, http.StatusTooManyRequests, "busy", "Another client diagnosis snapshot is in flight; retry shortly")
		return
	case errors.Is(err, vpn.ErrClientDiagnosisSessionRequired):
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "session_id is required: select a client session")
		return
	case err != nil:
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to read the client diagnosis")
		return
	}
	h.JSON(w, http.StatusOK, answer)
}

// decodeClientDiagnosis reads and validates the body. It writes the error
// response itself and reports whether the caller may proceed.
func (h *Handlers) decodeClientDiagnosis(w http.ResponseWriter, r *http.Request) (vpn.ClientDiagnosisRequest, bool) {
	if r == nil || r.Body == nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Request body is empty")
		return vpn.ClientDiagnosisRequest{}, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, clientDiagnosisMaxBodyBytes+1))
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return vpn.ClientDiagnosisRequest{}, false
	}
	defer func() { _ = r.Body.Close() }()
	switch {
	case len(raw) == 0:
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Request body is empty")
		return vpn.ClientDiagnosisRequest{}, false
	case len(raw) > clientDiagnosisMaxBodyBytes:
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Request body is too large")
		return vpn.ClientDiagnosisRequest{}, false
	}

	var body clientDiagnosisBody
	if err := json.Unmarshal(raw, &body); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return vpn.ClientDiagnosisRequest{}, false
	}

	out, rejection := buildClientDiagnosisRequest(body)
	if rejection != "" {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", rejection)
		return vpn.ClientDiagnosisRequest{}, false
	}
	return out, true
}

// buildClientDiagnosisRequest validates a decoded body. It is pure so each rule
// can be read and tested on its own.
func buildClientDiagnosisRequest(body clientDiagnosisBody) (vpn.ClientDiagnosisRequest, string) {
	out := vpn.ClientDiagnosisRequest{SessionID: strings.TrimSpace(body.SessionID)}
	if out.SessionID == "" {
		return vpn.ClientDiagnosisRequest{}, "session_id is required: select a client session"
	}
	if len(out.SessionID) > clientDiagnosisMaxSessionID {
		return vpn.ClientDiagnosisRequest{}, "session_id is longer than 128 characters"
	}
	if body.RouteGeneration != nil {
		out.RouteGeneration = *body.RouteGeneration
		out.HasRouteGeneration = true
	}
	return out, ""
}
