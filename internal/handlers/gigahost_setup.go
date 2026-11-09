package handlers

// Durable administrator-approved setup intents.
//
// The installer workflow itself is not part of this file: approving setup
// records what the administrator explicitly asked for and hands the provider
// tracking to a background worker, so provisioning survives a closed browser and
// a panel restart. When the provider server is ready the intent settles into
// ready_for_setup, awaiting_credentials or awaiting_host_confirmation and stops
// there. Nothing here installs a protocol or enables a backend.
//
// The approval requires a real order of this provider: the intent is bound to the
// order id recorded by the purchase path, and an approval that names an order the
// ledger does not have is refused rather than creating a job with no order.
//
// No credential material is stored. The intent records only the reference kind
// (managed or manual) and, when the administrator supplied one, the exact SSH
// host fingerprint they confirmed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
)

// GigahostSetupApproveRequest is the explicit approval payload.
type GigahostSetupApproveRequest struct {
	// Protocol is the selected protocol; it is recorded, not defaulted.
	Protocol      string `json:"protocol"`
	Port          string `json:"port,omitempty"`
	TLSDomain     string `json:"tls_domain,omitempty"`
	EngineProfile string `json:"engine_profile,omitempty"`
	// ExpectedFingerprint is the SSH host identity the administrator confirmed.
	// Empty means "not confirmed yet", which pauses at handoff.
	ExpectedFingerprint string `json:"expected_fingerprint,omitempty"`
	// UseOrderCredential declares that the order already carries the managed
	// credential setup will use.
	UseOrderCredential bool `json:"use_order_credential,omitempty"`
}

// validate rejects an approval that could not describe a real setup job.
//
// The protocol must be explicit and supported: the pre-existing deploy path
// defaults a missing protocol to awg, but a durable approved intent is the
// administrator's own statement of what to install, so a default here would
// record a choice nobody made.
func (r *GigahostSetupApproveRequest) validate() error {
	proto := strings.TrimSpace(r.Protocol)
	if proto == "" {
		return errors.New("protocol is required: approve an explicit protocol (awg, vless, naive)")
	}
	if !models.IsValidProtocol(proto) {
		return fmt.Errorf("unsupported protocol %q: must be awg, vless, or naive", proto)
	}
	if fp := strings.TrimSpace(r.ExpectedFingerprint); fp != "" {
		if err := validateFingerprintFormat(fp); err != nil {
			return fmt.Errorf("expected_fingerprint: %w", err)
		}
	}
	return nil
}

// credentialMode reports which credential reference the approval asserts.
func (r *GigahostSetupApproveRequest) credentialMode() string {
	if r.UseOrderCredential {
		return models.SetupCredentialManaged
	}
	return models.SetupCredentialManual
}

// GigahostSetupApproveHandler handles POST /api/admin/hosting/gigahost/orders/{order_id}/setup-approval.
func (h *Handlers) GigahostSetupApproveHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

	orderID := strings.TrimSpace(chi.URLParam(r, "order_id"))
	var req GigahostSetupApproveRequest
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req); err != nil {
			h.JSONError(w, http.StatusBadRequest, "invalid_payload", "Failed to parse request JSON")
			return
		}
	}

	intent, created, err := h.ApproveGigahostSetup(r.Context(), orderID, req, sess.UserID)
	h.writeSetupIntentResult(w, intent, created, err)
}

// GigahostSetupCancelHandler handles DELETE /api/admin/hosting/gigahost/orders/{order_id}/setup-approval.
func (h *Handlers) GigahostSetupCancelHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}
	orderID := strings.TrimSpace(chi.URLParam(r, "order_id"))

	intent, changed, err := h.CancelGigahostSetup(r.Context(), orderID)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	if intent == nil {
		h.JSONError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("no setup approval is recorded for order %s", orderID))
		return
	}
	h.JSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"changed": changed,
		"setup":   intent,
	})
}

// GigahostSetupStatusHandler handles GET /api/admin/hosting/gigahost/orders/{order_id}/setup-approval.
func (h *Handlers) GigahostSetupStatusHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}
	orderID := strings.TrimSpace(chi.URLParam(r, "order_id"))

	intent, found, err := h.GetGigahostSetupIntent(r.Context(), orderID)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	if !found {
		h.JSONError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("no setup approval is recorded for order %s", orderID))
		return
	}
	h.JSONOK(w, map[string]any{"setup": intent})
}

// GigahostSetupIntentsHandler handles GET /api/admin/hosting/gigahost/setup-intents,
// the administrator's view of saved setup work without any browser open.
func (h *Handlers) GigahostSetupIntentsHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}
	intents, err := h.ListGigahostSetupIntents(r.Context())
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	h.JSONOK(w, map[string]any{
		"setup_intents": intents,
		"count":         len(intents),
	})
}

// ApproveGigahostSetup records the administrator's setup approval for an order.
//
// The approval is refused when the order is not in the ledger: an intent with no
// order would be a job whose provider side nobody placed, and the tracker would
// poll for it forever.
//
// A repeated approval is answered with the existing intent and created=false
// rather than a second job, because provisioning may already be in progress and a
// second tracker would double the provider reads and race the progress.
func (h *Handlers) ApproveGigahostSetup(
	ctx context.Context, orderID string, req GigahostSetupApproveRequest, approvedBy string,
) (*models.GigahostSetupIntent, bool, error) {
	if err := req.validate(); err != nil {
		return nil, false, newSetupValidationError(err.Error())
	}
	if h.db == nil {
		return nil, false, errors.New("database not available")
	}

	order, err := h.loadApprovableOrder(ctx, orderID)
	if err != nil {
		return nil, false, err
	}

	intent := buildSetupIntent(orderID, order, req, approvedBy)
	if err := h.db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		if !errors.Is(err, database.ErrSetupIntentExists) {
			return nil, false, err
		}
		// An approval already exists. Answering with it is what makes a repeated
		// or concurrent approval idempotent instead of a second job racing the
		// first one's progress writes.
		existing, foundExisting, getErr := h.GetGigahostSetupIntent(ctx, orderID)
		if getErr != nil {
			return nil, false, getErr
		}
		if !foundExisting {
			return nil, false, err
		}
		return existing, false, nil
	}
	h.nudgeSetupTracker()
	return intent, true, nil
}

// loadApprovableOrder resolves the placed order an approval may reference.
//
// Both refusals here exist so no job can be created whose provider side nobody
// placed: an unknown id has no order, and a placeholder id (an unresolved intent
// or an unknown purchase outcome) has no confirmed provider order.
func (h *Handlers) loadApprovableOrder(ctx context.Context, orderID string) (*models.GigahostOrder, error) {
	if strings.TrimSpace(orderID) == "" {
		return nil, newSetupValidationError("order_id is required")
	}
	if isSyntheticOrderID(orderID) {
		return nil, newSetupValidationError(fmt.Sprintf(
			"order %s has no confirmed provider order; setup cannot be approved for it", orderID))
	}
	order, found, err := h.db.GetGigahostOrder(ctx, orderID)
	if err != nil {
		return nil, fmt.Errorf("failed to read gigahost order %s: %w", orderID, err)
	}
	if !found {
		return nil, newSetupValidationError(fmt.Sprintf(
			"order %s is not recorded; setup can only be approved for a placed order", orderID))
	}
	return order, nil
}

// buildSetupIntent assembles the approval, carrying forward provider identity the
// ledger already knows.
func buildSetupIntent(
	orderID string, order *models.GigahostOrder, req GigahostSetupApproveRequest, approvedBy string,
) *models.GigahostSetupIntent {
	now := time.Now().UTC()
	intent := &models.GigahostSetupIntent{
		OrderID:         orderID,
		Protocol:        models.NormalizeProtocol(strings.TrimSpace(req.Protocol)),
		Port:            strings.TrimSpace(req.Port),
		TLSDomain:       strings.TrimSpace(req.TLSDomain),
		EngineProfile:   strings.TrimSpace(req.EngineProfile),
		CredentialMode:  req.credentialMode(),
		State:           models.SetupStatePending,
		Step:            "approved",
		HostFingerprint: strings.TrimSpace(req.ExpectedFingerprint),
		NextAttemptAt:   now,
		ApprovedBy:      approvedBy,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if order != nil {
		intent.ProviderServerID = order.ServerID
		intent.AssignedIP = strings.TrimSpace(order.AssignedIP)
		if intent.Port == "" {
			intent.Port = defaultSetupPort(intent.Protocol)
		}
	}
	return intent
}

// defaultSetupPort mirrors the existing deploy default for the recorded protocol.
// It is only reached when the approval omitted a port, and it is written into the
// durable record so the handoff cannot disagree with what was approved.
func defaultSetupPort(protocol string) string {
	switch models.NormalizeProtocol(protocol) {
	case models.ProtocolVLESS, models.ProtocolNaive:
		return "443"
	default:
		return "51820"
	}
}

// isSyntheticOrderID reports the ledger's placeholder order ids: an intent a
// purchase never resolved, or an unknown purchase outcome. Neither is a provider
// order, so neither can be set up.
func isSyntheticOrderID(orderID string) bool {
	return strings.HasPrefix(orderID, "intent_") || strings.HasPrefix(orderID, "unknown_")
}

// CancelGigahostSetup revokes the approval for an order.
func (h *Handlers) CancelGigahostSetup(
	ctx context.Context, orderID string,
) (*models.GigahostSetupIntent, bool, error) {
	if strings.TrimSpace(orderID) == "" {
		return nil, false, newSetupValidationError("order_id is required")
	}
	if h.db == nil {
		return nil, false, errors.New("database not available")
	}
	return h.db.CancelGigahostSetupIntent(ctx, orderID, "setup approval revoked by administrator")
}

// GetGigahostSetupIntent returns the recorded approval for an order.
func (h *Handlers) GetGigahostSetupIntent(
	ctx context.Context, orderID string,
) (*models.GigahostSetupIntent, bool, error) {
	if h.db == nil {
		return nil, false, nil
	}
	return h.db.GetGigahostSetupIntent(ctx, orderID)
}

// ListGigahostSetupIntents returns every recorded approval, newest first.
func (h *Handlers) ListGigahostSetupIntents(ctx context.Context) ([]models.GigahostSetupIntent, error) {
	if h.db == nil {
		return []models.GigahostSetupIntent{}, nil
	}
	return h.db.ListGigahostSetupIntents(ctx)
}

// GigahostSetupResumeHandler handles POST /api/admin/hosting/gigahost/orders/{order_id}/setup-resume.
//
// Resuming is the administrator's decision that a paused job may proceed. It is
// explicit because the alternative - an automatic retry - would re-issue remote
// commands whose outcome was never proven. The handler reports the row's actual
// state when the resume does not apply, so a caller is never told a job resumed
// when it did not.
func (h *Handlers) GigahostSetupResumeHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}
	orderID := strings.TrimSpace(chi.URLParam(r, "order_id"))

	intent, changed, err := h.ResumeGigahostSetup(r.Context(), orderID)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	if intent == nil {
		h.JSONError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("no setup approval is recorded for order %s", orderID))
		return
	}
	if !changed {
		h.JSON(w, http.StatusConflict, map[string]any{
			"status": "not_resumable",
			"error":  "this setup job is not in a state a resume can act on",
			"setup":  intent,
		})
		return
	}
	h.nudgeSetupInstaller()
	h.JSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"resumed": true,
		"setup":   intent,
	})
}

// GigahostSetupConfirmHostHandler handles
// POST /api/admin/hosting/gigahost/orders/{order_id}/setup-host-confirmation.
//
// The confirmation is bound to the exact identity the panel displayed for this
// job, so a later connection presenting a different key is a contradiction rather
// than an accepted host, and a client cannot supply a host the panel never showed.
// The endpoint refuses a malformed fingerprint here as well, because a stored
// malformed value would only fail much later, at the handshake.
//
// A refused confirmation answers 409 with the stored row, so the caller explains
// the real state instead of inferring one.
func (h *Handlers) GigahostSetupConfirmHostHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}
	orderID := strings.TrimSpace(chi.URLParam(r, "order_id"))

	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if r.Body != nil && r.Body != http.NoBody {
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			h.JSONError(w, http.StatusBadRequest, "invalid_payload", "Failed to parse request JSON")
			return
		}
	}
	fingerprint := strings.TrimSpace(req.Fingerprint)
	if err := validateFingerprintFormat(fingerprint); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed",
			"expected_fingerprint must be the canonical SHA256 SSH fingerprint that was displayed")
		return
	}

	intent, changed, err := h.ConfirmGigahostSetupHost(r.Context(), orderID, fingerprint)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	if intent == nil {
		h.JSONError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("no setup approval is recorded for order %s", orderID))
		return
	}
	if !changed {
		h.JSON(w, http.StatusConflict, map[string]any{
			"status": "not_confirmable",
			"error":  "this setup job is not waiting for host confirmation",
			"setup":  intent,
		})
		return
	}
	h.nudgeSetupTracker()
	h.JSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"confirmed":   true,
		"fingerprint": fingerprint,
		"setup":       intent,
	})
}

// ResumeGigahostSetup asks the installer to continue a paused job.
//
// Only states that stopped and asked for a decision are resumable, and the claim
// is a compare-and-set that increments the install generation, so a resume cannot
// revive a completed install, a revocation or a provider terminal failure - and
// it fences out any attempt that was already running.
func (h *Handlers) ResumeGigahostSetup(
	ctx context.Context, orderID string,
) (*models.GigahostSetupIntent, bool, error) {
	if strings.TrimSpace(orderID) == "" {
		return nil, false, newSetupValidationError("order_id is required")
	}
	if h.db == nil {
		return nil, false, errors.New("database not available")
	}
	current, found, err := h.db.GetGigahostSetupIntent(ctx, orderID)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	if !isResumableSetupState(current.State) {
		return current, false, nil
	}
	return h.db.ResumeGigahostSetupInstall(ctx, orderID)
}

// ConfirmGigahostSetupHost records the exact host identity an administrator
// confirmed and re-arms provider tracking.
func (h *Handlers) ConfirmGigahostSetupHost(
	ctx context.Context, orderID, fingerprint string,
) (*models.GigahostSetupIntent, bool, error) {
	if strings.TrimSpace(orderID) == "" {
		return nil, false, newSetupValidationError("order_id is required")
	}
	if h.db == nil {
		return nil, false, errors.New("database not available")
	}
	return h.db.ConfirmGigahostSetupHostFingerprint(ctx, orderID, fingerprint)
}

// isResumableSetupState mirrors the states a resume may act on. It is kept next
// to the handler so the refusal explanation and the database guard cannot drift.
func isResumableSetupState(state string) bool {
	switch state {
	case models.SetupStateReadyForSetup, models.SetupStateAwaitingHostConfirm,
		models.SetupStateAwaitingCredentials, models.SetupStateInstallPaused:
		return true
	default:
		return false
	}
}

// nudgeSetupTracker asks the background worker to run a pass now instead of
// waiting for its next interval, so a fresh approval is observed promptly.
//
// The nudge is a hint, not a mechanism the approval depends on: the interval
// sweep picks the row up regardless, so a nil callback (unit tests, a build
// without the worker) is not a functional gap.
func (h *Handlers) nudgeSetupTracker() {
	if h.setupNudge != nil {
		h.setupNudge()
	}
}

// setupValidationError marks a refusal the client caused, so the handler answers
// 400 rather than reporting a server fault.
type setupValidationError struct{ msg string }

func (e *setupValidationError) Error() string { return e.msg }

func newSetupValidationError(msg string) error { return &setupValidationError{msg: msg} }

// writeSetupIntentResult maps an approval outcome to its HTTP response.
func (h *Handlers) writeSetupIntentResult(
	w http.ResponseWriter, intent *models.GigahostSetupIntent, created bool, err error,
) {
	if err != nil {
		var validation *setupValidationError
		if errors.As(err, &validation) {
			h.JSONError(w, http.StatusBadRequest, "validation_failed", validation.msg)
			return
		}
		h.JSONError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	// A re-approval of an existing intent returns the stored row with 200, so the
	// caller can tell "already approved" from "just approved" by the status code
	// alone, without a second job being created.
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	h.JSON(w, status, map[string]any{
		"status":  "ok",
		"created": created,
		"setup":   intent,
	})
}
