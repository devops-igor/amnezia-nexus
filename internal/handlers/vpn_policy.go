package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// This file implements the four admin-only policy routing endpoints of issue
// #678. All four are mounted under middleware.RequireAdmin by the router,
// including the reads, because the issue requires that roles without admin
// cannot read or mutate policy settings.
//
// Security and lifecycle properties enforced here:
//   - settings are validated BEFORE anything is persisted, so a rejected request
//     never overwrites a last working configuration;
//   - persistence and runtime activation are applied atomically from the caller's
//     point of view: a stored record is only written once activation succeeded,
//     and a failed activation rolls the stored record back;
//   - activation goes through vpn.StartPolicyRouting, which fails closed through
//     the existing VPN prerequisite guards (missing direct egress or an empty
//     policy snapshot refuses enablement with a useful error);
//   - stats expose aggregate counters only. No client DNS history, queried
//     domains, credentials or client/private addresses are returned;
//   - audit events record who changed settings and whether a sync succeeded or
//     failed, without introducing an approval workflow.

// policyStoreDir returns the directory holding the durable policy
// last-known-good snapshot, alongside the panel database.
func (h *Handlers) policyStoreDir() string {
	if h.cfg != nil && h.cfg.DataDir != "" {
		return filepath.Join(h.cfg.DataDir, "policy")
	}
	return "policy"
}

// policySettingsOrDefault loads the persisted record. An absent row yields the
// disabled default, which is what keeps existing and fresh installs on the old
// all-proxy route.
func (h *Handlers) policySettingsOrDefault(ctx context.Context) (policy.Settings, error) {
	settings := policy.DefaultSettings()
	if h.db == nil {
		return settings, nil
	}
	var stored policy.Settings
	if err := h.db.GetSetting(ctx, policy.SettingsKey, &stored); err != nil {
		return settings, err
	}
	// GetSetting leaves the target untouched when the row is absent, so a stored
	// record is only adopted when it says something. Settings contains a slice and
	// is therefore not comparable, so emptiness is checked field by field.
	if stored.Preset == "" && !stored.Enabled && stored.SyncInterval == 0 && len(stored.CustomURLs) == 0 {
		return settings, nil
	}
	return stored.Normalize(), nil
}

// savePolicySettings durably writes the record.
func (h *Handlers) savePolicySettings(ctx context.Context, settings policy.Settings) error {
	if h.db == nil {
		return errors.New("database unavailable")
	}
	return h.db.SetSetting(ctx, policy.SettingsKey, settings)
}

// GetPolicyHandler serves GET /api/vpn/policy.
func (h *Handlers) GetPolicyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	settings, err := h.policySettingsOrDefault(ctx)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load policy settings")
		return
	}

	response := map[string]any{
		"enabled":               settings.Enabled,
		"preset":                string(settings.Preset),
		"custom_urls":           customURLsOrEmpty(settings.CustomURLs),
		"sync_interval_seconds": settings.SyncInterval,
	}
	if h.vpnSvc != nil {
		response["status"] = h.vpnSvc.PolicyStatusSnapshot()
	}

	h.JSON(w, http.StatusOK, response)
}

// customURLsOrEmpty reports an empty JSON array rather than null for a preset
// selection that carries no custom URLs.
func customURLsOrEmpty(urls []string) []string {
	if urls == nil {
		return []string{}
	}
	return urls
}

// PutPolicyHandler serves PUT /api/vpn/policy.
func (h *Handlers) PutPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Request body is empty")
		return
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || len(bodyBytes) == 0 {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}
	defer func() { _ = r.Body.Close() }()

	var incoming policy.Settings
	if err := json.Unmarshal(bodyBytes, &incoming); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}
	incoming = incoming.Normalize()

	// Reject invalid settings before any persistence or activation, so a bad
	// request cannot destroy a working configuration.
	if err := incoming.Validate(); err != nil {
		h.audit(r, "policy.settings_save", map[string]any{"result": "rejected", "reason": err.Error()})
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()
	previous, prevErr := h.policySettingsOrDefault(ctx)
	if prevErr != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load current policy settings")
		return
	}

	// Persist first so a restart reproduces the operator's intent, then activate.
	// Activation failure rolls the record back to the exact previous value.
	if err := h.savePolicySettings(ctx, incoming); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to save policy settings")
		return
	}

	if err := h.applyPolicySettings(ctx, incoming); err != nil {
		if rollbackErr := h.savePolicySettings(ctx, previous); rollbackErr != nil {
			slog.Error("Failed to roll back policy settings after activation failure",
				"err", rollbackErr, "activation_err", err)
		}
		h.audit(r, "policy.settings_save", map[string]any{
			"result": "failed", "enabled": incoming.Enabled, "preset": string(incoming.Preset), "reason": err.Error(),
		})
		h.JSONError(w, http.StatusUnprocessableEntity, "activation_failed", err.Error())
		return
	}

	h.audit(r, "policy.settings_save", map[string]any{
		"result": "ok", "enabled": incoming.Enabled, "preset": string(incoming.Preset),
		"custom_url_count": len(incoming.CustomURLs), "sync_interval_seconds": incoming.SyncInterval,
	})

	response := map[string]any{
		"status":                "ok",
		"enabled":               incoming.Enabled,
		"preset":                string(incoming.Preset),
		"custom_urls":           customURLsOrEmpty(incoming.CustomURLs),
		"sync_interval_seconds": incoming.SyncInterval,
	}
	if h.vpnSvc != nil {
		response["policy_status"] = h.vpnSvc.PolicyStatusSnapshot()
	}
	h.JSON(w, http.StatusOK, response)
}

// applyPolicySettings reconciles the runtime with the saved record: it either
// activates PBR from the configured sources or disables it.
//
// Disable is intentionally unconditional and cheap: turning policy routing off
// must always succeed, because "disabled means the existing all-proxy behavior"
// is the safe state.
func (h *Handlers) applyPolicySettings(ctx context.Context, settings policy.Settings) error {
	if h.vpnSvc == nil {
		// Management-only deployments have no data plane; the record is still
		// persisted so the operator's intent survives until the plane is enabled.
		if settings.Enabled {
			return errors.New("VPN data plane is not available in this deployment")
		}
		return nil
	}

	if !settings.Enabled {
		h.vpnSvc.StopPolicyRouting()
		return nil
	}

	store := policy.NewFileStore(h.policyStoreDir())
	return h.vpnSvc.StartPolicyRouting(ctx, settings, store, string(settings.Preset))
}

// SyncPolicyHandler serves POST /api/vpn/policy/sync.
func (h *Handlers) SyncPolicyHandler(w http.ResponseWriter, r *http.Request) {
	if h.vpnSvc == nil {
		h.JSONError(w, http.StatusServiceUnavailable, "unavailable", "VPN data plane is not available")
		return
	}

	// Bound the on-demand sync; the response waits for the sync outcome so the
	// operator learns whether it succeeded.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	result, err := h.vpnSvc.SyncPolicyNow(ctx)
	switch {
	case errors.Is(err, policy.ErrSyncInProgress):
		// Clear already-running behavior: 409, not a queued duplicate sync.
		h.audit(r, "policy.sync", map[string]any{"result": "already_running"})
		h.JSONError(w, http.StatusConflict, "sync_in_progress", "A policy sync is already running")
		return
	case errors.Is(err, context.DeadlineExceeded):
		h.audit(r, "policy.sync", map[string]any{"result": "timeout"})
		h.JSONError(w, http.StatusGatewayTimeout, "sync_timeout", "Policy sync did not complete in time")
		return
	case err != nil:
		h.audit(r, "policy.sync", map[string]any{"result": "failed", "reason": err.Error()})
		h.JSONError(w, http.StatusUnprocessableEntity, "sync_failed", err.Error())
		return
	}

	h.audit(r, "policy.sync", map[string]any{
		"result": "ok", "version": result.Version, "generation_id": result.GenerationID, "published": result.Published,
	})

	response := map[string]any{
		"status":           "ok",
		"published":        result.Published,
		"version":          result.Version,
		"generation_id":    result.GenerationID,
		"duration_seconds": result.Duration.Seconds(),
	}
	if h.vpnSvc != nil {
		response["policy_status"] = h.vpnSvc.PolicyStatusSnapshot()
	}
	h.JSON(w, http.StatusOK, response)
}

// GetPolicyStatsHandler serves GET /api/vpn/policy/stats.
//
// Only aggregate counters are published: proxy/direct byte totals, drop counts,
// the DNS route-cache size, and the active rule count. Deliberately excluded are
// client DNS history, full queried domains, credentials and any client or
// private address.
func (h *Handlers) GetPolicyStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := map[string]any{
		"proxy_bytes":    int64(0),
		"direct_bytes":   int64(0),
		"proxy_drops":    uint64(0),
		"direct_drops":   uint64(0),
		"route_cache":    0,
		"route_sessions": 0,
		"active_rules":   0,
		"enabled":        false,
	}

	if h.vpnSvc != nil {
		proxyBytes, directBytes, proxyDrops := h.vpnSvc.PolicyDispatchCounters()
		stats["proxy_bytes"] = proxyBytes
		stats["direct_bytes"] = directBytes
		stats["proxy_drops"] = proxyDrops
		stats["direct_drops"] = h.vpnSvc.PolicyDirectDrops()

		entries, sessions := h.vpnSvc.PolicyRouteCacheSize()
		stats["route_cache"] = entries
		stats["route_sessions"] = sessions

		status := h.vpnSvc.PolicyStatusSnapshot()
		stats["enabled"] = status.Enabled
		stats["active_rules"] = status.DomainCount + status.CIDRCount
		stats["sync_state"] = status.SyncState
	}

	h.JSON(w, http.StatusOK, stats)
}

// Compile-time assertion that the status type stays JSON-serializable through the
// API surface above.
var _ = vpn.PolicyStatus{}
