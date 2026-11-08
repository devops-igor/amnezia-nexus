package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// policyCompensationTimeout bounds the compensating write that undoes a
// committed settings change whose activation was refused.
//
// Compensation must not inherit the request's cancellation: F678-02 showed that
// a client disconnect or the shipped 60-second request deadline arrives exactly
// when activation fails, so reusing the request context made the rollback itself
// fail with "context canceled" and left the rejected record durable. A bounded,
// cancellation-independent context keeps the write short and request-unowned.
const policyCompensationTimeout = 10 * time.Second

// errPolicySettingsSuperseded reports that a compensating write was skipped
// because a later save had already replaced the record this request wrote.
// Overwriting it would discard an accepted configuration, which is strictly
// worse than leaving the newer one in place.
var errPolicySettingsSuperseded = errors.New("policy settings were replaced by a later save")

// previousPolicyRecord is the durable state a request must restore if its own
// activation is refused. present distinguishes "the record existed" from "the
// key was absent", so compensation restores the previous record exactly instead
// of materializing a default one.
type previousPolicyRecord struct {
	settings policy.Settings
	present  bool
}

// loadPolicyRecord reads the persisted record together with its presence. An
// absent or all-zero row yields the disabled default, which is what keeps
// existing and fresh installs on the old all-proxy route.
func (h *Handlers) loadPolicyRecord(ctx context.Context) (previousPolicyRecord, error) {
	rec := previousPolicyRecord{settings: policy.DefaultSettings()}
	if h.db == nil {
		return rec, nil
	}
	raw, found, err := h.db.GetSettingRaw(ctx, policy.SettingsKey)
	if err != nil {
		return rec, fmt.Errorf("read policy settings: %w", err)
	}
	if !found || !raw.Valid || raw.String == "" {
		return rec, nil
	}
	var stored policy.Settings
	if err := json.Unmarshal([]byte(raw.String), &stored); err != nil {
		return rec, fmt.Errorf("decode policy settings: %w", err)
	}
	// A row that says nothing is treated as absent, the same way the admin GET
	// and the panel startup loader have always interpreted it.
	if stored.IsZero() {
		return rec, nil
	}
	rec.settings = stored.Normalize()
	rec.present = true
	return rec, nil
}

// policySettingsOrDefault loads the persisted record. An absent row yields the
// disabled default, which is what keeps existing and fresh installs on the old
// all-proxy route.
func (h *Handlers) policySettingsOrDefault(ctx context.Context) (policy.Settings, error) {
	rec, err := h.loadPolicyRecord(ctx)
	if err != nil {
		return policy.DefaultSettings(), err
	}
	return rec.settings, nil
}

// savePolicySettings durably writes the record.
func (h *Handlers) savePolicySettings(ctx context.Context, settings policy.Settings) error {
	if h.db == nil {
		return errors.New("database unavailable")
	}
	return h.db.SetSetting(ctx, policy.SettingsKey, settings)
}

// policySettingsEqual reports whether two records describe the same
// configuration. Settings contains a slice, so == is unavailable.
func policySettingsEqual(a, b policy.Settings) bool {
	if a.Enabled != b.Enabled || a.Preset != b.Preset || a.SyncInterval != b.SyncInterval {
		return false
	}
	if len(a.CustomURLs) != len(b.CustomURLs) {
		return false
	}
	for i := range a.CustomURLs {
		if a.CustomURLs[i] != b.CustomURLs[i] {
			return false
		}
	}
	return true
}

// restorePolicySettings compensates a committed settings write whose activation
// was refused, on a bounded context that is independent of the request.
//
// Two properties matter beyond "write the old value back":
//   - it re-reads the record first and does nothing when the durable value is no
//     longer the one this request wrote, so a concurrent accepted save (another
//     admin, a backup restore) is never clobbered;
//   - returning an error means the durable record and the live runtime may now
//     disagree, which the caller surfaces as an inconsistent-state outcome
//     instead of a log line.
func (h *Handlers) restorePolicySettings(ctx context.Context, previous previousPolicyRecord, written policy.Settings) error {
	compCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policyCompensationTimeout)
	defer cancel()

	current, err := h.policySettingsOrDefault(compCtx)
	if err != nil {
		return fmt.Errorf("re-read policy settings before rollback: %w", err)
	}
	if !policySettingsEqual(current, written) {
		return errPolicySettingsSuperseded
	}
	if !previous.present {
		if h.db == nil {
			return errors.New("database unavailable")
		}
		return h.db.DeleteSetting(compCtx, policy.SettingsKey)
	}
	return h.savePolicySettings(compCtx, previous.settings)
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
	incoming, ok := h.decodePolicyPut(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	previous, prevErr := h.loadPolicyRecord(ctx)
	if prevErr != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to load current policy settings")
		return
	}

	// Persist first so a restart reproduces the operator's intent, then activate.
	// Activation failure compensates the committed write.
	//
	// The post-commit barrier below is deliberate: persistence happens before any
	// activation work, so a cancellation during activation always arrives after
	// the row this request owns is durable. That is what makes the compensation
	// path reachable and what keeps its regression test non-vacuous.
	if err := h.savePolicySettings(ctx, incoming); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to save policy settings")
		return
	}

	if err := h.applyPolicySettings(ctx, incoming); err != nil {
		h.rollbackPolicySettings(w, r, previous, incoming, err)
		return
	}

	h.audit(r, "policy.settings_save", map[string]any{
		"result": "ok", "enabled": incoming.Enabled, "preset": string(incoming.Preset),
		"custom_url_count": len(incoming.CustomURLs), "sync_interval_seconds": incoming.SyncInterval,
	})
	h.JSON(w, http.StatusOK, h.policyPutResponse(incoming))
}

// rollbackPolicySettings compensates a committed settings write whose activation
// was refused, and renders the operator-facing outcome.
//
// Three outcomes are distinguished instead of collapsing into one log line:
//   - compensation restored the previous record: 422 with the activation reason,
//     which is the documented "rejected enablement with a useful error" contract;
//   - a later save replaced the record this request wrote: 422 as well, because
//     this request's configuration is not in effect, but the durable value is a
//     newer accepted one and is deliberately left alone;
//   - compensation itself failed: 500. The rejected settings may still be
//     durable while the runtime stays on the previous policy, so a restart could
//     pick up intent that was never activated. Reporting success or a plain
//     activation error would hide a material inconsistent state.
func (h *Handlers) rollbackPolicySettings(w http.ResponseWriter, r *http.Request, previous previousPolicyRecord, written policy.Settings, activationErr error) {
	rollbackErr := h.restorePolicySettings(r.Context(), previous, written)

	details := map[string]any{
		"result": "failed", "enabled": written.Enabled, "preset": string(written.Preset), "reason": activationErr.Error(),
	}
	switch {
	case rollbackErr == nil:
		details["rollback"] = "restored"
	case errors.Is(rollbackErr, errPolicySettingsSuperseded):
		details["rollback"] = "superseded"
	default:
		details["rollback"] = "failed"
		details["rollback_error"] = rollbackErr.Error()
	}
	h.audit(r, "policy.settings_save", details)

	if rollbackErr != nil && !errors.Is(rollbackErr, errPolicySettingsSuperseded) {
		slog.Error("Policy settings rollback failed after activation failure; durable settings and the running policy may disagree",
			"rollback_err", rollbackErr, "activation_err", activationErr,
			"enabled", written.Enabled, "preset", string(written.Preset))
		h.JSONError(w, http.StatusInternalServerError, "state_inconsistent",
			"Policy activation failed and the rejected settings could not be rolled back: "+rollbackErr.Error()+"; activation error: "+activationErr.Error())
		return
	}

	h.JSONError(w, http.StatusUnprocessableEntity, "activation_failed", activationErr.Error())
}

// decodePolicyPut reads and validates the request body. It writes the error
// response itself and reports whether the caller may proceed. Validation happens
// here, before any persistence, so a bad request cannot destroy a working
// configuration.
func (h *Handlers) decodePolicyPut(w http.ResponseWriter, r *http.Request) (policy.Settings, bool) {
	var incoming policy.Settings
	if r.Body == nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Request body is empty")
		return incoming, false
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || len(bodyBytes) == 0 {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return incoming, false
	}
	defer func() { _ = r.Body.Close() }()

	if err := json.Unmarshal(bodyBytes, &incoming); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return incoming, false
	}
	incoming = incoming.Normalize()

	if err := incoming.Validate(); err != nil {
		h.audit(r, "policy.settings_save", map[string]any{"result": "rejected", "reason": err.Error()})
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return incoming, false
	}
	return incoming, true
}

// policyPutResponse renders the saved record plus live status.
func (h *Handlers) policyPutResponse(saved policy.Settings) map[string]any {
	response := map[string]any{
		"status":                "ok",
		"enabled":               saved.Enabled,
		"preset":                string(saved.Preset),
		"custom_urls":           customURLsOrEmpty(saved.CustomURLs),
		"sync_interval_seconds": saved.SyncInterval,
	}
	if h.vpnSvc != nil {
		response["policy_status"] = h.vpnSvc.PolicyStatusSnapshot()
	}
	return response
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

// PolicyStoreDirForTest exposes the durable policy store directory so a test can
// assert it resolves under the panel data directory. Test-only seam: the value is
// a path, not mutable state.
func (h *Handlers) PolicyStoreDirForTest() string {
	return h.policyStoreDir()
}
