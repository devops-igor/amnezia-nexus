package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/manager/updater"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// populateServerEngineStatus populates EngineStatus on ServerItemResponse for admin users.
// For non-admin and support callers, item.EngineStatus is left nil so it is omitted from JSON.
func (h *Handlers) populateServerEngineStatus(ctx context.Context, item *models.ServerItemResponse, server *models.Server, isAdmin bool) {
	if item == nil {
		return
	}
	if !isAdmin || server == nil {
		item.EngineStatus = nil
		return
	}

	statusMap := h.resolveServerEngineStatus(ctx, server)
	if len(statusMap) == 0 {
		item.EngineStatus = nil
		return
	}
	item.EngineStatus = statusMap
}

// resolveServerEngineStatus inspects installed protocols on the server and checks update status.
func (h *Handlers) resolveServerEngineStatus(ctx context.Context, server *models.Server) map[string]any {
	if server == nil || len(server.Protocols) == 0 {
		return nil
	}

	checker := h.getUpdaterService()
	if checker == nil {
		return nil
	}

	result := make(map[string]any)

	// 1. Xray (models.ProtocolVLESS = "vless")
	if vMeta, ok := getInstalledProtocolMetadata(server.Protocols, models.ProtocolVLESS); ok {
		h.resolveXrayStatus(ctx, checker, vMeta, result)
	}

	// 2. NaiveProxy / Caddy (models.ProtocolNaive = "naive")
	if nMeta, ok := getInstalledProtocolMetadata(server.Protocols, models.ProtocolNaive); ok {
		h.resolveNaiveStatus(ctx, checker, nMeta, result)
	}

	// 3. Optional sing-box (if configured in protocols)
	if sMeta, ok := getInstalledProtocolMetadata(server.Protocols, "sing-box"); ok {
		h.resolveSingBoxStatus(ctx, checker, sMeta, result)
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func (h *Handlers) resolveXrayStatus(ctx context.Context, checker *updater.ReleaseChecker, meta map[string]any, dest map[string]any) {
	profile := extractXrayProfile(meta)
	installedVersion := extractXrayVersion(meta, profile)

	status, err := checker.CheckEngineWithProfile(ctx, updater.EngineXray, installedVersion, profile)
	if err != nil {
		return
	}

	dest[models.ProtocolVLESS] = status
	dest[string(updater.EngineXray)] = status
}

func (h *Handlers) resolveNaiveStatus(ctx context.Context, checker *updater.ReleaseChecker, meta map[string]any, dest map[string]any) {
	// 1. Caddy Core
	caddyVersion := extractCaddyVersion(meta)
	caddyStatus, err := checker.CheckEngine(ctx, updater.EngineCaddyCore, caddyVersion)
	if err == nil {
		dest["caddy"] = caddyStatus
		dest["caddy_core"] = caddyStatus
	}

	// 2. Naive ForwardProxy Plugin
	pluginVersion := extractNaivePluginVersion(meta)
	pluginStatus, err := checker.CheckEngine(ctx, updater.EngineNaiveForwardProxy, pluginVersion)
	if err == nil {
		dest[models.ProtocolNaive] = pluginStatus
		dest["naive"] = pluginStatus
		dest["naive-forwardproxy"] = pluginStatus
		dest["forwardproxy"] = pluginStatus
	}
}

func (h *Handlers) resolveSingBoxStatus(ctx context.Context, checker *updater.ReleaseChecker, meta map[string]any, dest map[string]any) {
	version := ""
	if meta != nil {
		for _, key := range []string{"installed_version", "version", "engine_version"} {
			if v, ok := meta[key].(string); ok && strings.TrimSpace(v) != "" {
				version = strings.TrimSpace(v)
				break
			}
		}
	}
	if version == "" {
		version = "1.9.0"
	}
	status, err := checker.CheckEngine(ctx, updater.EngineSingBox, version)
	if err == nil {
		dest["sing-box"] = status
	}
}

// ServerEngineStatusHandler returns detailed engine update status for all installed protocols on a server.
// Protected under administrator RBAC (models.RoleAdmin).
func (h *Handlers) ServerEngineStatusHandler(w http.ResponseWriter, r *http.Request) {
	session := h.GetSession(r)
	if session == nil || !session.IsAuthenticated() {
		h.JSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	if !session.IsAdmin() {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

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

	engineStatus := h.resolveServerEngineStatus(ctx, server)
	if engineStatus == nil {
		engineStatus = make(map[string]any)
	}

	resp := map[string]any{
		"status":        "ok",
		"server_id":     server.ID,
		"engine_status": engineStatus,
	}
	for k, v := range engineStatus {
		resp[k] = v
	}

	h.JSON(w, http.StatusOK, resp)
}

func (h *Handlers) getUpdaterService() *updater.ReleaseChecker {
	if h.updaterSvc != nil {
		return h.updaterSvc
	}
	return updater.NewReleaseChecker()
}

func getInstalledProtocolMetadata(protocols map[string]any, protocol string) (map[string]any, bool) {
	if protocols == nil {
		return nil, false
	}
	raw, ok := protocols[protocol]
	if !ok {
		for k, v := range protocols {
			if strings.EqualFold(k, protocol) {
				raw = v
				ok = true
				break
			}
		}
	}
	if !ok || raw == nil {
		return nil, false
	}

	switch v := raw.(type) {
	case bool:
		if v {
			return make(map[string]any), true
		}
		return nil, false
	case map[string]any:
		if inst, ok := v["installed"].(bool); ok {
			if !inst {
				return nil, false
			}
			return v, true
		}
		return v, true
	default:
		return nil, false
	}
}

func extractXrayProfile(meta map[string]any) string {
	if meta == nil {
		return "legacy"
	}
	for _, key := range []string{"engine_profile", "engineProfile", "profile"} {
		if p, ok := meta[key].(string); ok && strings.TrimSpace(p) != "" {
			return strings.TrimSpace(p)
		}
	}
	if params, ok := meta["params"].(map[string]any); ok {
		for _, key := range []string{"engine_profile", "engineProfile", "profile"} {
			if p, ok := params[key].(string); ok && strings.TrimSpace(p) != "" {
				return strings.TrimSpace(p)
			}
		}
	}
	for _, key := range []string{"installed_version", "engine_version", "running_engine_version", "version"} {
		if v, ok := meta[key].(string); ok {
			norm := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
			if strings.HasPrefix(norm, "26.") || strings.HasPrefix(norm, "25.") {
				return "modern_pq"
			}
		}
	}
	return "legacy"
}

func extractXrayVersion(meta map[string]any, profile string) string {
	if meta != nil {
		for _, key := range []string{"installed_version", "engine_version", "running_engine_version", "version"} {
			if v, ok := meta[key].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		if params, ok := meta["params"].(map[string]any); ok {
			for _, key := range []string{"installed_version", "engine_version", "running_engine_version", "version"} {
				if v, ok := params[key].(string); ok && strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			}
		}
	}

	norm := strings.ToLower(strings.TrimSpace(profile))
	if norm == "modern_pq" || norm == "modern" || norm == "26.10.29" || norm == "v26.10.29" {
		return "26.10.29"
	}
	return "1.8.24"
}

func extractCaddyVersion(meta map[string]any) string {
	if meta != nil {
		for _, key := range []string{"caddy_version", "caddyVersion", "engine_version", "version"} {
			if v, ok := meta[key].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		if img, ok := meta["caddy_image"].(string); ok && strings.TrimSpace(img) != "" {
			if tag := parseImageTag(img); tag != "" {
				return tag
			}
		}
	}
	return ""
}

func extractNaivePluginVersion(meta map[string]any) string {
	if meta != nil {
		for _, key := range []string{"plugin_version", "pluginVersion", "naive_version", "forwardproxy_version", "naiveVersion"} {
			if v, ok := meta[key].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func parseImageTag(img string) string {
	s := strings.TrimSpace(img)
	if atIdx := strings.Index(s, "@"); atIdx != -1 {
		s = s[:atIdx]
	}
	if colonIdx := strings.LastIndex(s, ":"); colonIdx != -1 {
		tag := s[colonIdx+1:]
		tag = strings.TrimSuffix(tag, "-alpine")
		tag = strings.TrimSuffix(tag, "-builder")
		if tag != "" && tag != "latest" {
			return tag
		}
	}
	return ""
}
