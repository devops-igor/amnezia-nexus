package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/devops-igor/amnezia-nexus/internal/manager/updater"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

var bgReleaseWarmGroup singleflight.Group

func (h *Handlers) triggerBackgroundReleaseWarm(checker *updater.ReleaseChecker, engine updater.EngineType) {
	if checker == nil {
		return
	}
	go func() {
		key := string(engine)
		_, _, _ = bgReleaseWarmGroup.Do(key, func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return checker.GetLatestRelease(ctx, engine)
		})
	}()
}

// populateServerEngineStatus populates EngineStatus on ServerItemResponse for admin users.
// For non-admin and support callers, item.EngineStatus is left nil so it is omitted from JSON.
// Decoupled from synchronous GitHub network latency using cached releases only and async warming.
func (h *Handlers) populateServerEngineStatus(ctx context.Context, item *models.ServerItemResponse, server *models.Server, isAdmin bool) {
	if item == nil {
		return
	}
	if !isAdmin || server == nil {
		item.EngineStatus = nil
		return
	}

	statusMap := h.resolveServerEngineStatusCached(server)
	if len(statusMap) == 0 {
		item.EngineStatus = nil
		return
	}
	item.EngineStatus = statusMap
}

// resolveServerEngineStatusCached returns immediately available cached status.
// On cold cache, it marks status as unknown and warms the release asynchronously.
func (h *Handlers) resolveServerEngineStatusCached(server *models.Server) map[string]any {
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
		profile := extractXrayProfile(vMeta)
		installedVersion := extractXrayVersion(vMeta)
		rel, cached := checker.GetCachedRelease(updater.EngineXray)
		if !cached {
			h.triggerBackgroundReleaseWarm(checker, updater.EngineXray)
			result[models.ProtocolVLESS] = buildUnknownStatus(updater.EngineXray, models.ProtocolVLESS, installedVersion, profile)
		} else {
			result[models.ProtocolVLESS] = evaluateReleaseStatus(updater.EngineXray, models.ProtocolVLESS, installedVersion, profile, rel)
		}
	}

	// 2. NaiveProxy / Caddy (models.ProtocolNaive = "naive")
	if nMeta, ok := getInstalledProtocolMetadata(server.Protocols, models.ProtocolNaive); ok {
		caddyVersion := extractCaddyVersion(nMeta)
		cRel, cCached := checker.GetCachedRelease(updater.EngineCaddyCore)
		if !cCached {
			h.triggerBackgroundReleaseWarm(checker, updater.EngineCaddyCore)
			result["caddy"] = buildUnknownStatus(updater.EngineCaddyCore, "caddy", caddyVersion, "")
		} else {
			result["caddy"] = evaluateReleaseStatus(updater.EngineCaddyCore, "caddy", caddyVersion, "", cRel)
		}

		pluginVersion := extractNaivePluginVersion(nMeta)
		pRel, pCached := checker.GetCachedRelease(updater.EngineNaiveForwardProxy)
		if !pCached {
			h.triggerBackgroundReleaseWarm(checker, updater.EngineNaiveForwardProxy)
			result[models.ProtocolNaive] = buildUnknownStatus(updater.EngineNaiveForwardProxy, models.ProtocolNaive, pluginVersion, "")
		} else {
			result[models.ProtocolNaive] = evaluateReleaseStatus(updater.EngineNaiveForwardProxy, models.ProtocolNaive, pluginVersion, "", pRel)
		}
	}

	// 3. Optional sing-box
	if sMeta, ok := getInstalledProtocolMetadata(server.Protocols, "sing-box"); ok {
		version := extractSingBoxVersion(sMeta)
		sRel, sCached := checker.GetCachedRelease(updater.EngineSingBox)
		if !sCached {
			h.triggerBackgroundReleaseWarm(checker, updater.EngineSingBox)
			result["sing-box"] = buildUnknownStatus(updater.EngineSingBox, "sing-box", version, "")
		} else {
			result["sing-box"] = evaluateReleaseStatus(updater.EngineSingBox, "sing-box", version, "", sRel)
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func evaluateReleaseStatus(engine updater.EngineType, protocol, installedVersion, profile string, rel updater.ReleaseInfo) updater.EngineStatus {
	st := updater.CheckUpdateStatus(installedVersion, rel.Version)
	var upstreamNewer bool
	var upgradeCompatible bool
	var updateAvailable bool

	switch st {
	case updater.UpdateUnknown:
		upstreamNewer = false
		upgradeCompatible = false
		updateAvailable = false
	case updater.UpdateAvailable:
		upstreamNewer = true
		if engine == updater.EngineXray {
			upgradeCompatible = isXrayProfileCompatible(profile, rel.Version)
		} else {
			upgradeCompatible = true
		}
		updateAvailable = upstreamNewer && upgradeCompatible
	case updater.UpdateUpToDate:
		upstreamNewer = false
		upgradeCompatible = true
		updateAvailable = false
	}

	checkedAt := rel.PublishedAt
	if checkedAt.IsZero() {
		checkedAt = time.Now()
	}

	return updater.EngineStatus{
		Protocol:          protocol,
		InstalledVersion:  installedVersion,
		LatestVersion:     rel.Version,
		UpdateAvailable:   updateAvailable,
		UpstreamNewer:     upstreamNewer,
		UpgradeCompatible: upgradeCompatible,
		Status:            st,
		Channel:           profile,
		ReleaseURL:        rel.ReleaseURL,
		CheckedAt:         checkedAt,
		RequestedAt:       time.Now(),
	}
}

func isXrayProfileCompatible(profile, upstreamTag string) bool {
	norm := strings.ToLower(strings.TrimSpace(profile))
	if norm == "" {
		return false
	}
	vLat, err := updater.ParseVersion(upstreamTag)
	if err != nil {
		return false
	}
	switch {
	case norm == "legacy" || norm == "legacy_baseline" || norm == "baseline" || norm == "1.8.24" || norm == "v1.8.24":
		return vLat.Major() < 20
	case norm == "modern_pq" || norm == "modern" || norm == "pq" || norm == "v26" || norm == "26" || strings.HasPrefix(norm, "26.10.") || strings.HasPrefix(norm, "v26.10."):
		return vLat.Major() >= 20
	default:
		return false
	}
}

func buildUnknownStatus(engine updater.EngineType, protocol, installedVersion, channel string) updater.EngineStatus {
	return updater.EngineStatus{
		Protocol:          protocol,
		InstalledVersion:  installedVersion,
		LatestVersion:     "",
		UpdateAvailable:   false,
		UpstreamNewer:     false,
		UpgradeCompatible: false,
		Status:            updater.UpdateUnknown,
		Channel:           channel,
		RequestedAt:       time.Now(),
	}
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
	installedVersion := extractXrayVersion(meta)

	status, err := checker.CheckEngineWithProfile(ctx, updater.EngineXray, installedVersion, profile)
	if err != nil {
		dest[models.ProtocolVLESS] = buildUnknownStatus(updater.EngineXray, models.ProtocolVLESS, installedVersion, profile)
		return
	}

	dest[models.ProtocolVLESS] = status
}

func (h *Handlers) resolveNaiveStatus(ctx context.Context, checker *updater.ReleaseChecker, meta map[string]any, dest map[string]any) {
	// 1. Caddy Core
	caddyVersion := extractCaddyVersion(meta)
	caddyStatus, err := checker.CheckEngine(ctx, updater.EngineCaddyCore, caddyVersion)
	if err != nil {
		dest["caddy"] = buildUnknownStatus(updater.EngineCaddyCore, "caddy", caddyVersion, "")
	} else {
		dest["caddy"] = caddyStatus
	}

	// 2. Naive ForwardProxy Plugin
	pluginVersion := extractNaivePluginVersion(meta)
	pluginStatus, err := checker.CheckEngine(ctx, updater.EngineNaiveForwardProxy, pluginVersion)
	if err != nil {
		dest[models.ProtocolNaive] = buildUnknownStatus(updater.EngineNaiveForwardProxy, models.ProtocolNaive, pluginVersion, "")
	} else {
		dest[models.ProtocolNaive] = pluginStatus
	}
}

func (h *Handlers) resolveSingBoxStatus(ctx context.Context, checker *updater.ReleaseChecker, meta map[string]any, dest map[string]any) {
	version := extractSingBoxVersion(meta)
	status, err := checker.CheckEngine(ctx, updater.EngineSingBox, version)
	if err != nil {
		dest["sing-box"] = buildUnknownStatus(updater.EngineSingBox, "sing-box", version, "")
		return
	}
	dest["sing-box"] = status
}

func extractSingBoxVersion(meta map[string]any) string {
	if meta == nil {
		return ""
	}
	for _, key := range []string{"running_engine_version", "installed_version", "version", "engine_version"} {
		if v, ok := meta[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if params, ok := meta["params"].(map[string]any); ok && params != nil {
		for _, key := range []string{"running_engine_version", "installed_version", "version", "engine_version"} {
			if v, ok := params[key].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
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

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

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
	for _, key := range []string{"running_engine_version", "installed_version", "engine_version", "version"} {
		if v, ok := meta[key].(string); ok {
			norm := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
			if strings.HasPrefix(norm, "26.") || strings.HasPrefix(norm, "25.") {
				return "modern_pq"
			}
		}
	}
	return "legacy"
}

func extractXrayVersion(meta map[string]any, _ ...string) string {
	if meta == nil {
		return ""
	}

	params, _ := meta["params"].(map[string]any)

	// 1. Prefer verified running_engine_version
	for _, m := range []map[string]any{meta, params} {
		if m == nil {
			continue
		}
		if v, ok := m["running_engine_version"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}

	// 2. Inspect installed container/image metadata (engine_image, xray_image, image)
	for _, m := range []map[string]any{meta, params} {
		if m == nil {
			continue
		}
		for _, key := range []string{"engine_image", "xray_image", "image"} {
			if img, ok := m[key].(string); ok && strings.TrimSpace(img) != "" {
				if tag := parseImageTag(img); tag != "" {
					return tag
				}
			}
		}
	}

	// 3. Inspect static engine_version, installed_version, or version
	for _, m := range []map[string]any{meta, params} {
		if m == nil {
			continue
		}
		for _, key := range []string{"installed_version", "engine_version", "version"} {
			if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}

	// 4. Return "" when unestablished (unknown) — NEVER guess from profile channel!
	return ""
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
				s := strings.TrimSpace(v)
				if strings.HasPrefix(s, "c096d6a") {
					return "v2.11.7-naive2"
				}
				return s
			}
		}
		if params, ok := meta["params"].(map[string]any); ok && params != nil {
			for _, key := range []string{"plugin_version", "pluginVersion", "naive_version", "forwardproxy_version", "naiveVersion"} {
				if v, ok := params[key].(string); ok && strings.TrimSpace(v) != "" {
					s := strings.TrimSpace(v)
					if strings.HasPrefix(s, "c096d6a") {
						return "v2.11.7-naive2"
					}
					return s
				}
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
