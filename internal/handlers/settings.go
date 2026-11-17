package handlers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// GetSettingsHandler returns panel configuration with sensitive credentials masked.
func (h *Handlers) GetSettingsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var appearance models.AppearanceSettings
	var captchaCfg models.CaptchaSettings
	var sslCfg models.SSLSettings
	var limitsCfg models.ConnectionLimits
	telegramCfg := make(map[string]any)
	gigahostCfg := make(map[string]any)

	_ = h.db.GetSetting(ctx, "appearance", &appearance)
	_ = h.db.GetSetting(ctx, "captcha", &captchaCfg)
	_ = h.db.GetSetting(ctx, "telegram", &telegramCfg)
	_ = h.db.GetSetting(ctx, "ssl", &sslCfg)
	_ = h.db.GetSetting(ctx, "limits", &limitsCfg)
	_ = h.db.GetSetting(ctx, "gigahost", &gigahostCfg)

	// Strip sensitive private keys & certificate text from API response
	sslCfg.KeyText = ""
	sslCfg.CertText = ""

	// Mask telegram bot tokens if present
	if bt, ok := telegramCfg["bot_token"].(string); ok && bt != "" {
		telegramCfg["bot_token"] = "********"
	}
	if tok, ok := telegramCfg["token"].(string); ok && tok != "" {
		telegramCfg["token"] = "********"
	}

	// Mask gigahost API key if present
	if key, ok := gigahostCfg["api_key"].(string); ok && key != "" {
		gigahostCfg["api_key"] = "********"
	}
	stripObsoleteGigahostKeys(gigahostCfg)

	h.JSON(w, http.StatusOK, map[string]any{
		"appearance": appearance,
		"captcha":    captchaCfg,
		"telegram":   telegramCfg,
		"ssl":        sslCfg,
		"limits":     limitsCfg,
		"gigahost":   gigahostCfg,
	})
}

// obsoleteGigahostKeys are setting fields the panel no longer reads or writes.
// They are not migrated away: an existing row keeps the bytes so nothing in the
// database is destroyed, but the panel neither reports them nor accepts them.
var obsoleteGigahostKeys = []string{"monthly_budget_nok"}

// stripObsoleteGigahostKeys removes retired Gigahost setting fields from a
// decoded settings map, so the retired surface cannot come back through the read
// API or be re-saved by a stale client.
func stripObsoleteGigahostKeys(cfg map[string]any) {
	for _, key := range obsoleteGigahostKeys {
		delete(cfg, key)
	}
}

func (h *Handlers) preserveSecretsOnSave(ctx context.Context, req *models.SaveSettingsRequest) {
	h.preserveSSLOnSave(ctx, &req.SSL)
	h.preserveTelegramOnSave(ctx, req.Telegram)
	// Gigahost: Preserve existing api_key if incoming is empty or masked
	if req.Gigahost != nil {
		h.preserveGigahostOnSave(ctx, req.Gigahost)
	}
}

// preserveSSLOnSave keeps the stored certificate material when the incoming
// values are empty or the masked placeholder the settings page renders.
func (h *Handlers) preserveSSLOnSave(ctx context.Context, incoming *models.SSLSettings) {
	var existing models.SSLSettings
	_ = h.db.GetSetting(ctx, "ssl", &existing)
	if incoming.KeyText == "" || incoming.KeyText == "********" {
		incoming.KeyText = existing.KeyText
	}
	if incoming.CertText == "" || incoming.CertText == "********" {
		incoming.CertText = existing.CertText
	}
}

// preserveTelegramOnSave keeps the stored bot token when the incoming value is
// absent, empty or masked. A nil section means "not edited", not "erase".
func (h *Handlers) preserveTelegramOnSave(ctx context.Context, incoming map[string]any) {
	if incoming == nil {
		return
	}
	existing := make(map[string]any)
	_ = h.db.GetSetting(ctx, "telegram", &existing)
	for _, key := range []string{"bot_token", "token"} {
		value, ok := incoming[key].(string)
		if ok && value != "" && value != "********" {
			continue
		}
		if old, ok := existing[key].(string); ok && old != "" {
			incoming[key] = old
		}
	}
}

// preserveGigahostOnSave keeps the stored Gigahost secrets and retired fields
// that the incoming payload does not supply.
//
// The API key is preserved exactly like the other masked secrets. The retired
// fields are stripped from what the panel ACCEPTS (see stripObsoleteGigahostKeys)
// but carried through on write, so saving unrelated settings never destroys a
// value an older panel stored. Nothing reads them.
func (h *Handlers) preserveGigahostOnSave(ctx context.Context, incoming map[string]any) {
	existing := make(map[string]any)
	_ = h.db.GetSetting(ctx, "gigahost", &existing)

	if key, ok := incoming["api_key"].(string); !ok || key == "" || key == "********" || strings.HasPrefix(key, "****") {
		if oldKey, ok := existing["api_key"].(string); ok && oldKey != "" {
			incoming["api_key"] = oldKey
		}
	}

	carryObsoleteGigahostKeys(incoming, existing)
}

// carryObsoleteGigahostKeys copies retired setting fields from the stored row into
// the row being written, unless the request supplied one. This is a byte-preserving
// carry-through, never a read: no panel path interprets these values.
func carryObsoleteGigahostKeys(incoming, existing map[string]any) {
	for _, key := range obsoleteGigahostKeys {
		if _, provided := incoming[key]; provided {
			continue
		}
		if old, ok := existing[key]; ok {
			incoming[key] = old
		}
	}
}

func (h *Handlers) persistSettings(ctx context.Context, req *models.SaveSettingsRequest) error {
	if err := h.db.SetSetting(ctx, "appearance", req.Appearance); err != nil {
		return err
	}
	if err := h.db.SetSetting(ctx, "captcha", req.Captcha); err != nil {
		return err
	}
	if req.Telegram != nil {
		if err := h.db.SetSetting(ctx, "telegram", req.Telegram); err != nil {
			return err
		}
	}
	if err := h.db.SetSetting(ctx, "ssl", req.SSL); err != nil {
		return err
	}
	if req.Gigahost != nil {
		if err := h.db.SetSetting(ctx, "gigahost", req.Gigahost); err != nil {
			return err
		}
	}
	return h.db.SetSetting(ctx, "limits", req.Limits)
}

// providerCatalogClient forwards every Client method to the injected client
// unchanged and additionally exposes the last catalog eligibility it decoded.
//
// It previously synthesized a hardcoded hourly plan list whenever the inner
// client returned no plans. That fabricated pids, price ids, rates and a region,
// so the portal could offer - and the order path could accept - a "plan" the
// provider never published. Nothing may be invented on the way to a purchase, so
// the fallback is gone and the provider answer passes through unchanged.
type providerCatalogClient struct {
	gigahost.Client
}

func (m *providerCatalogClient) GetCatalogEligibility() gigahost.CatalogEligibility {
	if ce, ok := m.Client.(interface {
		GetCatalogEligibility() gigahost.CatalogEligibility
	}); ok {
		return ce.GetCatalogEligibility()
	}
	return gigahost.CatalogEligibility{}
}

// SaveSettingsHandler updates persistent settings sections in the database.
func (h *Handlers) SaveSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var req models.SaveSettingsRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	sess := h.GetSession(r)
	if sess == nil || !sess.IsAdmin() {
		if req.Gigahost != nil && len(req.Gigahost) > 0 {
			h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required to configure provider settings")
			return
		}
		req.Gigahost = nil
	}

	ctx := r.Context()
	if req.Gigahost != nil {
		stripObsoleteGigahostKeys(req.Gigahost)
	}
	h.preserveSecretsOnSave(ctx, &req)

	if err := h.persistSettings(ctx, &req); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to save settings: "+err.Error())
		return
	}

	h.audit(r, "settings.save", nil)
	h.JSON(w, http.StatusOK, map[string]any{"status": "success"})
}

// DownloadBackupHandler exports panel metadata as a credential-free JSON backup.
//
// The payload contract is versioned by BackupData.FormatVersion: 0/absent is the
// legacy export that could carry decrypted secrets, 2 omits every panel
// credential (issue #343). Migration path: a legacy backup restores unchanged on
// this panel; a version-2 backup must not be restored on a pre-#343 panel, which
// ignores the field and would write the settings map without its secrets.
func (h *Handlers) DownloadBackupHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	servers, _ := h.db.GetAllServers(ctx)
	users, _ := h.db.GetAllUsers(ctx)
	conns, _ := h.db.GetAllConnections(ctx)

	serverMaps := make([]map[string]any, len(servers))
	for i, s := range servers {
		serverMaps[i] = map[string]any{
			"id":       s.ID,
			"name":     s.Name,
			"host":     s.Host,
			"ssh_user": s.SSHUser,
			"ssh_port": s.SSHPort,
			// AWG 3.1 provisioning stores the backend header-protection key in
			// this metadata under several aliases and nested shapes. The same
			// recursive scrub applies here as to settings (#343 review).
			"protocols":  redactBackupSettings(s.Protocols),
			"created_at": s.CreatedAt,
		}
	}

	userMaps := make([]map[string]any, len(users))
	for i, u := range users {
		userMaps[i] = map[string]any{
			"id":                     u.ID,
			"username":               u.Username,
			"email":                  u.Email,
			"telegramId":             u.TelegramID,
			"description":            u.Description,
			"role":                   u.Role,
			"enabled":                u.Enabled,
			"traffic_limit":          u.TrafficLimit,
			"traffic_used":           u.TrafficUsed,
			"traffic_total":          u.TrafficTotal,
			"traffic_total_rx":       u.TrafficTotalRx,
			"traffic_total_tx":       u.TrafficTotalTx,
			"monthly_rx":             u.MonthlyRx,
			"monthly_tx":             u.MonthlyTx,
			"traffic_reset_strategy": u.TrafficResetStrategy,
			"share_enabled":          u.ShareEnabled,
			"created_at":             u.CreatedAt,
			"awg_mimicry":            u.AWGMimicry,
		}
	}

	connMaps := make([]map[string]any, len(conns))
	for i, c := range conns {
		clientID := c.ClientID
		connName := c.Name
		if models.NormalizeProtocol(c.Protocol) == models.ProtocolVLESS {
			// The VLESS UUID is the client's authentication credential, not a mere
			// identifier, so it is redacted for every role. The display name is
			// replaced when it embeds the UUID (safeVLESSDisplayName).
			clientID = ""
			connName = safeVLESSDisplayName(connName, c.ClientID)
		}
		connMaps[i] = map[string]any{
			"id":               c.ID,
			"user_id":          c.UserID,
			"server_id":        c.ServerID,
			"protocol":         c.Protocol,
			"client_id":        clientID,
			"name":             connName,
			"awg_mimicry":      c.AWGMimicry,
			"traffic_total_rx": c.TrafficTotalRx,
			"traffic_total_tx": c.TrafficTotalTx,
			"traffic_total":    c.TrafficTotal,
			"created_at":       c.CreatedAt,
		}
	}

	settingsMap, _ := h.db.GetAllSettings(ctx)
	if settingsMap != nil {
		// GetAllSettings returns decrypted credentials (ssl.key_text, provider and
		// bot tokens). The export is a credential-free metadata artifact (#343),
		// so every credential-bearing field is removed rather than masked, and the
		// marker below is then a true statement.
		if redacted, ok := redactBackupSettings(settingsMap).(map[string]any); ok {
			settingsMap = redacted
		}
	}

	// Export SSH host-key fingerprints (TOFU) and leaderboard snapshots for parity
	// with the Python reference backup format.
	allServers, _ := h.db.GetAllServers(ctx)
	knownHosts := make([]map[string]any, 0, len(allServers))
	for _, s := range allServers {
		fp, err := h.db.GetKnownHostFingerprint(ctx, s.ID)
		if err != nil || fp == "" {
			continue
		}
		kh, err := h.db.GetKnownHost(ctx, s.ID)
		if err != nil || kh == nil {
			continue
		}
		entry := map[string]any{
			"server_id":   s.ID,
			"fingerprint": fp,
		}
		if !kh.FirstSeen.IsZero() {
			entry["first_seen"] = kh.FirstSeen
		}
		knownHosts = append(knownHosts, entry)
	}

	leaderboardSnapshots := make([]map[string]any, 0)
	entries, _ := h.db.GetLeaderboardSnapshot(ctx, time.Now().Year(), int(time.Now().Month()))
	for _, e := range entries {
		leaderboardSnapshots = append(leaderboardSnapshots, map[string]any{
			"username": e.Username,
			"total":    e.Total,
		})
	}

	backup := models.BackupData{
		FormatVersion:         BackupFormatVersion,
		Servers:               serverMaps,
		Users:                 userMaps,
		UserConnections:       connMaps,
		ConnectionCreationLog: make([]map[string]any, 0),
		KnownHosts:            knownHosts,
		LeaderboardSnapshots:  leaderboardSnapshots,
		Settings:              settingsMap,
	}

	// A credential-free export (#343): panel secrets are absent, so this marker
	// is now a true statement. Connection identifiers are still exported because
	// they are connection identity, not portal credentials.
	w.Header().Set("X-Backup-Credentials-Excluded", "true")
	w.Header().Set("X-Backup-Format-Version", strconv.Itoa(BackupFormatVersion))

	backupBytes, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to serialize backup")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"amnezia_backup.json\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(backupBytes)
}

// RestoreBackupHandler imports and merges database records from a JSON backup.
func (h *Handlers) RestoreBackupHandler(w http.ResponseWriter, r *http.Request) {
	sess := h.GetSession(r)
	if sess == nil || !sess.IsAdmin() {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin role required")
		return
	}

	var bodyBytes []byte

	// Handle multipart upload or raw JSON
	if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		file, _, err := r.FormFile("file")
		if err != nil {
			file, _, err = r.FormFile("backup")
		}
		if err != nil {
			h.JSONError(w, http.StatusBadRequest, "validation_failed", "No file uploaded")
			return
		}
		defer file.Close()
		bodyBytes, _ = io.ReadAll(io.LimitReader(file, 52428800)) // 50MB max
	} else {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 52428800))
	}

	if len(bodyBytes) == 0 {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Empty backup file")
		return
	}

	var backup models.BackupData
	if err := json.Unmarshal(bodyBytes, &backup); err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}
	if backup.FormatVersion > BackupFormatVersion {
		h.JSONError(w, http.StatusBadRequest, "unsupported_backup_format",
			"Backup format is newer than this panel supports")
		return
	}

	ctx := r.Context()

	restored := h.restoreBackupData(ctx, &backup)

	h.audit(r, "settings.backup_restore", map[string]any{
		"servers":  restored["servers"],
		"users":    restored["users"],
		"conns":    restored["conns"],
		"settings": restored["settings"],
	})

	h.JSON(w, http.StatusOK, map[string]any{
		"status":   "success",
		"restored": restored,
	})
}

// restoreBackupData restores settings, servers, users, and connections from a backup,
// returning counts of restored records per entity type.
func (h *Handlers) restoreBackupData(ctx context.Context, backup *models.BackupData) map[string]int {
	restoredSettings := h.restoreBackupSettings(ctx, backup.Settings)
	restoredServers, serverIDMap := h.restoreBackupServers(ctx, backup.Servers)
	restoredUsers := h.restoreBackupUsers(ctx, backup.Users)
	restoredConns := h.restoreBackupConnections(ctx, backup.UserConnections, serverIDMap)
	h.restoreBackupKnownHosts(ctx, backup.KnownHosts)

	return map[string]int{
		"servers":  restoredServers,
		"users":    restoredUsers,
		"conns":    restoredConns,
		"settings": restoredSettings,
	}
}

var allowedSettingsKeys = map[string]bool{
	"appearance":     true,
	"sync":           true,
	"captcha":        true,
	"telegram":       true,
	"notifications":  true,
	"ssl":            true,
	"limits":         true,
	"vpn_config":     true,
	"schema_version": true,
}

func (h *Handlers) restoreBackupSettings(ctx context.Context, settings map[string]any) int {
	restored := 0
	for k, v := range settings {
		if !allowedSettingsKeys[k] {
			continue
		}
		merged, ok := h.mergeBackupSettingSecrets(ctx, k, v)
		if !ok {
			// Could not read the live value. Writing blind could blank a
			// credential the backup redacted, so this setting is skipped and
			// the restore reports one fewer applied setting.
			continue
		}
		if err := h.db.SetSetting(ctx, k, merged); err == nil {
			restored++
		}
	}
	return restored
}

// mergeBackupSettingSecrets overlays an incoming settings map on the live value,
// preserving every credential the backup omitted or blanked.
//
// A credential-free export (#343) carries no ssl.key_text or bot token. Without
// this, restoring it would overwrite the stored TLS key with a map that has
// none, turning a metadata restore into an outage. The second return value is
// false when the live value cannot be read: the caller must then skip the write
// rather than replace a secret with a redaction artifact.
func (h *Handlers) mergeBackupSettingSecrets(ctx context.Context, key string, incoming any) (any, bool) {
	if _, ok := incoming.(map[string]any); !ok {
		return incoming, true
	}
	var existing any
	if err := h.db.GetSetting(ctx, key, &existing); err != nil {
		return nil, false
	}
	if key == "ssl" {
		return mergeSSLIdentity(incoming, existing)
	}
	return mergePreservingSecrets(incoming, existing), true
}

// mergeSSLIdentity keeps the TLS identity coherent.
//
// A credential-free export carries a certificate but no private key. Applying
// that certificate over the live key would leave a mismatched pair, which
// tls.X509KeyPair rejects at the next listener start. The identity is therefore
// applied only when the backup supplies both halves AND they form a valid pair;
// otherwise the live pair is kept whole — or, with no live pair to keep, nothing
// is written.
func mergeSSLIdentity(incoming, existing any) (any, bool) {
	inMap, ok := incoming.(map[string]any)
	if !ok {
		return incoming, true
	}
	keyText, certText := strVal(inMap["key_text"]), strVal(inMap["cert_text"])
	if keyText != "" && certText != "" {
		if _, err := tls.X509KeyPair([]byte(certText), []byte(keyText)); err == nil {
			return inMap, true
		}
	}
	if exMap, ok := existing.(map[string]any); ok && len(exMap) > 0 {
		return exMap, true
	}
	return nil, false
}

func (h *Handlers) restoreBackupServers(ctx context.Context, servers []map[string]any) (int, map[int64]int64) {
	restored := 0
	for _, sMap := range servers {
		s := &models.Server{
			Name:      strVal(sMap["name"]),
			Host:      strVal(sMap["host"]),
			SSHUser:   strVal(sMap["ssh_user"]),
			SSHPort:   intVal(sMap["ssh_port"]),
			SSHPass:   strVal(sMap["ssh_pass"]),
			SSHKey:    strVal(sMap["ssh_key"]),
			Protocols: mapFromInterface(sMap["protocols"]),
			CreatedAt: time.Now(),
		}
		if id := int64Val(sMap["id"]); id > 0 {
			s.ID = id
		}
		if s.Name != "" && s.Host != "" {
			if createdID, err := h.db.CreateServer(ctx, s); err == nil {
				restored++
				if h.vpnSvc != nil {
					targetID := s.ID
					if targetID <= 0 {
						targetID = createdID
					}
					if targetID > 0 {
						h.vpnSvc.ClearServerDeletedTombstone(targetID)
					}
				}
			}
		}
	}

	serverIDMap := make(map[int64]int64)
	if len(servers) > 0 {
		allServers, _ := h.db.GetAllServers(ctx)
		for _, s := range allServers {
			serverIDMap[s.ID] = s.ID
		}
		for _, sMap := range servers {
			oldID := int64Val(sMap["id"])
			if oldID == 0 {
				continue
			}
			for _, s := range allServers {
				if s.Host == strVal(sMap["host"]) && s.Name == strVal(sMap["name"]) {
					serverIDMap[oldID] = s.ID
					break
				}
			}
		}
	}
	return restored, serverIDMap
}

func (h *Handlers) restoreBackupUsers(ctx context.Context, users []map[string]any) int {
	restored := 0
	for _, uMap := range users {
		u := h.userFromBackupMap(uMap)
		if len(u.Username) > 0 {
			if _, err := h.db.CreateUser(ctx, u); err == nil {
				restored++
			}
		}
	}
	return restored
}

func (h *Handlers) restoreBackupConnections(ctx context.Context, connections []map[string]any, serverIDMap map[int64]int64) int {
	restored := 0
	for _, cMap := range connections {
		oldServerID := int64Val(cMap["server_id"])
		newServerID := serverIDMap[oldServerID]
		if newServerID == 0 {
			newServerID = oldServerID
		}

		c := &models.UserConnection{
			ID:             strVal(cMap["id"]),
			UserID:         strVal(cMap["user_id"]),
			ServerID:       newServerID,
			Protocol:       strVal(cMap["protocol"]),
			ClientID:       strVal(cMap["client_id"]),
			Name:           strVal(cMap["name"]),
			AWGMimicry:     models.AWGMimicryProfile(strVal(cMap["awg_mimicry"])),
			TrafficTotalRx: int64Val(cMap["traffic_total_rx"]),
			TrafficTotalTx: int64Val(cMap["traffic_total_tx"]),
			TrafficTotal:   int64Val(cMap["traffic_total"]),
			CreatedAt:      time.Now(),
		}
		if created := strVal(cMap["created_at"]); created != "" {
			if t, err := time.Parse(time.RFC3339, created); err == nil {
				c.CreatedAt = t
			}
		}
		if c.UserID != "" && c.ServerID > 0 && c.Protocol != "" {
			if _, err := h.db.CreateConnection(ctx, c); err == nil {
				restored++
			}
		}
	}
	return restored
}

func (h *Handlers) restoreBackupKnownHosts(ctx context.Context, knownHosts []map[string]any) {
	for _, khMap := range knownHosts {
		serverID := int64Val(khMap["server_id"])
		fp := strVal(khMap["fingerprint"])
		if serverID > 0 && fp != "" {
			_ = h.db.SaveKnownHost(ctx, serverID, fp)
		}
	}
}

// userFromBackupMap converts a raw backup user map into a models.User.
func (h *Handlers) userFromBackupMap(uMap map[string]any) *models.User {
	u := &models.User{
		ID:                   strVal(uMap["id"]),
		Username:             strVal(uMap["username"]),
		PasswordHash:         strVal(uMap["password_hash"]),
		Role:                 models.UserRole(strVal(uMap["role"])),
		Enabled:              boolVal(uMap["enabled"]),
		TrafficLimit:         int64Val(uMap["traffic_limit"]),
		TrafficUsed:          int64Val(uMap["traffic_used"]),
		TrafficTotal:         int64Val(uMap["traffic_total"]),
		TrafficTotalRx:       int64Val(uMap["traffic_total_rx"]),
		TrafficTotalTx:       int64Val(uMap["traffic_total_tx"]),
		MonthlyRx:            int64Val(uMap["monthly_rx"]),
		MonthlyTx:            int64Val(uMap["monthly_tx"]),
		TrafficResetStrategy: models.TrafficResetStrategy(strVal(uMap["traffic_reset_strategy"])),
		ShareEnabled:         boolVal(uMap["share_enabled"]),
		AWGMimicry:           models.AWGMimicryProfile(strVal(uMap["awg_mimicry"])),
		CreatedAt:            time.Now(),
	}
	if email := strVal(uMap["email"]); email != "" {
		u.Email = &email
	}
	if tg := strVal(uMap["telegramId"]); tg != "" {
		u.TelegramID = &tg
	}
	if desc := strVal(uMap["description"]); desc != "" {
		u.Description = &desc
	}
	if shareToken := strVal(uMap["share_token"]); shareToken != "" {
		u.ShareToken = &shareToken
	} else if u.ShareEnabled {
		// A credential-free export carries no share token. Restoring it must not
		// leave a half-enabled share whose old link still resolves, so the share
		// is written disabled and the owner re-enables it deliberately.
		u.ShareEnabled = false
	}
	if created := strVal(uMap["created_at"]); created != "" {
		if t, err := time.Parse(time.RFC3339, created); err == nil {
			u.CreatedAt = t
		}
	}
	return u
}

// Helper functions for type-safe extraction from backup maps.
func strVal(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func int64Val(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case string:
		if n, err := strconv.ParseInt(n, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func intVal(v any) int {
	return int(int64Val(v))
}

func boolVal(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case float64:
		return b != 0
	case string:
		return b == "true" || b == "1"
	}
	return false
}

func mapFromInterface(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return make(map[string]any)
}
