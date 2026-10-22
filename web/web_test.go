package web

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

func TestModernJavaScriptAndInteractiveComponents(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	// 1. Assert api.js presence and key API methods
	apiData, err := fs.ReadFile(staticFS, "js/api.js")
	if err != nil {
		t.Fatalf("failed to read js/api.js: %v", err)
	}
	if len(apiData) == 0 {
		t.Errorf("js/api.js is empty")
	}
	apiStr := string(apiData)
	requiredAPISignatures := []string{
		"root.API",
		"X-CSRF-Token",
		"password_change_required",
		"request(url",
		"get(url",
		"post(url",
		"patch(url",
		"delete: del",
	}
	for _, sig := range requiredAPISignatures {
		if !strings.Contains(apiStr, sig) {
			t.Errorf("js/api.js missing required signature %q", sig)
		}
	}

	// 2. Assert ui.js presence and key UI components
	uiData, err := fs.ReadFile(staticFS, "js/ui.js")
	if err != nil {
		t.Fatalf("failed to read js/ui.js: %v", err)
	}
	if len(uiData) == 0 {
		t.Errorf("js/ui.js is empty")
	}
	uiStr := string(uiData)
	requiredUISignatures := []string{
		"root.UI",
		"toast: toast",
		"modal:",
		"openModal",
		"closeModal",
		"copy: copy",
		"confirm: confirm",
		"nexusConfirmModal",
		"formatBytes",
		"downloadFile",
		"downloadQRCode",
		"escapeHtml",
		"escapeJs",
	}
	for _, sig := range requiredUISignatures {
		if !strings.Contains(uiStr, sig) {
			t.Errorf("js/ui.js missing required signature %q", sig)
		}
	}

	// 3. Assert base.css and components.css skeleton shimmer and micro-interactions
	baseCSSData, err := fs.ReadFile(staticFS, "css/base.css")
	if err != nil {
		t.Fatalf("failed to read css/base.css: %v", err)
	}
	compData, err := fs.ReadFile(staticFS, "css/components.css")
	if err != nil {
		t.Fatalf("failed to read css/components.css: %v", err)
	}
	cssStr := string(baseCSSData) + "\n" + string(compData)
	requiredCSS := []string{
		"@keyframes shimmer",
		".skeleton",
		".skeleton-text",
		".skeleton-card",
		".skeleton-avatar",
		".copied",
		".toast",
		".toast-exit",
	}
	for _, item := range requiredCSS {
		if !strings.Contains(cssStr, item) {
			t.Errorf("base.css / components.css missing required skeleton or micro-interaction token %q", item)
		}
	}

	// 4. Assert base.html integration
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	baseData, err := fs.ReadFile(templatesFS, "base.html")
	if err != nil {
		t.Fatalf("failed to read base.html: %v", err)
	}
	baseStr := string(baseData)
	requiredIntegrations := []string{
		"src=\"/static/js/api.js\"",
		"src=\"/static/js/ui.js\"",
		"id=\"nexusConfirmModal\"",
		"id=\"nexusConfirmTitle\"",
		"id=\"nexusConfirmBody\"",
		"id=\"nexusConfirmOkBtn\"",
		"id=\"nexusConfirmCancelBtn\"",
	}
	for _, item := range requiredIntegrations {
		if !strings.Contains(baseStr, item) {
			t.Errorf("base.html missing required component integration %q", item)
		}
	}
}

func TestDeadCompatibilityAliasesPruned(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	// 1. Verify api.js does not contain root.apiCall
	apiData, err := fs.ReadFile(staticFS, "js/api.js")
	if err != nil {
		t.Fatalf("failed to read js/api.js: %v", err)
	}
	if strings.Contains(string(apiData), "root.apiCall") {
		t.Errorf("js/api.js must not contain dead compatibility alias root.apiCall")
	}

	// 2. Verify ui.js does not contain root.confirmModal
	uiData, err := fs.ReadFile(staticFS, "js/ui.js")
	if err != nil {
		t.Fatalf("failed to read js/ui.js: %v", err)
	}
	if strings.Contains(string(uiData), "root.confirmModal") {
		t.Errorf("js/ui.js must not contain dead compatibility alias root.confirmModal")
	}

	// 3. Verify tables.js does not contain root.DataTable
	tablesData, err := fs.ReadFile(staticFS, "js/tables.js")
	if err != nil {
		t.Fatalf("failed to read js/tables.js: %v", err)
	}
	if strings.Contains(string(tablesData), "root.DataTable") {
		t.Errorf("js/tables.js must not contain dead compatibility alias root.DataTable")
	}
}

func TestPhase3TablesAndTelemetryEngine(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	// 1. Assert tables.js presence and key engine signatures
	tablesData, err := fs.ReadFile(staticFS, "js/tables.js")
	if err != nil {
		t.Fatalf("failed to read js/tables.js: %v", err)
	}
	if len(tablesData) == 0 {
		t.Errorf("js/tables.js is empty")
	}
	tablesStr := string(tablesData)
	requiredTablesSignatures := []string{
		"root.NexusTable",
		"NexusTable",
		"searchable",
		"sortable",
		"paginate",
		"pageSize",
		"emptyMessage",
		"parseBytes",
		"parseSortValue",
		"th.sortable",
		"aria-sort",
		"table-empty-state",
		"table-pagination",
		"page-btn",
		"page-info",
		"data-status",
		"refresh()",
		"updateRows()",
	}
	for _, sig := range requiredTablesSignatures {
		if !strings.Contains(tablesStr, sig) {
			t.Errorf("js/tables.js missing required signature %q", sig)
		}
	}

	// 2. Assert telemetry.js presence and key telemetry signatures
	telemetryData, err := fs.ReadFile(staticFS, "js/telemetry.js")
	if err != nil {
		t.Fatalf("failed to read js/telemetry.js: %v", err)
	}
	if len(telemetryData) == 0 {
		t.Errorf("js/telemetry.js is empty")
	}
	telemetryStr := string(telemetryData)
	requiredTelemetrySignatures := []string{
		"root.NexusTelemetry",
		"root.Telemetry",
		"poll(streamId",
		"visibilitychange",
		"renderSparkline",
		"buildSmoothPath",
		"formatSpeed",
		"formatLatency",
		"formatBytes",
		"pause(streamId",
		"resume(streamId",
		"stop(streamId",
		"sparkline-svg",
		"sparkline-container",
	}
	for _, sig := range requiredTelemetrySignatures {
		if !strings.Contains(telemetryStr, sig) {
			t.Errorf("js/telemetry.js missing required signature %q", sig)
		}
	}

	// 3. Assert tables.css and vpn.css Phase 3 styles
	cssTablesData, err := fs.ReadFile(staticFS, "css/tables.css")
	if err != nil {
		t.Fatalf("failed to read css/tables.css: %v", err)
	}
	vpnData, err := fs.ReadFile(staticFS, "css/vpn.css")
	if err != nil {
		t.Fatalf("failed to read css/vpn.css: %v", err)
	}
	cssStr := string(cssTablesData) + "\n" + string(vpnData)
	requiredCSSPhase3 := []string{
		".table-toolbar",
		".table-search-box",
		"th.sortable",
		".sort-icon",
		".table-empty-state",
		".table-pagination",
		".page-btn",
		".page-info",
		".filter-chip",
		".sparkline-container",
		".sparkline-svg",
		".sparkline-dot",
	}
	for _, item := range requiredCSSPhase3 {
		if !strings.Contains(cssStr, item) {
			t.Errorf("tables.css / vpn.css missing required Phase 3 CSS token %q", item)
		}
	}

	// 4. Assert base.html script tags and SVG symbols
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	baseData, err := fs.ReadFile(templatesFS, "base.html")
	if err != nil {
		t.Fatalf("failed to read base.html: %v", err)
	}
	baseStr := string(baseData)

	requiredScripts := []string{
		"src=\"/static/js/tables.js\"",
		"src=\"/static/js/telemetry.js\"",
	}
	for _, script := range requiredScripts {
		if !strings.Contains(baseStr, script) {
			t.Errorf("base.html missing required script %q", script)
		}
	}

	requiredIcons := []string{
		"id=\"icon-search\"",
		"id=\"icon-filter\"",
		"id=\"icon-arrow-up\"",
		"id=\"icon-arrow-down\"",
		"id=\"icon-refresh\"",
		"id=\"icon-activity\"",
	}
	for _, icon := range requiredIcons {
		if !strings.Contains(baseStr, icon) {
			t.Errorf("base.html missing required icon symbol %q", icon)
		}
	}

	// 5. Assert icons.html contains matching SVG symbols
	iconsData, err := fs.ReadFile(templatesFS, "icons.html")
	if err != nil {
		t.Fatalf("failed to read icons.html: %v", err)
	}
	iconsStr := string(iconsData)
	for _, icon := range requiredIcons {
		if !strings.Contains(iconsStr, icon) {
			t.Errorf("icons.html missing required icon symbol %q", icon)
		}
	}
}

func TestPhase6ClientExperienceAndPolish(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	// 1. Assert Client Self-Service Dashboard (my_connections.html)
	myConnData, err := fs.ReadFile(templatesFS, "my_connections.html")
	if err != nil {
		t.Fatalf("failed to read my_connections.html: %v", err)
	}
	myConnStr := string(myConnData)

	requiredMyConnTokens := []string{
		"href=\"#icon-activity\"",
		"href=\"#icon-server\"",
		"href=\"#icon-lock\"",
		"href=\"#icon-plug\"",
		"href=\"#icon-shield\"",
		"href=\"#icon-download\"",
		"href=\"#icon-copy\"",
		"href=\"#icon-qr\"",
		"href=\"#icon-trash\"",
		"href=\"#icon-pencil\"",
		"href=\"#icon-plus\"",
		"href=\"#icon-calendar\"",
		"href=\"#icon-zap\"",
		"href=\"#icon-file-text\"",
		"UI.confirm",
		"UI.copy",
		"UI.downloadFile",
		"UI.toast",
		"UI.modal.open",
		"UI.modal.close",
		"UI.formatBytes",
		"API.get",
		"API.post",
		"connSearchInput",
		"filterConnections",
		"toggleSortOrder",
		"network-health-grid",
		"network-health-node",
	}
	for _, token := range requiredMyConnTokens {
		if !strings.Contains(myConnStr, token) {
			t.Errorf("my_connections.html missing required modernized token %q", token)
		}
	}

	// Ensure no raw confirm(), apiCall(), showToast() in my_connections.html
	if strings.Contains(myConnStr, "if (!confirm(") || strings.Contains(myConnStr, "if(!confirm(") {
		t.Errorf("my_connections.html should not use raw confirm(), must use UI.confirm")
	}
	if strings.Contains(myConnStr, "apiCall(") {
		t.Errorf("my_connections.html should not use apiCall(), must use API client")
	}
	if strings.Contains(myConnStr, "showToast(") {
		t.Errorf("my_connections.html should not use showToast(), must use UI.toast")
	}

	// Ensure legacy emojis are eliminated from my_connections.html
	legacyMyConnEmojis := []string{"📡", "🖥", "🔗", "📊", "⚡ Load Balancer", "✏️", "🗑️"}
	for _, emoji := range legacyMyConnEmojis {
		if strings.Contains(myConnStr, emoji) {
			t.Errorf("my_connections.html should not contain legacy emoji %q", emoji)
		}
	}

	// 2. Assert Authentication (login.html)
	loginData, err := fs.ReadFile(templatesFS, "login.html")
	if err != nil {
		t.Fatalf("failed to read login.html: %v", err)
	}
	loginStr := string(loginData)

	requiredLoginTokens := []string{
		"nexus-svg-icons",
		"href=\"#icon-shield\"",
		"href=\"#icon-moon\"",
		"href=\"#icon-sun\"",
		"href=\"#icon-globe\"",
		"href=\"#icon-user\"",
		"href=\"#icon-lock\"",
		"href=\"#icon-x\"",
		"href=\"#icon-check\"",
		"login-header-actions",
		"login-card-elevated",
		"login-icon-adornment-group",
		"login-input-adornment",
		"login-error-box",
		"API.post",
		"UI.modal.open",
		"UI.modal.close",
		"eq .lang \"fa\"",
		"dir=\"rtl\"",
	}
	for _, token := range requiredLoginTokens {
		if !strings.Contains(loginStr, token) {
			t.Errorf("login.html missing required modernized token %q", token)
		}
	}

	// Ensure legacy emojis are eliminated from login.html
	legacyLoginEmojis := []string{"🌙", "🇷🇺", "🇺🇸", "🇫🇷", "🇨🇳", "🇮🇷"}
	for _, emoji := range legacyLoginEmojis {
		if strings.Contains(loginStr, emoji) {
			t.Errorf("login.html should not contain legacy emoji %q", emoji)
		}
	}

	// 3. Assert System Settings (settings.html)
	settingsData, err := fs.ReadFile(templatesFS, "settings.html")
	if err != nil {
		t.Fatalf("failed to read settings.html: %v", err)
	}
	settingsStr := string(settingsData)

	requiredSettingsTokens := []string{
		"href=\"#icon-settings\"",
		"href=\"#icon-shield\"",
		"href=\"#icon-lock\"",
		"href=\"#icon-send\"",
		"href=\"#icon-link\"",
		"href=\"#icon-database\"",
		"href=\"#icon-download\"",
		"href=\"#icon-upload\"",
		"href=\"#icon-check\"",
		"settings-section-card",
		"settings-card-header",
		"switch-container",
		"switch-slider",
		"telegram_bot_title",
		"telegram_enabled",
		"telegram_bot_token",
		"telegram_chat_id",
		"API.post",
		"UI.confirm",
		"UI.toast",
	}
	for _, token := range requiredSettingsTokens {
		if !strings.Contains(settingsStr, token) {
			t.Errorf("settings.html missing required modernized token %q", token)
		}
	}

	// Ensure no raw confirm(), apiCall(), showToast() in settings.html
	if strings.Contains(settingsStr, "if (!confirm(") || strings.Contains(settingsStr, "if(!confirm(") {
		t.Errorf("settings.html should not use raw confirm(), must use UI.confirm")
	}
	if strings.Contains(settingsStr, "apiCall(") {
		t.Errorf("settings.html should not use apiCall(), must use API client")
	}
	if strings.Contains(settingsStr, "showToast(") {
		t.Errorf("settings.html should not use showToast(), must use UI.toast")
	}

	// Ensure legacy emojis are eliminated from settings.html
	legacySettingsEmojis := []string{"⚙️", "🔒", "📖", "📑", "💾", "🔄", "📤", "⬇️", "⬆️", "🗑"}
	for _, emoji := range legacySettingsEmojis {
		if strings.Contains(settingsStr, emoji) {
			t.Errorf("settings.html should not contain legacy emoji %q", emoji)
		}
	}

	// 4. Multi-Language RTL/LTR and Translation Coverage
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	requiredLangFiles := []string{"en.json", "fa.json", "fr.json", "ru.json", "zh.json"}
	requiredPhase6Keys := []string{
		"telegram_bot_title",
		"telegram_bot_enable",
		"telegram_bot_token_label",
		"telegram_chat_id_label",
		"telegram_bot_hint",
		"search_connections",
		"load_balancer_auto",
		"recommended",
		"load_balancer_recommended_hint",
	}

	for _, langFile := range requiredLangFiles {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", langFile, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
		}

		for _, k := range requiredPhase6Keys {
			val, ok := dict[k]
			if !ok || strings.TrimSpace(val) == "" {
				t.Errorf("translation %s missing or empty required key %q", langFile, k)
			}
		}
	}

	// 5. CSS Tokens and RTL Rules in components.css and vpn.css
	compData, err := fs.ReadFile(staticFS, "css/components.css")
	if err != nil {
		t.Fatalf("failed to read css/components.css: %v", err)
	}
	vpnData, err := fs.ReadFile(staticFS, "css/vpn.css")
	if err != nil {
		t.Fatalf("failed to read css/vpn.css: %v", err)
	}
	cssStr := string(compData) + "\n" + string(vpnData)

	requiredCSSRules := []string{
		".switch-container",
		".switch-slider",
		"[dir=\"rtl\"] .switch-slider:before",
		".login-header-actions",
		"[dir=\"rtl\"] .login-header-actions",
		".login-card-elevated",
		".login-icon-adornment-group",
		"[dir=\"rtl\"] .login-input-adornment",
		".login-error-box",
		".settings-section-card",
		".settings-card-header",
		".network-health-grid",
		".network-health-node",
		".lb-selection-callout",
		"[dir=\"rtl\"] .lb-selection-callout",
	}
	for _, rule := range requiredCSSRules {
		if !strings.Contains(cssStr, rule) {
			t.Errorf("components.css / vpn.css missing required Phase 6 CSS rule %q", rule)
		}
	}
}

func TestAPIClientCsrfTokenRecursionPrevention(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	apiData, err := fs.ReadFile(staticFS, "js/api.js")
	if err != nil {
		t.Fatalf("failed to read js/api.js: %v", err)
	}
	apiStr := string(apiData)

	// Extract getCsrfToken function body
	startIdx := strings.Index(apiStr, "function getCsrfToken()")
	if startIdx == -1 {
		t.Fatalf("getCsrfToken function definition not found in js/api.js")
	}

	// Find the boundary before window.getCsrfToken export
	endIdx := strings.Index(apiStr[startIdx:], "// Ensure window.getCsrfToken")
	if endIdx == -1 {
		t.Fatalf("window.getCsrfToken export boundary not found in js/api.js")
	}
	csrfFuncBody := apiStr[startIdx : startIdx+endIdx]

	// 1. Assert getCsrfToken does NOT call window.getCsrfToken (preventing infinite recursion)
	if strings.Contains(csrfFuncBody, "window.getCsrfToken") {
		t.Errorf("getCsrfToken function body must not call window.getCsrfToken to prevent circular recursion")
	}

	// 2. Assert getCsrfToken inspects meta tag and cookie
	requiredInspections := []string{
		`meta[name="csrf-token"]`,
		`getAttribute('content')`,
		`csrftoken=([^;]+)`,
	}
	for _, req := range requiredInspections {
		if !strings.Contains(csrfFuncBody, req) {
			t.Errorf("getCsrfToken missing required inspection %q", req)
		}
	}

	// 3. Assert window.getCsrfToken is safely exported
	if !strings.Contains(apiStr, "window.getCsrfToken = getCsrfToken;") {
		t.Errorf("js/api.js must safely export window.getCsrfToken")
	}
}
