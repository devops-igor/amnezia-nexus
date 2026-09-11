package web

import (
	"encoding/json"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func TestEmbeddedTranslations(t *testing.T) {
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	requiredTranslations := []string{"en.json", "fa.json", "fr.json", "ru.json", "zh.json"}
	for _, langFile := range requiredTranslations {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Errorf("failed to read embedded translation %s: %v", langFile, err)
		}
		if len(data) == 0 {
			t.Errorf("embedded translation %s is empty", langFile)
		}

		var parsed map[string]string
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Errorf("embedded translation %s is not valid JSON: %v", langFile, err)
		}
		if len(parsed) == 0 {
			t.Errorf("embedded translation %s parsed to empty map", langFile)
		}
		for _, key := range []string{"vpn_delete", "vpn_confirm_delete"} {
			if _, ok := parsed[key]; !ok {
				t.Errorf("embedded translation %s missing key %q", langFile, key)
			}
		}
	}
}

func TestEmbeddedStaticAndTemplates(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	staticDirs := []string{"css", "js"}
	for _, dir := range staticDirs {
		if _, err := fs.Stat(staticFS, dir); err != nil {
			t.Errorf("static/%s directory not found in embed: %v", dir, err)
		}
	}

	staticFiles := []string{
		"css/style.css",
		"js/qrcode.min.js",
		"js/api.js",
		"js/ui.js",
		"js/tables.js",
		"js/telemetry.js",
		"favicon.svg",
	}
	for _, file := range staticFiles {
		if data, err := fs.ReadFile(staticFS, file); err != nil || len(data) == 0 {
			t.Errorf("static/%s missing or empty: %v", file, err)
		}
	}

	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	requiredTemplates := []string{
		"base.html",
		"index.html",
		"server.html",
		"users.html",
		"my_connections.html",
		"settings.html",
		"login.html",
		"setup.html",
		"change_password.html",
		"leaderboard.html",
		"user_share.html",
		"vpn.html",
		"icons.html",
	}

	for _, tmpl := range requiredTemplates {
		data, err := fs.ReadFile(templatesFS, tmpl)
		if err != nil {
			t.Errorf("template %s not found in embed: %v", tmpl, err)
		}
		if len(data) == 0 {
			t.Errorf("template %s is empty", tmpl)
		}
	}
}

func TestModernDesignSystemAndShell(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	cssData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	css := string(cssData)

	requiredCSSTokens := []string{
		"--bg-primary: #090a0f",
		"--bg-surface: #0d0e15",
		"--bg-card: #13151f",
		"--accent: #6366f1",
		"--success: #10b981",
		"--warning: #f59e0b",
		"--danger: #f43f5e",
		"--info: #0ea5e9",
		"--font-family: 'Inter'",
		"--font-mono: 'JetBrains Mono'",
	}
	for _, token := range requiredCSSTokens {
		if !strings.Contains(css, token) {
			t.Errorf("style.css missing required design token %q", token)
		}
	}

	requiredCSSClasses := []string{
		".app-layout",
		".app-sidebar",
		".app-main",
		".mobile-topbar",
		".drawer-backdrop",
		".mobile-bottom-bar",
		".icon",
		".nav-icon",
		".sidebar-nav-link",
	}
	for _, cls := range requiredCSSClasses {
		if !strings.Contains(css, cls) {
			t.Errorf("style.css missing required layout class %q", cls)
		}
	}

	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	iconsData, err := fs.ReadFile(templatesFS, "icons.html")
	if err != nil {
		t.Fatalf("failed to read icons.html: %v", err)
	}
	icons := string(iconsData)

	requiredIcons := []string{
		"id=\"icon-server\"",
		"id=\"icon-shield\"",
		"id=\"icon-users\"",
		"id=\"icon-network\"",
		"id=\"icon-settings\"",
		"id=\"icon-lock\"",
		"id=\"icon-key\"",
		"id=\"icon-plug\"",
		"id=\"icon-trophy\"",
		"id=\"icon-sun\"",
		"id=\"icon-moon\"",
		"id=\"icon-globe\"",
		"id=\"icon-logout\"",
		"id=\"icon-menu\"",
		"id=\"icon-x\"",
		"id=\"icon-pencil\"",
		"id=\"icon-trash\"",
		"id=\"icon-plus\"",
		"id=\"icon-chevron-right\"",
	}
	for _, icon := range requiredIcons {
		if !strings.Contains(icons, icon) {
			t.Errorf("icons.html missing expected icon symbol %q", icon)
		}
	}

	baseData, err := fs.ReadFile(templatesFS, "base.html")
	if err != nil {
		t.Fatalf("failed to read base.html: %v", err)
	}
	base := string(baseData)

	requiredBaseElements := []string{
		"class=\"app-layout\"",
		"id=\"appSidebar\"",
		"class=\"sidebar-header\"",
		"class=\"sidebar-nav\"",
		"class=\"sidebar-footer\"",
		"class=\"mobile-topbar\"",
		"id=\"drawerToggle\"",
		"id=\"drawerBackdrop\"",
		"class=\"mobile-bottom-bar\"",
		"toggleMobileDrawer",
		"href=\"#icon-plug\"",
	}
	for _, elem := range requiredBaseElements {
		if !strings.Contains(base, elem) {
			t.Errorf("base.html missing required responsive shell element %q", elem)
		}
	}
}

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
		"root.apiCall",
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
		"escapeHtml",
		"escapeJs",
	}
	for _, sig := range requiredUISignatures {
		if !strings.Contains(uiStr, sig) {
			t.Errorf("js/ui.js missing required signature %q", sig)
		}
	}

	// 3. Assert style.css skeleton shimmer and micro-interactions
	cssData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	cssStr := string(cssData)
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
			t.Errorf("style.css missing required skeleton or micro-interaction token %q", item)
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

	// 3. Assert style.css Phase 3 styles
	cssData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	cssStr := string(cssData)
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
		"@keyframes pulse-dot",
		".live-dot",
		".live-badge",
		".metric-card-stat",
	}
	for _, item := range requiredCSSPhase3 {
		if !strings.Contains(cssStr, item) {
			t.Errorf("style.css missing required Phase 3 CSS token %q", item)
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

func TestPhase4DashboardAndServerModernization(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	// 1. Assert index.html modernizations
	indexData, err := fs.ReadFile(templatesFS, "index.html")
	if err != nil {
		t.Fatalf("failed to read index.html: %v", err)
	}
	indexStr := string(indexData)

	requiredIndexTokens := []string{
		"href=\"#icon-server\"",
		"href=\"#icon-plus\"",
		"href=\"#icon-pencil\"",
		"href=\"#icon-trash\"",
		"href=\"#icon-shield\"",
		"href=\"#icon-search\"",
		"table-toolbar",
		"table-search-box",
		"table-search-input",
		"filterServers",
		"serverSearchEmpty",
		"UI.confirm",
		"API.post",
		"UI.toast",
	}
	for _, token := range requiredIndexTokens {
		if !strings.Contains(indexStr, token) {
			t.Errorf("index.html missing required modernized token %q", token)
		}
	}

	// Ensure raw confirm() is not used in index.html
	if strings.Contains(indexStr, "if (!confirm(") || strings.Contains(indexStr, "if(!confirm(") {
		t.Errorf("index.html should not use raw confirm(), must use UI.confirm")
	}

	// 2. Assert server.html modernizations
	serverData, err := fs.ReadFile(templatesFS, "server.html")
	if err != nil {
		t.Fatalf("failed to read server.html: %v", err)
	}
	serverStr := string(serverData)

	requiredServerTokens := []string{
		"href=\"#icon-server\"",
		"href=\"#icon-pencil\"",
		"href=\"#icon-refresh\"",
		"href=\"#icon-activity\"",
		"href=\"#icon-network\"",
		"href=\"#icon-shield\"",
		"href=\"#icon-settings\"",
		"href=\"#icon-copy\"",
		"href=\"#icon-file-text\"",
		"href=\"#icon-trash\"",
		"UI.confirm",
		"UI.copy",
		"UI.downloadFile",
		"UI.toast",
		"API.get",
		"API.post",
		"API.patch",
		"NexusTable",
		"connectionsTable",
		"connectionsTableContainer",
		"data-sort-type",
		"data-searchable",
		"reachabilityOverallBadge",
	}
	for _, token := range requiredServerTokens {
		if !strings.Contains(serverStr, token) {
			t.Errorf("server.html missing required modernized token %q", token)
		}
	}

	// Ensure raw confirm(), apiCall(), showToast() are not used in server.html
	if strings.Contains(serverStr, "if (!confirm(") || strings.Contains(serverStr, "if(!confirm(") {
		t.Errorf("server.html should not use raw confirm(), must use UI.confirm")
	}
	if strings.Contains(serverStr, "apiCall(") {
		t.Errorf("server.html should not use apiCall(), must use API client")
	}
	if strings.Contains(serverStr, "showToast(") {
		t.Errorf("server.html should not use showToast(), must use UI.toast")
	}
}

func TestPhase5VPNAndUsersModernization(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	// 1. Assert vpn.html modernizations
	vpnData, err := fs.ReadFile(templatesFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}
	vpnStr := string(vpnData)

	requiredVPNTokens := []string{
		"href=\"#icon-shield\"",
		"href=\"#icon-network\"",
		"href=\"#icon-server\"",
		"href=\"#icon-plus\"",
		"href=\"#icon-pencil\"",
		"href=\"#icon-trash\"",
		"href=\"#icon-activity\"",
		"href=\"#icon-x\"",
		"UI.confirm",
		"UI.toast",
		"API.get",
		"API.post",
		"API.delete",
		"API.request",
		"NexusTable",
		"NexusTelemetry.poll",
		"Telemetry.formatBytes",
		"vpnBackendsTable",
		"vpnTableContainer",
		"data-sort-type",
		"vpn-listener-badge",
		"vpn-public-endpoint",
		"vpn_delete",
		"vpn_confirm_delete",
	}
	for _, token := range requiredVPNTokens {
		if !strings.Contains(vpnStr, token) {
			t.Errorf("vpn.html missing required modernized token %q", token)
		}
	}

	// Ensure raw confirm(), apiCall(), showToast() are eliminated from vpn.html
	if strings.Contains(vpnStr, "if (!confirm(") || strings.Contains(vpnStr, "if(!confirm(") {
		t.Errorf("vpn.html should not use raw confirm(), must use UI.confirm")
	}
	if strings.Contains(vpnStr, "apiCall(") {
		t.Errorf("vpn.html should not use apiCall(), must use API client")
	}
	if strings.Contains(vpnStr, "showToast(") {
		t.Errorf("vpn.html should not use showToast(), must use UI.toast")
	}

	// 2. Assert users.html modernizations
	usersData, err := fs.ReadFile(templatesFS, "users.html")
	if err != nil {
		t.Fatalf("failed to read users.html: %v", err)
	}
	usersStr := string(usersData)

	requiredUsersTokens := []string{
		"href=\"#icon-users\"",
		"href=\"#icon-user\"",
		"href=\"#icon-plus\"",
		"href=\"#icon-pencil\"",
		"href=\"#icon-trash\"",
		"href=\"#icon-search\"",
		"href=\"#icon-file-text\"",
		"href=\"#icon-network\"",
		"href=\"#icon-x\"",
		"href=\"#icon-copy\"",
		"table-toolbar",
		"table-search-box",
		"table-search-input",
		"table-filter-chips",
		"filter-chip",
		"roleFilterChips",
		"UI.confirm",
		"UI.copy",
		"UI.toast",
		"API.get",
		"API.post",
		"NexusTable",
		"userConnsTable",
		"Telemetry.formatBytes",
	}
	for _, token := range requiredUsersTokens {
		if !strings.Contains(usersStr, token) {
			t.Errorf("users.html missing required modernized token %q", token)
		}
	}

	// Ensure raw confirm(), apiCall(), showToast() are eliminated from users.html
	if strings.Contains(usersStr, "if (!confirm(") || strings.Contains(usersStr, "if(!confirm(") {
		t.Errorf("users.html should not use raw confirm(), must use UI.confirm")
	}
	if strings.Contains(usersStr, "apiCall(") {
		t.Errorf("users.html should not use apiCall(), must use API client")
	}
	if strings.Contains(usersStr, "showToast(") {
		t.Errorf("users.html should not use showToast(), must use UI.toast")
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
		"href=\"#icon-book\"",
		"href=\"#icon-lock\"",
		"href=\"#icon-send\"",
		"href=\"#icon-refresh\"",
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

	// 5. CSS Tokens and RTL Rules in style.css
	cssData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	cssStr := string(cssData)

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
			t.Errorf("style.css missing required Phase 6 CSS rule %q", rule)
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

func TestLoadBalancerHighlightAndAwgPreselection(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	myConnData, err := fs.ReadFile(templatesFS, "my_connections.html")
	if err != nil {
		t.Fatalf("failed to read my_connections.html: %v", err)
	}
	myConnStr := string(myConnData)

	// 1. Assert presence of .lb-selection-callout, lbHighlightCallout, and load_balancer_auto in my_connections.html
	requiredHTMLElements := []string{
		`class="lb-selection-callout"`,
		`id="lbHighlightCallout"`,
		`load_balancer_auto`,
		`load_balancer_recommended_hint`,
		`data-is-lb="true" selected`,
	}
	for _, elem := range requiredHTMLElements {
		if !strings.Contains(myConnStr, elem) {
			t.Errorf("my_connections.html missing required element %q", elem)
		}
	}

	// 2. Assert pre-selection of Load Balancer and 'awg' (AmneziaWG) in my_connections.html JavaScript
	requiredJSLogic := []string{
		`serverSelect.value = '0'`,
		`protoSelect.value = 'awg'`,
		`lbCallout.style.display = serverSelect.value === '0' ? 'flex' : 'none'`,
		`document.getElementById('myAwgMimicryGroup').style.display = protoSelect.value === 'awg' ? '' : 'none'`,
	}
	for _, js := range requiredJSLogic {
		if !strings.Contains(myConnStr, js) {
			t.Errorf("my_connections.html missing required JS logic %q", js)
		}
	}

	// 3. Assert CSS contains .lb-selection-callout and RTL rules
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	cssData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	cssStr := string(cssData)
	if !strings.Contains(cssStr, ".lb-selection-callout") {
		t.Errorf("style.css missing .lb-selection-callout")
	}
	if !strings.Contains(cssStr, `[dir="rtl"] .lb-selection-callout`) {
		t.Errorf("style.css missing RTL rule for .lb-selection-callout")
	}

	// 4. Assert presence of the new keys in all 5 JSON translation files
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}
	requiredKeys := []string{
		"load_balancer_auto",
		"recommended",
		"load_balancer_recommended_hint",
	}
	languages := []string{"en.json", "fa.json", "fr.json", "ru.json", "zh.json"}
	for _, langFile := range languages {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", langFile, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
		}
		for _, k := range requiredKeys {
			val, ok := dict[k]
			if !ok || strings.TrimSpace(val) == "" {
				t.Errorf("%s missing or empty required key %q", langFile, k)
			}
		}
	}
}

func TestModernClientDashboardPage(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	// 1. Assert icons.html and base.html contain icon-plug symbol definition
	iconsData, err := fs.ReadFile(templatesFS, "icons.html")
	if err != nil {
		t.Fatalf("failed to read icons.html: %v", err)
	}
	if !strings.Contains(string(iconsData), `id="icon-plug"`) {
		t.Errorf("icons.html missing id=\"icon-plug\" symbol")
	}

	baseData, err := fs.ReadFile(templatesFS, "base.html")
	if err != nil {
		t.Fatalf("failed to read base.html: %v", err)
	}
	baseStr := string(baseData)
	if !strings.Contains(baseStr, `id="icon-plug"`) {
		t.Errorf("base.html missing embedded id=\"icon-plug\" symbol")
	}

	// 2. Assert navigation links to /my use icon-plug
	if !strings.Contains(baseStr, `<span class="nav-icon"><svg class="icon"><use href="#icon-plug"></use></svg></span>`) {
		t.Errorf("base.html sidebar /my link missing href=\"#icon-plug\"")
	}
	if !strings.Contains(baseStr, `<a href="/my" class="bottom-bar-link {{ if eq .active_page "my_connections" }}active{{ end }}">`+"\n"+`                <svg class="icon"><use href="#icon-plug"></use></svg>`) {
		t.Errorf("base.html mobile bottom bar /my link missing href=\"#icon-plug\"")
	}

	// 3. Assert my_connections.html uses icon-plug for header and connection avatars
	myConnData, err := fs.ReadFile(templatesFS, "my_connections.html")
	if err != nil {
		t.Fatalf("failed to read my_connections.html: %v", err)
	}
	myConnStr := string(myConnData)
	if !strings.Contains(myConnStr, `href="#icon-plug"`) {
		t.Errorf("my_connections.html missing href=\"#icon-plug\"")
	}
	if !strings.Contains(myConnStr, `<span class="icon"><svg class="icon"><use href="#icon-plug"></use></svg></span>`) {
		t.Errorf("my_connections.html header title missing href=\"#icon-plug\"")
	}
	if !strings.Contains(myConnStr, `<div class="client-avatar">`+"\n"+`                    <svg class="icon"><use href="#icon-plug"></use></svg>`) {
		t.Errorf("my_connections.html card avatar missing href=\"#icon-plug\"")
	}

	// 4. Assert vpn_key_tab uses icon-lock instead of broken icon-key
	if !strings.Contains(myConnStr, `href="#icon-lock"`) {
		t.Errorf("my_connections.html should contain href=\"#icon-lock\" for vpn_key_tab")
	}
	if strings.Contains(myConnStr, `href="#icon-key"`) {
		t.Errorf("my_connections.html must not contain href=\"#icon-key\"")
	}
}

func TestIssue101VPNModernization(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	// 1. Assert vpn.html contains all 36 required DOM element IDs
	vpnData, err := fs.ReadFile(templatesFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}
	vpnStr := string(vpnData)

	requiredDOMIDs := []string{
		"vpn-listener-badge",
		"vpn-listen-port",
		"vpn-subnet",
		"vpn-public-endpoint",
		"vpn-edit-endpoint-btn",
		"vpn-sessions",
		"vpn-active-tunnels",
		"vpn-rx",
		"vpn-tx",
		"vpnTableContainer",
		"vpnBackendsTable",
		"vpn-backends-tbody",
		"vpn-backends-loading",
		"vpn-add-backend-btn",
		"addBackendModal",
		"addBackendForm",
		"vpnServerSelect",
		"vpnServerDetails",
		"vpnServerDetailHost",
		"vpnServerDetailPort",
		"vpnServerDetailStatus",
		"vpnServerDetailAwgBadge",
		"vpnServerDetailCheckRow",
		"vpnServerDetailCheckHint",
		"vpnQuickCheckBtn",
		"vpnQuickCheckBtnText",
		"vpnQuickCheckIcon",
		"vpnQuickCheckSpinner",
		"vpnNoServersNotice",
		"vpnModalError",
		"vpnAddBackendSubmitBtn",
		"editEndpointModal",
		"editEndpointForm",
		"vpnPublicEndpointInput",
		"vpnEndpointModalError",
		"vpnEditEndpointSubmitBtn",
	}
	for _, id := range requiredDOMIDs {
		if !strings.Contains(vpnStr, `id="`+id+`"`) {
			t.Errorf("vpn.html missing required DOM element id=%q", id)
		}
	}

	// 2. Assert broken 8px yellow speck is eliminated and replaced with pause/play icon buttons
	if strings.Contains(vpnStr, "width:8px") || strings.Contains(vpnStr, "height:8px") {
		t.Errorf("vpn.html should not contain broken 8px dot toggle button")
	}
	if !strings.Contains(vpnStr, `href="#icon-pause"`) {
		t.Errorf("vpn.html missing href=\"#icon-pause\" for active backend toggle")
	}
	if !strings.Contains(vpnStr, `href="#icon-play"`) {
		t.Errorf("vpn.html missing href=\"#icon-play\" for disabled backend toggle")
	}

	// 3. Assert latency tiers and indicators in JS
	requiredLatencyTokens := []string{
		"latency-pill",
		"latency-good",
		"latency-fair",
		"latency-poor",
		"latency-dot",
	}
	for _, token := range requiredLatencyTokens {
		if !strings.Contains(vpnStr, token) {
			t.Errorf("vpn.html missing required latency token %q", token)
		}
	}

	// 4. Assert NexusTable options include statusFilters and statusAttribute
	requiredTableOptions := []string{
		"statusFilters: ['all', 'active', 'degraded', 'disabled']",
		"statusAttribute: 'data-status'",
		"searchPlaceholder",
		"emptyMessage",
	}
	for _, opt := range requiredTableOptions {
		if !strings.Contains(vpnStr, opt) {
			t.Errorf("vpn.html missing NexusTable option %q", opt)
		}
	}

	// 5. Assert hardcoded English strings eliminated from stat cards
	unwantedEnglishTokens := []string{
		"Entry point for LB traffic",
		"Telemetry live",
	}
	for _, token := range unwantedEnglishTokens {
		if strings.Contains(vpnStr, token) {
			t.Errorf("vpn.html still contains raw English string %q", token)
		}
	}

	// 6. Assert icons.html and base.html contain icon-play and icon-pause
	iconsData, err := fs.ReadFile(templatesFS, "icons.html")
	if err != nil {
		t.Fatalf("failed to read icons.html: %v", err)
	}
	iconsStr := string(iconsData)
	if !strings.Contains(iconsStr, `id="icon-play"`) {
		t.Errorf("icons.html missing id=\"icon-play\" symbol")
	}
	if !strings.Contains(iconsStr, `id="icon-pause"`) {
		t.Errorf("icons.html missing id=\"icon-pause\" symbol")
	}

	baseData, err := fs.ReadFile(templatesFS, "base.html")
	if err != nil {
		t.Fatalf("failed to read base.html: %v", err)
	}
	baseStr := string(baseData)
	if !strings.Contains(baseStr, `id="icon-play"`) {
		t.Errorf("base.html missing id=\"icon-play\" symbol")
	}
	if !strings.Contains(baseStr, `id="icon-pause"`) {
		t.Errorf("base.html missing id=\"icon-pause\" symbol")
	}

	// 7. Assert tables.js supports statusFilters and container placement
	tablesData, err := fs.ReadFile(staticFS, "js/tables.js")
	if err != nil {
		t.Fatalf("failed to read js/tables.js: %v", err)
	}
	tablesStr := string(tablesData)
	if !strings.Contains(tablesStr, "statusFilters: null") {
		t.Errorf("tables.js DEFAULT_OPTIONS missing statusFilters")
	}
	if !strings.Contains(tablesStr, "table-container") {
		t.Errorf("tables.js missing table-container placement handling")
	}

	// 8. Assert style.css contains modern VPN, stat-card, latency pill, and info-card classes
	cssData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	cssStr := string(cssData)
	requiredCSSClasses := []string{
		".stat-card",
		".stat-card-header",
		".stat-card-title",
		".stat-card-value",
		".stat-card-sub",
		".latency-pill",
		".latency-good",
		".latency-fair",
		".latency-poor",
		".latency-dot",
		".info-card",
		".info-card-grid",
		".info-card-item",
		".info-card-label",
		".info-card-value",
		".interactive-table th",
		".interactive-table td",
	}
	for _, cls := range requiredCSSClasses {
		if !strings.Contains(cssStr, cls) {
			t.Errorf("style.css missing required class definition %q", cls)
		}
	}
	if !strings.Contains(cssStr, ".interactive-table") || !strings.Contains(cssStr, "width: 100%") {
		t.Errorf("style.css missing .interactive-table with width: 100%%")
	}

	// 9. Assert presence of new VPN keys across all 5 translations
	newVPNTranslationKeys := []string{
		"vpn_bandwidth",
		"vpn_entry_point_hint",
		"vpn_telemetry_live",
		"vpn_port",
		"vpn_unset_auto",
		"vpn_unset_auto_detected",
		"vpn_search_backends",
		"vpn_no_backends_desc",
	}
	languages := []string{"en.json", "fa.json", "fr.json", "ru.json", "zh.json"}
	for _, langFile := range languages {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", langFile, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
		}
		for _, k := range newVPNTranslationKeys {
			val, ok := dict[k]
			if !ok || strings.TrimSpace(val) == "" {
				t.Errorf("%s missing or empty required VPN key %q", langFile, k)
			}
		}
		if langFile == "en.json" {
			if dict["vpn_unset_auto"] != "Auto-detect" {
				t.Errorf("en.json vpn_unset_auto = %q, want %q", dict["vpn_unset_auto"], "Auto-detect")
			}
			if dict["vpn_unset_auto_detected"] != "Auto: %s" {
				t.Errorf("en.json vpn_unset_auto_detected = %q, want %q", dict["vpn_unset_auto_detected"], "Auto: %s")
			}
		}
	}
}

func TestIssue101ShowConfigIconRework(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	// 1. my_connections.html: Show config buttons must use #icon-file-text, vpn_key_tab must use #icon-lock
	myConnData, err := fs.ReadFile(templatesFS, "my_connections.html")
	if err != nil {
		t.Fatalf("failed to read my_connections.html: %v", err)
	}
	myConnStr := string(myConnData)

	expectedStaticShowConfig := `<svg class="icon"><use href="#icon-file-text"></use></svg> {{ _ "show_config" }}`
	if !strings.Contains(myConnStr, expectedStaticShowConfig) {
		t.Errorf("my_connections.html missing static show_config button with #icon-file-text")
	}
	oldStaticShowConfig := `<svg class="icon"><use href="#icon-key"></use></svg> {{ _ "show_config" }}`
	if strings.Contains(myConnStr, oldStaticShowConfig) {
		t.Errorf("my_connections.html still contains old static show_config button with #icon-key")
	}

	expectedDynamicShowConfig := `<svg class="icon"><use href="#icon-file-text"></use></svg> ${_('show_config')}`
	if !strings.Contains(myConnStr, expectedDynamicShowConfig) {
		t.Errorf("my_connections.html missing dynamic show_config button with #icon-file-text")
	}
	oldDynamicShowConfig := `<svg class="icon"><use href="#icon-key"></use></svg> ${_('show_config')}`
	if strings.Contains(myConnStr, oldDynamicShowConfig) {
		t.Errorf("my_connections.html still contains old dynamic show_config button with #icon-key")
	}

	expectedKeyTab := `<svg class="icon" style="width:14px;height:14px;"><use href="#icon-lock"></use></svg> {{ _ "vpn_key_tab" }}`
	if !strings.Contains(myConnStr, expectedKeyTab) {
		t.Errorf("my_connections.html must use #icon-lock for vpn_key_tab")
	}
	if strings.Contains(myConnStr, `href="#icon-key"`) {
		t.Errorf("my_connections.html must not contain href=\"#icon-key\"")
	}

	// 2. users.html: No #icon-key, all config and share headers/buttons use #icon-file-text
	usersData, err := fs.ReadFile(templatesFS, "users.html")
	if err != nil {
		t.Fatalf("failed to read users.html: %v", err)
	}
	usersStr := string(usersData)

	if strings.Contains(usersStr, `href="#icon-key"`) {
		t.Errorf("users.html must not contain href=\"#icon-key\"")
	}
	if !strings.Contains(usersStr, `href="#icon-file-text"`) {
		t.Errorf("users.html must contain href=\"#icon-file-text\"")
	}
	if !strings.Contains(usersStr, `showUserConnectionConfig`) {
		t.Errorf("users.html missing showUserConnectionConfig")
	}

	// 3. server.html: No #icon-key, connections config button uses #icon-file-text
	serverData, err := fs.ReadFile(templatesFS, "server.html")
	if err != nil {
		t.Fatalf("failed to read server.html: %v", err)
	}
	serverStr := string(serverData)

	if strings.Contains(serverStr, `href="#icon-key"`) {
		t.Errorf("server.html must not contain href=\"#icon-key\"")
	}
	if !strings.Contains(serverStr, `href="#icon-file-text"`) {
		t.Errorf("server.html must contain href=\"#icon-file-text\" for client config button")
	}

	// 4. Assert zero templates contain href="#icon-key"
	entries, err := fs.ReadDir(templatesFS, ".")
	if err != nil {
		t.Fatalf("failed to list templates: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".html") {
			continue
		}
		tmplData, err := fs.ReadFile(templatesFS, entry.Name())
		if err != nil {
			t.Fatalf("failed to read template %s: %v", entry.Name(), err)
		}
		if strings.Contains(string(tmplData), `href="#icon-key"`) {
			t.Errorf("template %s contains forbidden href=\"#icon-key\"", entry.Name())
		}
	}
}

func TestIssue101VPNPolishRework(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	// 1. Live telemetry green dot spacing in vpn.html and style.css .gap-xs
	vpnData, err := fs.ReadFile(templatesFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}
	vpnStr := string(vpnData)
	if !strings.Contains(vpnStr, `style="gap: var(--space-sm);"`) {
		t.Errorf("vpn.html missing style=\"gap: var(--space-sm);\" for live telemetry dot spacing")
	}

	cssData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	cssStr := string(cssData)
	if !strings.Contains(cssStr, ".gap-xs {") || !strings.Contains(cssStr, "gap: var(--space-xs);") {
		t.Errorf("style.css missing .gap-xs utility class")
	}

	// 2. Public Endpoint text simplification
	expectedAutoTranslations := map[string][2]string{
		"en.json": {"Auto-detect", "Auto: %s"},
		"ru.json": {"Автоопределение", "Авто: %s"},
		"fr.json": {"Détection auto", "Auto : %s"},
		"fa.json": {"تشخیص خودکار", "خودکار: %s"},
		"zh.json": {"自动检测", "自动：%s"},
	}
	for langFile, expected := range expectedAutoTranslations {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", langFile, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
		}
		if dict["vpn_unset_auto"] != expected[0] {
			t.Errorf("%s vpn_unset_auto = %q, want %q", langFile, dict["vpn_unset_auto"], expected[0])
		}
		if dict["vpn_unset_auto_detected"] != expected[1] {
			t.Errorf("%s vpn_unset_auto_detected = %q, want %q", langFile, dict["vpn_unset_auto_detected"], expected[1])
		}
	}

	// Assert vpn.html JS fallback uses simplified strings
	if !strings.Contains(vpnStr, `'Auto: %s'`) {
		t.Errorf("vpn.html missing 'Auto: %%s' fallback")
	}
	if !strings.Contains(vpnStr, `'Auto-detect'`) {
		t.Errorf("vpn.html missing 'Auto-detect' fallback")
	}

	// 3. VPN Backends table width 100%
	if !strings.Contains(cssStr, ".interactive-table {\n    width: 100%;\n    min-width: 100%;\n    border-collapse: collapse;\n}") {
		t.Errorf("style.css missing .interactive-table with width: 100%%, min-width: 100%%, and border-collapse: collapse")
	}
	if !strings.Contains(cssStr, ".table-container table {\n    width: 100%;\n    min-width: 100%;\n    border-collapse: collapse;\n}") {
		t.Errorf("style.css missing .table-container table with width: 100%%, min-width: 100%%, and border-collapse: collapse")
	}
	if !strings.Contains(vpnStr, `id="vpnTableContainer"`) {
		t.Errorf("vpn.html missing #vpnTableContainer")
	}
	if !strings.Contains(vpnStr, `class="table interactive-table" id="vpnBackendsTable"`) {
		t.Errorf("vpn.html missing table.interactive-table#vpnBackendsTable")
	}
}

func TestIssue109VPNTableFullWidth(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	// 1. Assert style.css rules for .interactive-table and .table-container table
	cssData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	cssStr := string(cssData)
	if !strings.Contains(cssStr, ".interactive-table {\n    width: 100%;\n    min-width: 100%;\n    border-collapse: collapse;\n}") {
		t.Errorf("style.css missing .interactive-table with width: 100%% and min-width: 100%%")
	}
	if !strings.Contains(cssStr, ".table-container table {\n    width: 100%;\n    min-width: 100%;\n    border-collapse: collapse;\n}") {
		t.Errorf("style.css missing .table-container table with width: 100%% and min-width: 100%%")
	}

	// 2. Assert vpn.html contains table#vpnBackendsTable with 100% width and min-width
	vpnData, err := fs.ReadFile(templatesFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}
	vpnStr := string(vpnData)
	if !strings.Contains(vpnStr, `<table class="table interactive-table" id="vpnBackendsTable" style="width: 100%; min-width: 100%;">`) {
		t.Errorf("vpn.html missing table#vpnBackendsTable with style=\"width: 100%%; min-width: 100%%;\"")
	}
	if !strings.Contains(vpnStr, `id="vpnTableContainer"`) {
		t.Errorf("vpn.html missing #vpnTableContainer")
	}

	// 3. Assert stylesheet cache-busting (?v=1.1.0) across all shell and auth templates
	templatesToCheck := []string{"base.html", "login.html", "change_password.html", "setup.html"}
	for _, tmpl := range templatesToCheck {
		tmplData, err := fs.ReadFile(templatesFS, tmpl)
		if err != nil {
			t.Fatalf("failed to read %s: %v", tmpl, err)
		}
		tmplStr := string(tmplData)
		if !strings.Contains(tmplStr, `href="/static/css/style.css?v=1.1.0"`) {
			t.Errorf("%s missing stylesheet cache busting query param ?v=1.1.0", tmpl)
		}
	}
}

func TestIssue113UsersUIModernization(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	usersData, err := fs.ReadFile(templatesFS, "users.html")
	if err != nil {
		t.Fatalf("failed to read users.html: %v", err)
	}
	usersStr := string(usersData)

	// 1. Assert users.html references #icon-pause and #icon-play for user toggle controls
	if !strings.Contains(usersStr, `href="#icon-pause"`) {
		t.Errorf("users.html missing href=\"#icon-pause\" for active user toggle control")
	}
	if !strings.Contains(usersStr, `href="#icon-play"`) {
		t.Errorf("users.html missing href=\"#icon-play\" for disabled user toggle control")
	}

	// 2. Assert users.html does not contain the old dot toggle markup for user toggling
	if strings.Contains(usersStr, "badge-dot") {
		t.Errorf("users.html must not contain legacy dot toggle markup (badge-dot)")
	}

	// 3. Assert #userConnsTable has width: 100% and min-width: 100%
	if !strings.Contains(usersStr, `<table class="table interactive-table" id="userConnsTable" style="width: 100%; min-width: 100%;">`) {
		t.Errorf("users.html missing table#userConnsTable with style=\"width: 100%%; min-width: 100%%;\"")
	}

	// 4. Assert #usersContainer and #usersGrid expand to full width
	if !strings.Contains(usersStr, `id="usersContainer" class="hidden" style="width: 100%; min-width: 100%;"`) {
		t.Errorf("users.html missing #usersContainer with width: 100%% and min-width: 100%%")
	}
	if !strings.Contains(usersStr, `id="usersGrid"`) || !strings.Contains(usersStr, `width: 100%; min-width: 100%;`) {
		t.Errorf("users.html missing #usersGrid with width: 100%% and min-width: 100%%")
	}

	// 5. Assert action buttons use standardized button classes and danger hover
	if !strings.Contains(usersStr, `btn-danger-hover`) {
		t.Errorf("users.html missing btn-danger-hover class on delete action buttons")
	}
	if !strings.Contains(usersStr, `btn-success-hover`) {
		t.Errorf("users.html missing btn-success-hover class on play toggle button")
	}

	// 6. Assert required DOM element IDs are preserved
	requiredDOMIDs := []string{
		"userSearch", "userSearchClear", "roleFilterChips", "usersContainer", "usersGrid",
		"pagination", "prevPage", "pageInfo", "nextPage", "usersLoading", "usersEmpty",
		"addUserModal", "addUserForm", "newUsername", "newPassword", "newRole", "newTelegramId",
		"newEmail", "newTrafficLimit", "newTrafficResetStrategy", "newExpirationDate",
		"newDescription", "newUserServer", "newUserProtocol",
		"editUserModal", "editUserForm", "editUserId", "editUsername", "editTelegramId",
		"editEmail", "editTrafficLimit", "editTrafficResetStrategy", "editExpirationDate", "editDescription",
		"addUserConnModal", "addUserConnForm", "ucUserId", "ucServer", "ucProtocol", "ucName",
		"userConnsModal", "userConnsTitle", "userConnsTableContainer", "userConnsTable",
		"userConnsTableBody", "userConnsEmpty",
		"configModal", "configModalTitle", "configText", "configQrCode",
		"shareUserModal", "shareForm", "shareUserId", "shareUsername", "shareLinkInput",
		"shareEnabled", "sharePassword",
	}
	for _, id := range requiredDOMIDs {
		if !strings.Contains(usersStr, `id="`+id+`"`) {
			t.Errorf("users.html missing required DOM element id=%q", id)
		}
	}

	// 7. Assert style.css contains .clients-list, #usersContainer, #usersGrid, and #userConnsTable width rules
	cssData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	cssStr := string(cssData)
	if !strings.Contains(cssStr, "#usersContainer {\n    width: 100%;\n    min-width: 100%;\n}") {
		t.Errorf("style.css missing #usersContainer width rules")
	}
	if !strings.Contains(cssStr, "#usersGrid {\n    width: 100%;\n    min-width: 100%;\n}") {
		t.Errorf("style.css missing #usersGrid width rules")
	}
	if !strings.Contains(cssStr, "#userConnsTable {\n    width: 100%;\n    min-width: 100%;\n}") {
		t.Errorf("style.css missing #userConnsTable width rules")
	}
}

func TestIssue113TranslationParityAndValidity(t *testing.T) {
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	languages := []string{"en.json", "fa.json", "fr.json", "ru.json", "zh.json"}
	dicts := make(map[string]map[string]string)
	for _, langFile := range languages {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", langFile, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
		}
		dicts[langFile] = dict
	}

	// 1. Strict key parity across all 5 files
	baseKeys := dicts["en.json"]
	for _, langFile := range languages[1:] {
		curDict := dicts[langFile]
		if len(curDict) != len(baseKeys) {
			t.Errorf("key count mismatch between en.json (%d) and %s (%d)", len(baseKeys), langFile, len(curDict))
		}
		for k := range baseKeys {
			val, ok := curDict[k]
			if !ok {
				t.Errorf("%s is missing key %q present in en.json", langFile, k)
			} else if strings.TrimSpace(val) == "" {
				t.Errorf("%s has empty translation for key %q", langFile, k)
			}
		}
		for k := range curDict {
			if _, ok := baseKeys[k]; !ok {
				t.Errorf("%s has extra key %q not present in en.json", langFile, k)
			}
		}
	}

	// 2. Assert specific Issue #113 keys are defined
	requiredKeys := []string{
		"user_enable",
		"user_disable",
		"expired",
		"expires",
		"all",
		"role_admin",
		"role_support",
		"role_user",
		"role_filter",
		"connections_count",
		"delete_user_title",
		"delete_connection",
		"delete_conn_confirm",
		"select_connection",
		"search",
	}
	for _, k := range requiredKeys {
		for _, langFile := range languages {
			if val, ok := dicts[langFile][k]; !ok || strings.TrimSpace(val) == "" {
				t.Errorf("%s missing or empty required key %q", langFile, k)
			}
		}
	}

	// 3. Assert all template and JS translation keys in users.html exist across all 5 languages
	usersData, err := fs.ReadFile(templatesFS, "users.html")
	if err != nil {
		t.Fatalf("failed to read users.html: %v", err)
	}
	usersStr := string(usersData)

	tmplRe := regexp.MustCompile(`\{\{\s*_\s*"([^"]+)"\s*\}\}`)
	jsRe := regexp.MustCompile(`_\(\s*['"]([^'"]+)['"]\s*\)`)

	usersKeys := make(map[string]struct{})
	for _, m := range tmplRe.FindAllStringSubmatch(usersStr, -1) {
		usersKeys[m[1]] = struct{}{}
	}
	for _, m := range jsRe.FindAllStringSubmatch(usersStr, -1) {
		usersKeys[m[1]] = struct{}{}
	}

	for k := range usersKeys {
		for _, langFile := range languages {
			if val, ok := dicts[langFile][k]; !ok || strings.TrimSpace(val) == "" {
				t.Errorf("%s missing or empty translation for users.html key %q", langFile, k)
			}
		}
	}
}
