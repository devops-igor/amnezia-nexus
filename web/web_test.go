package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
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
		for _, key := range []string{"captcha_slide_prompt", "captcha_verified", "captcha_failed", "captcha_refresh"} {
			if parsed[key] == "" {
				t.Errorf("embedded translation %s missing captcha key %q", langFile, key)
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
		"js/captcha.js",
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

func TestLoginSlideCaptchaWiring(t *testing.T) {
	tmpl, err := fs.ReadFile(TemplatesFS, "templates/login.html")
	if err != nil {
		t.Fatal(err)
	}
	js, err := fs.ReadFile(StaticFS, "static/js/captcha.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"id=\"captchaPuzzle\"", "id=\"captchaHandle\"", "/static/js/captcha.js", "captcha_ticket"} {
		if !strings.Contains(string(tmpl), token) {
			t.Errorf("login page missing %s", token)
		}
	}
	if !strings.Contains(string(js), "/api/auth/captcha/verify") {
		t.Error("slider is not wired to verification endpoint")
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

func TestIssue115_RemoveApiDocsAndImportUsers(t *testing.T) {
	// 1. Assert absent translation keys across all 5 languages and verify 100% key parity
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	languages := []string{"en.json", "fa.json", "fr.json", "ru.json", "zh.json"}
	removedKeys := []string{
		"api_docs_title",
		"api_docs_hint",
		"import_users_title",
		"import_source_label",
		"remnawave_url_label",
		"api_key_label",
		"enable_sync",
		"sync_hint",
		"sync_now_btn",
		"delete_sync_btn",
		"auto_create_conns",
		"sync_server_label",
		"sync_running",
		"sync_success",
		"delete_sync_confirm",
		"sync_deleted",
	}

	dicts := make(map[string]map[string]string)
	for _, langFile := range languages {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", langFile, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("failed to parse %s: %v", langFile, err)
		}
		dicts[langFile] = dict

		for _, k := range removedKeys {
			if _, exists := dict[k]; exists {
				t.Errorf("%s still contains obsolete key %q", langFile, k)
			}
		}
	}

	// Verify 100% key parity across all 5 language dictionaries
	enDict := dicts["en.json"]
	for _, langFile := range languages {
		if langFile == "en.json" {
			continue
		}
		currDict := dicts[langFile]
		if len(currDict) != len(enDict) {
			t.Errorf("key count mismatch between en.json (%d) and %s (%d)", len(enDict), langFile, len(currDict))
		}
		for k := range enDict {
			if _, ok := currDict[k]; !ok {
				t.Errorf("%s missing key %q present in en.json", langFile, k)
			}
		}
		for k := range currDict {
			if _, ok := enDict[k]; !ok {
				t.Errorf("%s contains key %q not present in en.json", langFile, k)
			}
		}
	}

	// 2. Assert settings.html does not contain removed elements or functions
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	settingsData, err := fs.ReadFile(templatesFS, "settings.html")
	if err != nil {
		t.Fatalf("failed to read settings.html: %v", err)
	}
	settingsStr := string(settingsData)

	forbiddenTokens := []string{
		"api_docs_title",
		"api_docs_hint",
		"import_users_title",
		"syncRemnawaveNow",
		"deleteSyncRemnawave",
		"updateProtocolsForSync",
		"/docs",
		"/redoc",
		"remnawave_url",
		"remnawave_api_key",
		"remnawaveFields",
		"syncCreateConns",
		"href=\"#icon-book\"",
		"href=\"#icon-refresh\"",
	}

	for _, token := range forbiddenTokens {
		if strings.Contains(settingsStr, token) {
			t.Errorf("settings.html contains forbidden token %q", token)
		}
	}
}

func TestServerTemplateI18nAndTranslations(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	serverData, err := fs.ReadFile(templatesFS, "server.html")
	if err != nil {
		t.Fatalf("failed to read server.html: %v", err)
	}
	serverStr := string(serverData)

	// 1. Verify that server.html contains NO Cyrillic characters (regex [\x{0400}-\x{04FF}])
	cyrillicRe := regexp.MustCompile(`[\x{0400}-\x{04FF}]`)
	if matches := cyrillicRe.FindAllString(serverStr, -1); len(matches) > 0 {
		t.Errorf("server.html contains hardcoded Cyrillic characters (%d occurrences): %v", len(matches), matches)
	}

	// 2. Verify server.html references required translation tokens
	requiredTokens := []string{
		"${_('start_install')}",
		"_('port_telemt_hint')",
		"${_('config')}",
	}
	for _, token := range requiredTokens {
		if !strings.Contains(serverStr, token) {
			t.Errorf("server.html missing required token %q", token)
		}
	}

	// 3. Verify that port_telemt_hint, start_install, and config exist and have non-empty values in all 5 translations
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}
	requiredKeys := []string{"port_telemt_hint", "start_install", "config"}
	languages := []string{"en.json", "ru.json", "fr.json", "zh.json", "fa.json"}
	for _, langFile := range languages {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Fatalf("failed to read translation %s: %v", langFile, err)
		}
		var parsed map[string]string
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("translation %s is not valid JSON: %v", langFile, err)
		}
		for _, key := range requiredKeys {
			val, ok := parsed[key]
			if !ok || strings.TrimSpace(val) == "" {
				t.Errorf("translation %s missing or empty key %q", langFile, key)
			}
		}
	}
}

func TestUsersTemplateServerZeroHandling(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	usersData, err := fs.ReadFile(templatesFS, "users.html")
	if err != nil {
		t.Fatalf("failed to read users.html: %v", err)
	}
	usersStr := string(usersData)

	// Check Server 0 display name mapping
	if !strings.Contains(usersStr, `(Number(c.server_id) === 0) ? 'Cluster (Auto)'`) {
		t.Errorf("users.html must render 'Cluster (Auto)' when server_id is 0")
	}

	// Check that action buttons pass connection ID
	if !strings.Contains(usersStr, `onclick="copyUserConnectionDirect('${UI.escapeJs(c.id)}', ${Number(c.server_id)}`) {
		t.Errorf("users.html copyUserConnectionDirect must pass connection ID")
	}
	if !strings.Contains(usersStr, `onclick="showUserConnectionConfig('${UI.escapeJs(c.id)}', ${Number(c.server_id)}`) {
		t.Errorf("users.html showUserConnectionConfig must pass connection ID")
	}
	if !strings.Contains(usersStr, `onclick="unlinkUserConnection('${UI.escapeJs(c.id)}', ${Number(c.server_id)}`) {
		t.Errorf("users.html unlinkUserConnection must pass connection ID")
	}

	// Check fallback/direct connection endpoint calls
	if !strings.Contains(usersStr, `/api/connections/${connId}/delete`) {
		t.Errorf("users.html unlinkUserConnection must support /api/connections/${connId}/delete")
	}
	if !strings.Contains(usersStr, `/api/connections/${connId}/config`) {
		t.Errorf("users.html showUserConnectionConfig/copyUserConnectionDirect must support /api/connections/${connId}/config")
	}
}

func TestUsersTemplatePageSize(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("failed to get templates sub FS: %v", err)
	}

	usersData, err := fs.ReadFile(templatesFS, "users.html")
	if err != nil {
		t.Fatalf("failed to read users.html: %v", err)
	}
	usersStr := string(usersData)

	if !strings.Contains(usersStr, "let pageSize = 12;") {
		t.Errorf("users.html must configure 'let pageSize = 12;' for 3-column responsive grid layout")
	}
	if strings.Contains(usersStr, "let pageSize = 10;") {
		t.Errorf("users.html must not contain obsolete 'let pageSize = 10;'")
	}
}

func TestServerTemplate_TelemetryPolling(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	serverData, err := fs.ReadFile(templatesFS, "server.html")
	if err != nil {
		t.Fatalf("failed to read server.html: %v", err)
	}
	serverStr := string(serverData)

	// 1. Verify STATS_REFRESH_INTERVAL_MS definition
	const expectedInterval = "const STATS_REFRESH_INTERVAL_MS = 30000;"
	if !strings.Contains(serverStr, expectedInterval) {
		t.Errorf("server.html must define %q", expectedInterval)
	}

	// 2. Verify registration of Telemetry.poll for server-stats and server-reachability
	expectedStatsPoll := "Telemetry.poll('server-stats-' + SERVER_ID, loadServerStats, STATS_REFRESH_INTERVAL_MS);"
	if !strings.Contains(serverStr, expectedStatsPoll) {
		t.Errorf("server.html missing Telemetry.poll for server-stats: expected %q", expectedStatsPoll)
	}

	expectedReachPoll := "Telemetry.poll('server-reachability-' + SERVER_ID, updateReachability, STATS_REFRESH_INTERVAL_MS);"
	if !strings.Contains(serverStr, expectedReachPoll) {
		t.Errorf("server.html missing Telemetry.poll for server-reachability: expected %q", expectedReachPoll)
	}

	// 3. Verify no bare setInterval(updateReachability) remains
	if strings.Contains(serverStr, "setInterval(updateReachability") {
		t.Errorf("server.html must not contain bare unmanaged 'setInterval(updateReachability'")
	}

	// 4. Verify error preservation behavior in loadServerStats
	if !strings.Contains(serverStr, "if (!stats || typeof stats !== 'object'") {
		t.Errorf("server.html loadServerStats must validate stats payload before DOM updates")
	}
	expectedZeroCheck := "stats.ram_total === 0 && stats.disk_total === 0"
	if !strings.Contains(serverStr, expectedZeroCheck) {
		t.Errorf("server.html loadServerStats must check for zero totals: expected %q", expectedZeroCheck)
	}

	if !strings.Contains(serverStr, "return stats;") {
		t.Errorf("server.html loadServerStats must return stats payload")
	}

	if !strings.Contains(serverStr, "throw err;") {
		t.Errorf("server.html loadServerStats must re-throw errors for Telemetry.poll failure tracking")
	}

	loadStatsIdx := strings.Index(serverStr, "async function loadServerStats()")
	if loadStatsIdx == -1 {
		t.Fatalf("server.html missing loadServerStats function")
	}
	loadStatsBlock := serverStr[loadStatsIdx : loadStatsIdx+strings.Index(serverStr[loadStatsIdx:], "\n    }")]
	if strings.Contains(loadStatsBlock, "innerHTML = ''") || strings.Contains(loadStatsBlock, "innerHTML = \"\"") {
		t.Errorf("loadServerStats must not blank DOM innerHTML on error")
	}
}

func TestIssue278EditServerHostUIAndTranslations(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	// 1. Verify translation keys across all 5 languages
	requiredKeys := []string{
		"edit_server_host",
		"edit_server_host_placeholder",
		"server_host_updated",
	}
	languages := []string{"en.json", "ru.json", "fr.json", "zh.json", "fa.json"}
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
		if langFile == "en.json" {
			if dict["edit_server_host"] != "Edit Server IP" {
				t.Errorf("en.json edit_server_host = %q, want %q", dict["edit_server_host"], "Edit Server IP")
			}
			if dict["edit_server_host_placeholder"] != "Enter new IP address or hostname" {
				t.Errorf("en.json edit_server_host_placeholder = %q, want %q", dict["edit_server_host_placeholder"], "Enter new IP address or hostname")
			}
			if dict["server_host_updated"] != "Server IP updated" {
				t.Errorf("en.json server_host_updated = %q, want %q", dict["server_host_updated"], "Server IP updated")
			}
		}
		if langFile == "ru.json" {
			if dict["edit_server_host"] != "Изменить IP сервера" {
				t.Errorf("ru.json edit_server_host = %q, want %q", dict["edit_server_host"], "Изменить IP сервера")
			}
			if dict["edit_server_host_placeholder"] != "Введите новый IP-адрес или имя хоста" {
				t.Errorf("ru.json edit_server_host_placeholder = %q, want %q", dict["edit_server_host_placeholder"], "Введите новый IP-адрес или имя хоста")
			}
			if dict["server_host_updated"] != "IP сервера обновлен" {
				t.Errorf("ru.json server_host_updated = %q, want %q", dict["server_host_updated"], "IP сервера обновлен")
			}
		}
	}

	// 2. Verify server.html elements and JavaScript
	serverData, err := fs.ReadFile(templatesFS, "server.html")
	if err != nil {
		t.Fatalf("failed to read server.html: %v", err)
	}
	serverStr := string(serverData)

	requiredServerElements := []string{
		`id="serverHostDisplay"`,
		`openEditHostModal`,
		`id="editHostModal"`,
		`id="editHostInput"`,
		`function isValidHost(host)`,
		`submitEditHost()`,
		`closeEditHostModal()`,
		`const serverId = editHostServerId;`,
		`/api/servers/' + serverId + '/host`,
		`server_host_updated`,
	}
	for _, elem := range requiredServerElements {
		if !strings.Contains(serverStr, elem) {
			t.Errorf("server.html missing required edit host element %q", elem)
		}
	}

	// Ensure no hardcoded Cyrillic was added to server.html
	cyrillicRe := regexp.MustCompile(`[\x{0400}-\x{04FF}]`)
	if matches := cyrillicRe.FindAllString(serverStr, -1); len(matches) > 0 {
		t.Errorf("server.html contains hardcoded Cyrillic characters: %v", matches)
	}

	// 3. Verify index.html elements and JavaScript
	indexData, err := fs.ReadFile(templatesFS, "index.html")
	if err != nil {
		t.Fatalf("failed to read index.html: %v", err)
	}
	indexStr := string(indexData)

	requiredIndexElements := []string{
		`openEditHostModal`,
		`id="editHostModal"`,
		`id="editHostInput"`,
		`function isValidHost(host)`,
		`submitEditHost()`,
		`closeEditHostModal()`,
		`const serverId = editHostServerId;`,
		`id="server-host-`,
		`data-server-host`,
		`href="#icon-globe"`,
		`/api/servers/' + serverId + '/host`,
		`server_host_updated`,
	}
	for _, elem := range requiredIndexElements {
		if !strings.Contains(indexStr, elem) {
			t.Errorf("index.html missing required edit host element %q", elem)
		}
	}
}

func TestClientSideHostValidation(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	serverData, err := fs.ReadFile(templatesFS, "server.html")
	if err != nil {
		t.Fatalf("failed to read server.html: %v", err)
	}
	serverStr := string(serverData)

	indexData, err := fs.ReadFile(templatesFS, "index.html")
	if err != nil {
		t.Fatalf("failed to read index.html: %v", err)
	}
	indexStr := string(indexData)

	for _, tmpl := range []struct {
		name    string
		content string
	}{
		{"server.html", serverStr},
		{"index.html", indexStr},
	} {
		if !strings.Contains(tmpl.content, "function isValidHost(host)") {
			t.Errorf("%s missing function isValidHost(host)", tmpl.name)
		}
		if !strings.Contains(tmpl.content, "if (!isValidHost(newHost))") {
			t.Errorf("%s missing if (!isValidHost(newHost)) check in submitEditHost", tmpl.name)
		}
		if !strings.Contains(tmpl.content, "const serverId = editHostServerId;") {
			t.Errorf("%s missing serverId capture before modal close", tmpl.name)
		}
	}

	// Test the exact validation logic specified in isValidHost:
	// - trims whitespace
	// - returns false if empty
	// - returns false if whitespace is inside
	// - returns false if URL scheme is present
	// - validates IPv4 (4 octets, 0-255)
	// - validates IPv6 (bracketed or unbracketed)
	// - validates hostname / FQDN (alphanumeric, hyphens, dots, no leading/trailing hyphen)
	ipv4Regex := regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$`)
	digitsAndDotsRegex := regexp.MustCompile(`^[\d.]+$`)
	ipv6Regex := regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`)
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

	isValidHostGo := func(host string) bool {
		host = strings.TrimSpace(host)
		if host == "" {
			return false
		}
		for _, r := range host {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				return false
			}
		}
		if strings.Contains(host, "://") {
			return false
		}
		if ipv4Regex.MatchString(host) {
			return true
		}
		if digitsAndDotsRegex.MatchString(host) {
			return false
		}
		ipv6Candidate := host
		if strings.HasPrefix(ipv6Candidate, "[") && strings.HasSuffix(ipv6Candidate, "]") {
			ipv6Candidate = ipv6Candidate[1 : len(ipv6Candidate)-1]
		}
		if strings.Contains(ipv6Candidate, ":") {
			return ipv6Regex.MatchString(ipv6Candidate)
		}
		if len(host) > 253 {
			return false
		}
		return hostnameRegex.MatchString(host)
	}

	testCases := []struct {
		input string
		valid bool
	}{
		// Valid IPv4
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"  192.168.1.100  ", true},

		// Valid IPv6
		{"::1", true},
		{"[::1]", true},
		{"2001:db8::1", true},
		{"[2001:db8::1]", true},
		{"fe80::1", true},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},

		// Valid hostnames
		{"localhost", true},
		{"vpn.example.com", true},
		{"my-server-01.infra.corp.net", true},
		{"a.b.c.d.org", true},

		// Invalid cases
		{"", false},
		{"   ", false},
		{"\t\n", false},
		{"192.168.1. 1", false},
		{"vpn example com", false},
		{"http://192.168.1.1", false},
		{"https://vpn.example.com", false},
		{"tcp://10.0.0.1", false},
		{"://invalid", false},
		{"256.1.1.1", false},
		{"192.168.1", false},
		{"192.168.1.1.1", false},
		{":::1", false},
		{"12345::1", false},
		{"-example.com", false},
		{"example-.com", false},
		{"example..com", false},
		{"example$.com", false},
		{"example/path", false},
		{"host@domain.com", false},
		{strings.Repeat("a", 254), false},
	}

	for _, tc := range testCases {
		got := isValidHostGo(tc.input)
		if got != tc.valid {
			t.Errorf("isValidHost(%q) = %v, want %v", tc.input, got, tc.valid)
		}
	}
}

func TestIssue351MobileLogoutOcclusionAndStackingContext(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	cssBytes, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}
	css := string(cssBytes)

	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	baseBytes, err := fs.ReadFile(templatesFS, "base.html")
	if err != nil {
		t.Fatalf("failed to read templates/base.html: %v", err)
	}
	base := string(baseBytes)

	// 1. Verify .app-layout does not define an integer z-index that forms an isolated stacking context
	appLayoutRegex := regexp.MustCompile(`(?s)\.app-layout\s*\{([^}]+)\}`)
	matchLayout := appLayoutRegex.FindStringSubmatch(css)
	if len(matchLayout) < 2 {
		t.Fatal("style.css missing .app-layout definition")
	}
	layoutBlock := matchLayout[1]
	integerZIndexRegex := regexp.MustCompile(`z-index\s*:\s*[0-9]+`)
	if integerZIndexRegex.MatchString(layoutBlock) {
		t.Errorf(".app-layout defines integer z-index, which creates an isolated stacking context trapping the mobile drawer below .mobile-bottom-bar: %s", layoutBlock)
	}
	if !strings.Contains(layoutBlock, "position: relative") {
		t.Errorf(".app-layout should maintain position: relative, got: %s", layoutBlock)
	}

	// 2. Verify stacking hierarchy: .mobile-bottom-bar (70) < .drawer-backdrop (95) < .app-sidebar mobile (100)
	bottomBarRegex := regexp.MustCompile(`(?s)\.mobile-bottom-bar\s*\{([^}]+)\}`)
	matchBottomBar := bottomBarRegex.FindStringSubmatch(css)
	if len(matchBottomBar) < 2 {
		t.Fatal("style.css missing .mobile-bottom-bar definition")
	}
	bottomBarBlock := matchBottomBar[1]
	zIndexExtract := regexp.MustCompile(`z-index\s*:\s*([0-9]+)`)

	bottomBarZMatch := zIndexExtract.FindStringSubmatch(bottomBarBlock)
	if len(bottomBarZMatch) < 2 {
		t.Fatal(".mobile-bottom-bar missing numeric z-index")
	}

	backdropRegex := regexp.MustCompile(`(?s)\.drawer-backdrop\s*\{([^}]+)\}`)
	matchBackdrop := backdropRegex.FindStringSubmatch(css)
	if len(matchBackdrop) < 2 {
		t.Fatal("style.css missing .drawer-backdrop definition")
	}
	backdropBlock := matchBackdrop[1]
	backdropZMatch := zIndexExtract.FindStringSubmatch(backdropBlock)
	if len(backdropZMatch) < 2 {
		t.Fatal(".drawer-backdrop missing numeric z-index")
	}

	mobileQueryIdx := strings.Index(css, "@media (max-width: 1023px)")
	if mobileQueryIdx == -1 {
		t.Fatal("style.css missing @media (max-width: 1023px) query")
	}
	mobileQueryBlock := css[mobileQueryIdx:]
	nextMediaOffset := len("@media (max-width: 1023px)")
	if nextIdx := strings.Index(mobileQueryBlock[nextMediaOffset:], "@media"); nextIdx != -1 {
		mobileQueryBlock = mobileQueryBlock[:nextMediaOffset+nextIdx]
	}

	mobileSidebarRegex := regexp.MustCompile(`(?s)\.app-sidebar\s*\{([^}]+)\}`)
	matchMobileSidebar := mobileSidebarRegex.FindStringSubmatch(mobileQueryBlock)
	if len(matchMobileSidebar) < 2 {
		t.Fatal("mobile query missing .app-sidebar definition")
	}
	mobileSidebarBlock := matchMobileSidebar[1]
	mobileSidebarZMatch := zIndexExtract.FindStringSubmatch(mobileSidebarBlock)
	if len(mobileSidebarZMatch) < 2 {
		t.Fatal("mobile .app-sidebar missing numeric z-index")
	}

	bottomBarZ, err := strconv.Atoi(bottomBarZMatch[1])
	if err != nil {
		t.Fatalf("failed to parse bottomBarZ: %v", err)
	}
	backdropZ, err := strconv.Atoi(backdropZMatch[1])
	if err != nil {
		t.Fatalf("failed to parse backdropZ: %v", err)
	}
	mobileSidebarZ, err := strconv.Atoi(mobileSidebarZMatch[1])
	if err != nil {
		t.Fatalf("failed to parse mobileSidebarZ: %v", err)
	}

	if !(bottomBarZ < backdropZ) {
		t.Errorf("expected bottomBarZ (%d) < backdropZ (%d)", bottomBarZ, backdropZ)
	}
	if !(backdropZ < mobileSidebarZ) {
		t.Errorf("expected backdropZ (%d) < mobileSidebarZ (%d)", backdropZ, mobileSidebarZ)
	}
	if !(bottomBarZ < mobileSidebarZ) {
		t.Errorf("expected bottomBarZ (%d) < mobileSidebarZ (%d)", bottomBarZ, mobileSidebarZ)
	}

	// Verify background body::before is at or below z-index 0
	bodyBeforeRegex := regexp.MustCompile(`(?s)body::before\s*\{([^}]+)\}`)
	matchBodyBefore := bodyBeforeRegex.FindStringSubmatch(css)
	if len(matchBodyBefore) >= 2 {
		bodyBeforeBlock := matchBodyBefore[1]
		bodyBeforeZMatch := regexp.MustCompile(`z-index\s*:\s*(-?[0-9]+)`).FindStringSubmatch(bodyBeforeBlock)
		if len(bodyBeforeZMatch) >= 2 {
			bodyZ, err := strconv.Atoi(bodyBeforeZMatch[1])
			if err != nil {
				t.Fatalf("failed to parse body::before z-index: %v", err)
			}
			if bodyZ > 0 {
				t.Errorf("expected body::before z-index <= 0, got %d", bodyZ)
			}
		}
	}

	// 3. Verify .app-sidebar supports dynamic viewport height (100dvh) with fallback (100vh)
	if !strings.Contains(mobileSidebarBlock, "height: 100vh;") {
		t.Errorf("mobile .app-sidebar missing 100vh fallback: %s", mobileSidebarBlock)
	}
	if !strings.Contains(mobileSidebarBlock, "height: 100dvh;") {
		t.Errorf("mobile .app-sidebar missing 100dvh dynamic viewport height: %s", mobileSidebarBlock)
	}

	// 4. Verify .sidebar-footer has safe-area inset padding
	sidebarFooterRegex := regexp.MustCompile(`(?s)\.sidebar-footer\s*\{([^}]+)\}`)
	matchSidebarFooter := sidebarFooterRegex.FindStringSubmatch(css)
	if len(matchSidebarFooter) < 2 {
		t.Fatal("style.css missing .sidebar-footer definition")
	}
	footerBlock := matchSidebarFooter[1]
	if !strings.Contains(footerBlock, "env(safe-area-inset-bottom)") {
		t.Errorf(".sidebar-footer missing env(safe-area-inset-bottom) safe-area padding: %s", footerBlock)
	}

	// 5. Verify base.html contains the logout button with #icon-logout inside .sidebar-footer
	if !strings.Contains(base, "class=\"sidebar-footer\"") {
		t.Error("base.html missing .sidebar-footer")
	}
	if !strings.Contains(base, "href=\"/logout\"") {
		t.Error("base.html missing logout link href=\"/logout\"")
	}
	if !strings.Contains(base, "href=\"#icon-logout\"") {
		t.Error("base.html missing #icon-logout icon")
	}

	// Verify logout link is inside .sidebar-footer
	footerIdx := strings.Index(base, "class=\"sidebar-footer\"")
	if footerIdx == -1 {
		t.Fatal("could not find .sidebar-footer in base.html")
	}
	footerSnippet := base[footerIdx:]
	endFooterIdx := strings.Index(footerSnippet, "</aside>")
	if endFooterIdx != -1 {
		footerSnippet = footerSnippet[:endFooterIdx]
	}
	if !strings.Contains(footerSnippet, "href=\"/logout\"") {
		t.Errorf(".sidebar-footer does not contain logout link: %s", footerSnippet)
	}
	if !strings.Contains(footerSnippet, "href=\"#icon-logout\"") {
		t.Errorf(".sidebar-footer logout link missing #icon-logout icon: %s", footerSnippet)
	}

	// Verify mobile bottom bar interaction protection when drawer is open
	if !strings.Contains(css, ".app-layout:has(.drawer-open) ~ .mobile-bottom-bar") {
		t.Error("style.css missing rule disabling pointer events on .mobile-bottom-bar when drawer is open")
	}
}

func TestIssue305ForwarderHealthTelemetryUI(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	vpnData, err := fs.ReadFile(templatesFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}
	vpnStr := string(vpnData)

	t.Run("RequiredDOMElements", func(t *testing.T) {
		requiredDOMIDs := []string{
			"vpn-forwarder-card",
			"vpn-fwd-status-badge",
			"vpn-fwd-status-text",
			"vpn-fwd-queue",
			"vpn-fwd-peak",
			"vpn-fwd-drops-queue-full",
			"vpn-fwd-drops-no-route",
			"vpn-fwd-drops-packet-too-large",
			"vpn-fwd-write-errors",
			"vpn-fwd-routes-details",
			"vpn-fwd-routes-badge",
			"vpn-fwd-routes-summary-status",
			"vpn-fwd-routes-empty",
			"vpn-fwd-routes-table",
			"vpn-fwd-routes-tbody",
			"vpn-diag-peers-status",
			"vpn-diag-sync-failures",
			"vpn-diag-peer-sync-invalid",
			"vpn-diag-peer-sync-enqueue",
			"vpn-diag-peer-sync-reconcile",
			"vpn-diag-peer-sync-error",
			"vpn-diag-peer-sync-restart",
		}
		for _, id := range requiredDOMIDs {
			if !strings.Contains(vpnStr, `id="`+id+`"`) {
				t.Errorf("vpn.html missing required DOM element id=%q", id)
			}
		}
	})

	t.Run("TranslationKeysInAllLanguages", func(t *testing.T) {
		requiredKeys := []string{
			"vpn_forwarder_health",
			"vpn_forwarder_queue",
			"vpn_forwarder_peak",
			"vpn_forwarder_drops_queue_full",
			"vpn_forwarder_drops_no_route",
			"vpn_forwarder_drops_oversize",
			"vpn_forwarder_write_errors",
			"vpn_forwarder_routes",
			"vpn_forwarder_unavailable",
			"vpn_forwarder_no_route_pressure",
			"vpn_forwarder_route_peer",
			"vpn_forwarder_route_queue",
			"vpn_forwarder_route_peak",
			"vpn_forwarder_route_drops",
			"vpn_forwarder_route_writes",
			"vpn_forwarder_healthy",
			"vpn_forwarder_pressure",
			"vpn_forwarder_warning",
			"vpn_forwarder_instantaneous",
			"vpn_forwarder_peak_watermark",
			"vpn_forwarder_cumulative",
			"vpn_diag_peer_sync_peers",
			"vpn_diag_peer_sync_failures",
			"vpn_diag_peer_sync_op_failures",
			"vpn_diag_peer_sync_invalid_rows",
			"vpn_diag_peer_sync_enqueue",
			"vpn_diag_peer_sync_last_reconcile",
			"vpn_diag_peer_sync_last_error",
			"vpn_diag_peer_sync_restart_required",
			"vpn_diag_peer_sync_unavailable",
			"vpn_diag_peer_sync_never",
			"vpn_diag_peer_sync_none",
			"vpn_diag_peer_sync_restart_yes",
			"vpn_diag_peer_sync_restart_no",
		}
		languages := []string{"en.json", "ru.json", "fa.json", "fr.json", "zh.json"}

		for _, langFile := range languages {
			data, err := fs.ReadFile(transFS, langFile)
			if err != nil {
				t.Fatalf("failed to read %s: %v", langFile, err)
			}
			var dict map[string]string
			if err := json.Unmarshal(data, &dict); err != nil {
				t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
			}
			for _, key := range requiredKeys {
				val, ok := dict[key]
				if !ok {
					t.Errorf("%s missing required translation key %q", langFile, key)
				} else if strings.TrimSpace(val) == "" {
					t.Errorf("%s has empty translation for key %q", langFile, key)
				}
			}
		}
	})

	t.Run("NoRawUntranslatedStringsInForwarderCard", func(t *testing.T) {
		startIdx := strings.Index(vpnStr, `id="vpn-forwarder-card"`)
		if startIdx == -1 {
			t.Fatal("could not find #vpn-forwarder-card in vpn.html")
		}
		endIdx := strings.Index(vpnStr[startIdx:], `<!-- BACKENDS TABLE -->`)
		if endIdx == -1 {
			t.Fatal("could not find end of #vpn-forwarder-card before backends table")
		}
		cardHTML := vpnStr[startIdx : startIdx+endIdx]

		// Ensure all visible labels use {{ _ "..." }}
		expectedTokens := []string{
			`{{ _ "vpn_forwarder_health" }}`,
			`{{ _ "vpn_forwarder_unavailable" }}`,
			`{{ _ "vpn_forwarder_queue" }}`,
			`{{ _ "vpn_forwarder_instantaneous" }}`,
			`{{ _ "vpn_forwarder_peak" }}`,
			`{{ _ "vpn_forwarder_peak_watermark" }}`,
			`{{ _ "vpn_forwarder_drops_queue_full" }}`,
			`{{ _ "vpn_forwarder_cumulative" }}`,
			`{{ _ "vpn_forwarder_drops_no_route" }}`,
			`{{ _ "vpn_forwarder_drops_oversize" }}`,
			`{{ _ "vpn_forwarder_write_errors" }}`,
			`{{ _ "vpn_forwarder_routes" }}`,
			`{{ _ "vpn_forwarder_no_route_pressure" }}`,
			`{{ _ "vpn_forwarder_route_peer" }}`,
			`{{ _ "vpn_forwarder_route_queue" }}`,
			`{{ _ "vpn_forwarder_route_peak" }}`,
			`{{ _ "vpn_forwarder_route_drops" }}`,
			`{{ _ "vpn_forwarder_route_writes" }}`,
		}
		for _, token := range expectedTokens {
			if !strings.Contains(cardHTML, token) {
				t.Errorf("forwarder card missing translation token %q", token)
			}
		}

		// Ensure no hardcoded raw English strings exist in card labels
		rawEnglishStrings := []string{
			">Forwarder Health<",
			">Queue Occupancy<",
			">Peak High-Water<",
			">Device Write Errors<",
			">Transport Decrypt Failures<",
			">Queue Full Drops<",
			">No Route Drops<",
			">Oversize Packet Drops<",
		}
		for _, raw := range rawEnglishStrings {
			if strings.Contains(cardHTML, raw) {
				t.Errorf("forwarder card contains unlocalized raw English text %q", raw)
			}
		}
	})

	t.Run("SinglePollingLoopAssertion", func(t *testing.T) {
		pollCount := strings.Count(vpnStr, "NexusTelemetry.poll('vpn-status'")
		if pollCount != 1 {
			t.Errorf("expected exactly 1 NexusTelemetry.poll('vpn-status', got %d", pollCount)
		}
		apiGetStatusCount := strings.Count(vpnStr, "API.get('/api/vpn/status')")
		if apiGetStatusCount != 1 {
			t.Errorf("expected exactly 1 API.get('/api/vpn/status') call, got %d", apiGetStatusCount)
		}
		if !strings.Contains(vpnStr, "vpnRenderForwarderHealth(status)") {
			t.Errorf("vpn.html missing vpnRenderForwarderHealth(status) invocation inside vpnLoadData()")
		}
		if !strings.Contains(vpnStr, "vpnRenderForwarderHealth(null)") {
			t.Errorf("vpn.html missing vpnRenderForwarderHealth(null) in vpnLoadData() error handling")
		}
	})

	t.Run("ExecutableJSDOMScenarios", func(t *testing.T) {
		nodePath, err := findNodeBinary()
		if err != nil {
			t.Skipf("Node.js binary not available (%v): skipping executable JS DOM tests", err)
		}

		scenarios := []struct {
			name        string
			scenarioKey string
		}{
			{"Scenario1_HealthyWithRoutes", "healthy"},
			{"Scenario2_HealthyZeroRoutesIdleState", "healthy_zero_routes"},
			{"Scenario3_SurvivingPeakAfterRoutesDisconnect", "surviving_peak_after_routes_disconnect"},
			{"Scenario4_NonZeroFailureCounters", "failures"},
			{"Scenario5_SaturatedRouteWithDrops", "saturated_route"},
			{"Scenario6_OldBackendAbsentFields", "absent_fields"},
			{"Scenario7_FailedUnavailableStatusSample", "failed_sample"},
			{"Scenario8_PeerSyncKPIInSync", "peer_sync_in_sync"},
			{"Scenario9_PeerSyncKPIDiverged", "peer_sync_diverged"},
			{"Scenario10_PeerSyncKPIAbsent", "peer_sync_absent"},
			{"Scenario11_PeerSyncKPIIgnoresHandshakeCount", "peer_sync_ignores_handshake_count"},
			{"AllScenariosInSequence", "all"},
		}

		for _, sc := range scenarios {
			sc := sc
			t.Run(sc.name, func(t *testing.T) {
				runDOMScenario(t, nodePath, vpnStr, sc.scenarioKey)
			})
		}
	})

	t.Run("NoEmDashCharacters", func(t *testing.T) {
		// Strict constraint: NEVER use em dash ("\u2014") in new code, HTML, or translations
		startIdx := strings.Index(vpnStr, `id="vpn-forwarder-card"`)
		if startIdx == -1 {
			t.Fatal("could not find #vpn-forwarder-card in vpn.html")
		}
		endIdx := strings.Index(vpnStr[startIdx:], `<!-- BACKENDS TABLE -->`)
		if endIdx == -1 {
			t.Fatal("could not find end of #vpn-forwarder-card before backends table")
		}
		cardHTML := vpnStr[startIdx : startIdx+endIdx]
		if strings.Contains(cardHTML, "\u2014") {
			t.Errorf("vpn-forwarder-card HTML contains prohibited em dash (\\u2014)")
		}

		jsStart := strings.Index(vpnStr, "function vpnRenderForwarderHealth")
		if jsStart != -1 {
			jsEnd := strings.Index(vpnStr[jsStart:], "async function vpnLoadData")
			if jsEnd != -1 {
				jsCode := vpnStr[jsStart : jsStart+jsEnd]
				if strings.Contains(jsCode, "\u2014") {
					t.Errorf("vpnRenderForwarderHealth JS contains prohibited em dash (\\u2014)")
				}
			}
		}

		languages := []string{"en.json", "ru.json", "fa.json", "fr.json", "zh.json"}
		for _, langFile := range languages {
			data, err := fs.ReadFile(transFS, langFile)
			if err != nil {
				t.Fatalf("failed to read %s: %v", langFile, err)
			}
			var dict map[string]string
			if err := json.Unmarshal(data, &dict); err != nil {
				t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
			}
			for k, v := range dict {
				if strings.HasPrefix(k, "vpn_forwarder_") {
					if strings.Contains(v, "\u2014") {
						t.Errorf("%s key %s contains prohibited em dash (\\u2014): %q", langFile, k, v)
					}
				}
			}
		}
	})
}

func findNodeBinary() (string, error) {
	if p, err := exec.LookPath("node"); err == nil {
		return p, nil
	}
	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, ".local", "bin", "node"),
		"/usr/local/bin/node",
		"/usr/bin/node",
		"/bin/node",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", errors.New("node binary not found in PATH or standard locations")
}

func extractJSFunction(source, funcName string) (string, error) {
	startIdx := strings.Index(source, funcName)
	if startIdx == -1 {
		return "", fmt.Errorf("function %s not found in source", funcName)
	}
	braceStart := strings.Index(source[startIdx:], "{")
	if braceStart == -1 {
		return "", fmt.Errorf("opening brace for %s not found", funcName)
	}
	braceStart += startIdx
	depth := 1
	idx := braceStart + 1
	for idx < len(source) && depth > 0 {
		if source[idx] == '{' {
			depth++
		} else if source[idx] == '}' {
			depth--
		}
		idx++
	}
	if depth != 0 {
		return "", fmt.Errorf("unbalanced braces in function %s", funcName)
	}
	return source[startIdx:idx], nil
}

func buildJSTestRunner(f1, f2 string) string {
	return `const assert = require('assert');

class MockElement {
    constructor(tagName, id) {
        this.tagName = (tagName || 'div').toUpperCase();
        this.id = id || '';
        this.children = [];
        this._textContent = '';
        this.className = '';
        this.style = {};
        this.title = '';
        this.open = false;
        this.attributes = {};
    }
    get textContent() { return this._textContent; }
    set textContent(val) {
        this._textContent = String(val);
        if (val === '') this.children = [];
    }
    appendChild(child) {
        this.children.push(child);
        return child;
    }
    setAttribute(name, val) { this.attributes[name] = String(val); }
    getAttribute(name) { return this.attributes[name]; }
}

class MockDocument {
    constructor() {
        this.reset();
    }
    reset() {
        this.elements = new Map();
        const ids = [
            'vpn-forwarder-card',
            'vpn-fwd-status-badge',
            'vpn-fwd-status-text',
            'vpn-fwd-queue',
            'vpn-fwd-peak',
            'vpn-fwd-drops-queue-full',
            'vpn-fwd-drops-no-route',
            'vpn-fwd-drops-packet-too-large',
            'vpn-fwd-write-errors',
            'vpn-fwd-routes-details',
            'vpn-fwd-routes-badge',
            'vpn-fwd-routes-summary-status',
            'vpn-fwd-routes-empty',
            'vpn-fwd-routes-table',
            'vpn-fwd-routes-tbody',
            // The eight KPI tiles (issue #424 round 4, item H asserts on the
            // Peer Sync tile).
            'vpn-kpi-throughput', 'vpn-kpi-routes-sessions', 'vpn-kpi-queue-pressure',
            'vpn-kpi-packet-loss', 'vpn-kpi-client-engine', 'vpn-kpi-peer-sync',
            'vpn-kpi-backends', 'vpn-kpi-slow-writes'
        ];
        for (const id of ids) {
            this.elements.set(id, new MockElement('div', id));
        }
        this.elements.get('vpn-fwd-status-badge').className = 'badge';
        this.elements.get('vpn-fwd-status-text').textContent = 'Not reported';
        this.elements.get('vpn-fwd-queue').textContent = '-';
        this.elements.get('vpn-fwd-peak').textContent = '-';
        this.elements.get('vpn-fwd-drops-queue-full').textContent = '-';
        this.elements.get('vpn-fwd-drops-no-route').textContent = '-';
        this.elements.get('vpn-fwd-drops-packet-too-large').textContent = '-';
        this.elements.get('vpn-fwd-write-errors').textContent = '-';
        this.elements.get('vpn-fwd-routes-badge').textContent = '0';
        this.elements.get('vpn-fwd-routes-summary-status').textContent = 'Not reported';
        this.elements.get('vpn-fwd-routes-empty').style.display = 'block';
        this.elements.get('vpn-fwd-routes-table').style.display = 'none';
        this.elements.get('vpn-fwd-routes-details').open = false;
    }
    getElementById(id) {
        return this.elements.get(id) || null;
    }
    createElement(tag) {
        return new MockElement(tag);
    }
}

const mockDoc = new MockDocument();
const translations = {
    'vpn_forwarder_unavailable': 'Not reported',
    'vpn_forwarder_healthy': 'Healthy',
    'vpn_forwarder_pressure': 'Pressure Detected',
    'vpn_forwarder_warning': 'Warning',
    'vpn_forwarder_no_route_pressure': 'All route queues clear',
    'vpn_diag_peer_sync_unavailable': 'Unavailable'
};
const _ = (key) => translations[key] || key;
const document = mockDoc;

` + f1 + `
` + f2 + `

function runScenario(key) {
    if (key === 'healthy') {
        mockDoc.reset();
        vpnRenderForwarderHealth({
            forwarder_available: true,
            forwarder_queue_capacity: 2048,
            forwarder_queue_occupancy: 42,
            forwarder_queue_high_water: 1000,
            forwarder_drops_queue_full: 0,
            forwarder_drops_no_route: 0,
            forwarder_drops_packet_too_large: 0,
            forwarder_device_write_errors: 0,
            transport_decryption_failures: 0,
            forwarder_route_queues: {
                'abcdefghijklmnop': {
                    capacity: 2048,
                    occupancy: 10,
                    high_water: 20,
                    queue_full_drops: 0,
                    write_count: 100,
                    write_errors: 0
                }
            }
        });
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-success');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Healthy');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-queue').textContent, '42 / 2048');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-peak').textContent, '1000');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-peak').style.color, '');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-queue-full').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-write-errors').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, false);
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'All route queues clear');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-table').style.display, '');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-empty').style.display, 'none');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-tbody').children.length, 1);
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-tbody').children[0].children[2].textContent, '20');
    } else if (key === 'healthy_zero_routes') {
        mockDoc.reset();
        vpnRenderForwarderHealth({
            forwarder_available: true,
            forwarder_queue_capacity: 0,
            forwarder_queue_occupancy: 0,
            forwarder_queue_high_water: 0,
            forwarder_drops_queue_full: 0,
            forwarder_drops_no_route: 0,
            forwarder_drops_packet_too_large: 0,
            forwarder_device_write_errors: 0,
            transport_decryption_failures: 0,
            forwarder_route_queues: {}
        });
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-success');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Healthy');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-queue').textContent, '0 / 0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-queue').style.color, '');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-peak').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-peak').style.color, '');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-queue-full').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-no-route').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-packet-too-large').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-write-errors').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-badge').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, false);
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'All route queues clear');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-table').style.display, 'none');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-empty').style.display, 'block');
    } else if (key === 'surviving_peak_after_routes_disconnect') {
        mockDoc.reset();
        const isAvailable = vpnRenderForwarderHealth({
            forwarder_available: true,
            forwarder_queue_capacity: 0,
            forwarder_queue_occupancy: 0,
            forwarder_queue_high_water: 1500,
            forwarder_drops_queue_full: 0,
            forwarder_drops_no_route: 0,
            forwarder_drops_packet_too_large: 0,
            forwarder_drops_total: 0,
            forwarder_device_write_errors: 0,
            transport_decryption_failures: 0
        });
        assert.strictEqual(isAvailable, true);
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-success');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Healthy');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-queue').textContent, '0 / 0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-queue').style.color, '');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-peak').textContent, '1500');
        assert.notStrictEqual(mockDoc.getElementById('vpn-fwd-peak').textContent, '1500 / 0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-peak').style.color, '');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-queue-full').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-no-route').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-packet-too-large').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-write-errors').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, false);
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'All route queues clear');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-table').style.display, 'none');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-empty').style.display, 'block');
    } else if (key === 'failures') {
        mockDoc.reset();
        vpnRenderForwarderHealth({
            forwarder_available: true,
            forwarder_queue_capacity: 2048,
            forwarder_queue_occupancy: 100,
            forwarder_queue_high_water: 500,
            forwarder_drops_queue_full: 5,
            forwarder_drops_no_route: 2,
            forwarder_drops_packet_too_large: 1,
            forwarder_device_write_errors: 2,
            forwarder_route_queues: {}
        });
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-danger');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Pressure Detected');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-queue-full').textContent, '5');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-queue-full').style.color, 'var(--danger)');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-write-errors').textContent, '2');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-write-errors').style.color, 'var(--danger)');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-no-route').textContent, '2');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-no-route').style.color, 'var(--warning)');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-packet-too-large').textContent, '1');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-packet-too-large').style.color, 'var(--warning)');
    } else if (key === 'saturated_route') {
        mockDoc.reset();
        vpnRenderForwarderHealth({
            forwarder_available: true,
            forwarder_queue_capacity: 2048,
            forwarder_queue_occupancy: 200,
            forwarder_queue_high_water: 1200,
            forwarder_drops_queue_full: 0,
            forwarder_drops_no_route: 0,
            forwarder_drops_packet_too_large: 0,
            forwarder_device_write_errors: 0,
            transport_decryption_failures: 0,
            forwarder_route_queues: {
                'abcdefghijklmnopqrstuvwxyz012345': {
                    capacity: 2048,
                    occupancy: 2048,
                    high_water: 2048,
                    // Saturation includes fresh drops; lifetime loss alone stays descriptive.
                    queue_full_drops: 1723,
                    queue_full_drops_recent: 3,
                    write_count: 5000,
                    write_errors: 10
                }
            }
        });
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, true);
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'Pressure Detected');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').style.color, 'var(--danger)');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-danger');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Pressure Detected');
        const rows = mockDoc.getElementById('vpn-fwd-routes-tbody').children;
        assert.strictEqual(rows.length, 1);
        const r1 = rows[0];
        assert(r1.children[0].title.includes('Peer: abcdefghijklmnopqrstuvwxyz012345'));
        assert.strictEqual(r1.children[0].textContent, 'abcdefgh...2345');
        assert.strictEqual(r1.children[1].textContent, '2048 / 2048');
        assert.strictEqual(r1.children[1].style.color, 'var(--danger)');
        assert.strictEqual(r1.children[2].textContent, '2048');
        assert.strictEqual(r1.children[3].textContent, '1723');
        assert.strictEqual(r1.children[3].style.color, 'var(--danger)');
    } else if (key === 'absent_fields') {
        mockDoc.reset();
        mockDoc.getElementById('vpn-fwd-status-badge').className = 'badge badge-success';
        mockDoc.getElementById('vpn-fwd-status-text').textContent = 'Healthy';
        mockDoc.getElementById('vpn-fwd-queue').textContent = '50 / 2048';
        vpnRenderForwarderHealth({
            listener_running: true,
            active_tunnels: 2,
            connected_sessions: 2
        });
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Not reported');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-queue').textContent, '-');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-peak').textContent, '-');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-queue-full').textContent, '-');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-no-route').textContent, '-');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-packet-too-large').textContent, '-');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-write-errors').textContent, '-');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'Not reported');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-badge').textContent, '0');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-table').style.display, 'none');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-empty').style.display, 'block');
        assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, false);
        assert(!mockDoc.getElementById('vpn-fwd-status-badge').className.includes('badge-success'));
    } else if (key === 'peer_sync_in_sync') {
        mockDoc.reset();
        vpnRenderForwarderHealth({
            forwarder_available: true,
            forwarder_queue_capacity: 2048,
            forwarder_queue_occupancy: 10,
            peer_sync: { desired_peers: 12, actual_peers: 12 }
        });
        // The Peer Sync KPI reports SYNCHRONIZATION (issue #424 round 4, item H),
        // not the handshake peer count it used to render.
        assert.strictEqual(mockDoc.getElementById('vpn-kpi-peer-sync').textContent, '12 / 12');
        assert.strictEqual(mockDoc.getElementById('vpn-kpi-peer-sync').style.color, '');
    } else if (key === 'peer_sync_diverged') {
        mockDoc.reset();
        vpnRenderForwarderHealth({
            forwarder_available: true,
            forwarder_queue_capacity: 2048,
            forwarder_queue_occupancy: 10,
            peer_sync: { desired_peers: 12, actual_peers: 11 }
        });
        const kpi = mockDoc.getElementById('vpn-kpi-peer-sync');
        assert.strictEqual(kpi.textContent, '11 / 12');
        assert.strictEqual(kpi.style.color, 'var(--warning)');
    } else if (key === 'peer_sync_absent') {
        // peer_sync is omitempty: an absent payload must NOT render a misleading
        // '0 / 0', it must render the same explicit unavailable state the Peer
        // Sync panel uses.
        for (const sample of [
            { forwarder_available: true, forwarder_queue_capacity: 2048 },
            { forwarder_available: true, forwarder_queue_capacity: 2048, peer_sync: null },
            { forwarder_available: true, forwarder_queue_capacity: 2048, peer_sync: 7 },
            { forwarder_available: true, forwarder_queue_capacity: 2048, handshake_freshness: { total_peers: 42 } }
        ]) {
            mockDoc.reset();
            vpnRenderForwarderHealth(sample);
            assert.strictEqual(mockDoc.getElementById('vpn-kpi-peer-sync').textContent, 'Unavailable');
            assert.strictEqual(mockDoc.getElementById('vpn-kpi-peer-sync').style.color, 'var(--text-muted)');
        }
    } else if (key === 'peer_sync_ignores_handshake_count') {
        // A large handshake peer count must not be presented as the sync KPI.
        mockDoc.reset();
        vpnRenderForwarderHealth({
            forwarder_available: true,
            forwarder_queue_capacity: 2048,
            handshake_freshness: { total_peers: 42 },
            connected_sessions: 42,
            peer_sync: { desired_peers: 2, actual_peers: 2 }
        });
        const kpi = mockDoc.getElementById('vpn-kpi-peer-sync');
        assert.notStrictEqual(kpi.textContent, '42 peers');
        assert.strictEqual(kpi.textContent, '2 / 2');
    } else if (key === 'failed_sample') {
        const samples = [null, undefined, {}, { forwarder_available: false }, { forwarder_available: false, forwarder_queue_capacity: 0 }];
        for (const sample of samples) {
            mockDoc.reset();
            mockDoc.getElementById('vpn-fwd-status-badge').className = 'badge badge-success';
            mockDoc.getElementById('vpn-fwd-status-text').textContent = 'Healthy';
            mockDoc.getElementById('vpn-fwd-queue').textContent = '50 / 2048';
            vpnRenderForwarderHealth(sample);
            assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge');
            assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Not reported');
            assert.strictEqual(mockDoc.getElementById('vpn-fwd-queue').textContent, '-');
            assert.strictEqual(mockDoc.getElementById('vpn-fwd-peak').textContent, '-');
            assert.strictEqual(mockDoc.getElementById('vpn-fwd-drops-queue-full').textContent, '-');
            assert.strictEqual(mockDoc.getElementById('vpn-fwd-write-errors').textContent, '-');
            assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'Not reported');
            assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, false);
            assert(!mockDoc.getElementById('vpn-fwd-status-badge').className.includes('badge-success'));
        }
    } else {
        throw new Error('Unknown scenario key: ' + key);
    }
}

const scenarioArg = process.argv[1];
if (scenarioArg && scenarioArg !== 'all') {
    runScenario(scenarioArg);
} else {
    ['healthy', 'healthy_zero_routes', 'surviving_peak_after_routes_disconnect', 'failures', 'saturated_route', 'absent_fields', 'failed_sample', 'peer_sync_in_sync', 'peer_sync_diverged', 'peer_sync_absent', 'peer_sync_ignores_handshake_count'].forEach(runScenario);
}
console.log('SCENARIO_PASS');
`
}

func runDOMScenario(t *testing.T, nodePath, vpnStr, scenarioKey string) {
	t.Helper()
	f1, err := extractJSFunction(vpnStr, "function vpnFormatPeerKey")
	if err != nil {
		t.Fatalf("extract vpnFormatPeerKey failed: %v", err)
	}
	f2, err := extractJSFunction(vpnStr, "function vpnRenderForwarderHealth")
	if err != nil {
		t.Fatalf("extract vpnRenderForwarderHealth failed: %v", err)
	}

	script := buildJSTestRunner(f1, f2)
	cmd := exec.Command(nodePath, "-e", script, scenarioKey)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("DOM scenario %s failed: %v\nOutput:\n%s", scenarioKey, err, string(out))
	}
	if !strings.Contains(string(out), "SCENARIO_PASS") {
		t.Fatalf("DOM scenario %s did not output SCENARIO_PASS\nOutput:\n%s", scenarioKey, string(out))
	}
}

func TestIssue424ForwarderHealthRedesign(t *testing.T) {
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	vpnData, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}
	vpnStr := string(vpnData)

	t.Run("RequiredDOMElements", func(t *testing.T) {
		requiredIDs := []string{
			"vpn-fwd-headline-summary",
			"vpn-fwd-problem-list",
			"vpn-kpi-throughput",
			"vpn-kpi-routes-sessions",
			"vpn-kpi-queue-pressure",
			"vpn-kpi-packet-loss",
			"vpn-kpi-client-engine",
			"vpn-kpi-peer-sync",
			"vpn-kpi-backends",
			"vpn-kpi-slow-writes",
			"vpn-diag-throughput",
			"vpn-diag-packets",
			"vpn-diag-ewma5m",
			"vpn-diag-ewma1h",
			"vpn-diag-queue-occ",
			"vpn-diag-queue-peak",
			"vpn-diag-queue-dur50",
			"vpn-diag-queue-dur80",
			"vpn-diag-queue-drops",
			"vpn-diag-lat-percentiles",
			"vpn-diag-lat-max",
			"vpn-diag-lat-inflight",
			"vpn-diag-lat-stalls",
			"vpn-diag-lat-errors",
			"vpn-diag-drops-client",
			"vpn-diag-drops-return",
			"vpn-diag-drops-total",
			"vpn-diag-vtun-upstream",
			"vpn-diag-vtun-nexus",
			"vpn-diag-engine-status",
			"vpn-diag-peers-status",
			"vpn-diag-sync-failures",
			"vpn-diag-hs-freshness",
			"vpn-diag-routing-badge",
			"vpn-diag-routing-counts",
			"vpn-diag-routing-alerts",
			"vpn-diag-be-counts",
			"vpn-diag-be-latency",
			"vpn-diag-be-skew",
			"vpn-diag-be-drops",
			"vpn-diag-res-cpu",
			"vpn-diag-res-mem",
			"vpn-diag-res-goroutines",
			"vpn-diag-res-gc",
			"vpn-diag-res-fd",
			"vpn-chart-throughput",
			"vpn-chart-queue",
			"vpn-chart-drops",
			"vpn-chart-latency",
			"vpn-routes-toggle-all-btn",
		}
		for _, id := range requiredIDs {
			if !strings.Contains(vpnStr, fmt.Sprintf(`id="%s"`, id)) {
				t.Errorf("vpn.html missing required element ID %q", id)
			}
		}
	})

	t.Run("TranslationKeysInAllLanguages", func(t *testing.T) {
		transFS, err := GetTranslationsSubFS()
		if err != nil {
			t.Fatalf("GetTranslationsSubFS failed: %v", err)
		}

		requiredKeys := []string{
			"vpn_fwd_panel_traffic",
			"vpn_fwd_panel_queue",
			"vpn_fwd_panel_latency",
			"vpn_fwd_panel_drops",
			"vpn_fwd_panel_vtun",
			"vpn_fwd_panel_peer_sync",
			"vpn_fwd_panel_routing",
			"vpn_fwd_panel_backends",
			"vpn_fwd_panel_runtime",
			"vpn_fwd_panel_history",
			"vpn_fwd_panel_problems",
			"vpn_fwd_upstream_to_nexus",
			"vpn_fwd_nexus_to_upstream",
			"vpn_fwd_show_all",
			"vpn_fwd_show_problems",
			"vpn_fwd_kpi_throughput",
			"vpn_fwd_kpi_routes",
			"vpn_fwd_kpi_pressure",
			"vpn_fwd_kpi_loss",
			"vpn_fwd_kpi_client_engine",
			"vpn_fwd_kpi_peer_sync",
			"vpn_fwd_kpi_backends",
			"vpn_fwd_kpi_slow_writes",
		}

		languages := []string{"en.json", "ru.json", "fa.json", "fr.json", "zh.json"}
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
					t.Errorf("%s missing required translation key %q", langFile, k)
				}
				if strings.Contains(val, "\u2014") {
					t.Errorf("%s key %s contains prohibited em dash (\\u2014): %q", langFile, k, val)
				}
			}
		}
	})

	t.Run("ExecutableJSDOMHealthAssessment", func(t *testing.T) {
		nodePath, err := findNodeBinary()
		if err != nil {
			t.Skipf("node binary not found: %v", err)
		}

		f1, err := extractJSFunction(vpnStr, "function vpnFormatPeerKey")
		if err != nil {
			t.Fatalf("extract vpnFormatPeerKey failed: %v", err)
		}
		f2, err := extractJSFunction(vpnStr, "function vpnRenderForwarderHealth")
		if err != nil {
			t.Fatalf("extract vpnRenderForwarderHealth failed: %v", err)
		}

		runnerScript := fmt.Sprintf(`const assert = require('assert');

class MockElement {
    constructor(tagName, id) {
        this.tagName = (tagName || 'div').toUpperCase();
        this.id = id || '';
        this.children = [];
        this._textContent = '';
        this.className = '';
        this.style = {};
        this.title = '';
        this.open = false;
        this.attributes = {};
    }
    get textContent() { return this._textContent; }
    set textContent(val) {
        this._textContent = String(val);
        if (val === '') this.children = [];
    }
    appendChild(child) {
        this.children.push(child);
        return child;
    }
    setAttribute(name, val) { this.attributes[name] = String(val); }
    getAttribute(name) { return this.attributes[name]; }
}

class MockDocument {
    constructor() { this.reset(); }
    reset() {
        this.elements = new Map();
        const ids = [
            'vpn-forwarder-card', 'vpn-fwd-status-badge', 'vpn-fwd-status-text',
            'vpn-fwd-headline-summary', 'vpn-fwd-problem-list',
            'vpn-kpi-throughput', 'vpn-kpi-routes-sessions', 'vpn-kpi-queue-pressure',
            'vpn-kpi-packet-loss', 'vpn-kpi-client-engine', 'vpn-kpi-peer-sync',
            'vpn-kpi-backends', 'vpn-kpi-slow-writes',
            'vpn-fwd-queue', 'vpn-fwd-peak', 'vpn-fwd-drops-queue-full',
            'vpn-fwd-drops-no-route', 'vpn-fwd-drops-packet-too-large',
            'vpn-fwd-write-errors',
            'vpn-fwd-routes-details', 'vpn-fwd-routes-badge',
            'vpn-fwd-routes-summary-status', 'vpn-fwd-routes-empty',
            'vpn-fwd-routes-table', 'vpn-fwd-routes-tbody',
            'vpn-diag-throughput', 'vpn-diag-packets', 'vpn-diag-ewma5m', 'vpn-diag-ewma1h',
            'vpn-diag-queue-occ', 'vpn-diag-queue-peak', 'vpn-diag-queue-dur50',
            'vpn-diag-queue-dur80', 'vpn-diag-queue-drops',
            'vpn-diag-lat-percentiles', 'vpn-diag-lat-max', 'vpn-diag-lat-inflight',
            'vpn-diag-lat-stalls', 'vpn-diag-lat-errors',
            'vpn-diag-drops-client', 'vpn-diag-drops-return', 'vpn-diag-drops-total',
            'vpn-diag-vtun-upstream', 'vpn-diag-vtun-nexus',
            'vpn-diag-engine-status', 'vpn-diag-peers-status', 'vpn-diag-sync-failures',
            'vpn-diag-hs-freshness', 'vpn-diag-routing-badge', 'vpn-diag-routing-counts',
            'vpn-diag-routing-alerts', 'vpn-diag-be-counts', 'vpn-diag-be-latency',
            'vpn-diag-be-skew', 'vpn-diag-be-drops',
            'vpn-diag-res-cpu', 'vpn-diag-res-mem', 'vpn-diag-res-goroutines',
            'vpn-diag-res-gc', 'vpn-diag-res-fd',
            'vpn-chart-throughput', 'vpn-chart-queue', 'vpn-chart-drops', 'vpn-chart-latency',
            'vpn-routes-toggle-all-btn'
        ];
        for (const id of ids) {
            this.elements.set(id, new MockElement('div', id));
        }
        this.elements.get('vpn-fwd-status-badge').className = 'badge';
        this.elements.get('vpn-fwd-status-text').textContent = 'Not reported';
        this.elements.get('vpn-fwd-routes-empty').style.display = 'block';
        this.elements.get('vpn-fwd-routes-table').style.display = 'none';
        this.elements.get('vpn-fwd-routes-details').open = false;
    }
    getElementById(id) { return this.elements.get(id) || null; }
    createElement(tag) { return new MockElement(tag); }
}

const mockDoc = new MockDocument();
const translations = {
    'vpn_forwarder_unavailable': 'Not reported',
    'vpn_forwarder_healthy': 'Healthy',
    'vpn_forwarder_pressure': 'Pressure Detected',
    'vpn_forwarder_warning': 'Warning',
    'vpn_forwarder_no_route_pressure': 'All route queues clear',
    'vpn_diag_peer_sync_unavailable': 'Unavailable'
};
const _ = (key) => translations[key] || key;
const document = mockDoc;

%s
%s

// Test 1: HEALTHY state
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: {
        status: 'HEALTHY',
        summary: 'All clear and operational'
    },
    rates: { rx_bps: 1000000, tx_bps: 2000000 },
    routing_consistency: { is_consistent: true, active_routes_count: 5, active_sessions_count: 5 },
    backends: { healthy_count: 2, total_count: 2 }
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-success');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Healthy');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-headline-summary').textContent, 'All clear and operational');
assert.strictEqual(mockDoc.getElementById('vpn-kpi-backends').textContent, '2 / 2 healthy');

// Test 2: DEGRADED state with condition
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: {
        status: 'DEGRADED',
        summary: 'Elevated queue pressure',
        conditions: [{ severity: 'DEGRADED', message: 'Queue occupancy > 50%%' }]
    }
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-warn');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Warning');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-problem-list').style.display, 'flex');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-problem-list').children.length, 1);

// Test 3: CRITICAL state
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: {
        status: 'CRITICAL',
        summary: 'Packet drops detected',
        conditions: [{ severity: 'CRITICAL', message: 'Queue full drops' }]
    }
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-danger');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Pressure Detected');

// Test 4: UNAVAILABLE state
mockDoc.reset();
vpnRenderForwarderHealth(null);
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Not reported');
assert.strictEqual(mockDoc.getElementById('vpn-kpi-throughput').textContent, '-');

// Current route alarms recover while lifetime totals remain visible.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available:true, forwarder_queue_capacity:100, forwarder_queue_occupancy:0,
    health_assessment:{status:'HEALTHY',summary:'Recovered',conditions:[]},
    problem_routes:[],
    all_routes:[{peer_key:'peer',capacity:100,occupancy:0,drops:5,has_pressure:false}]
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'All route queues clear');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, false);
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Healthy');

// Fresh loss remains a problem after the queue drains.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available:true, forwarder_queue_capacity:100,
    problem_routes:[{peer_key:'peer',capacity:100,occupancy:0,drops:5,has_pressure:true}],
    all_routes:[{peer_key:'peer',capacity:100,occupancy:0,drops:5,has_pressure:true}]
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'Pressure Detected');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, true);

// Old payloads have no flag; current occupancy still detects live pressure.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available:true,forwarder_queue_capacity:100,
    forwarder_route_queues:{peer:{capacity:100,occupancy:0,queue_full_drops:5}}
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'All route queues clear');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, false);
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available:true,forwarder_queue_capacity:100,
    forwarder_route_queues:{peer:{capacity:100,occupancy:0,queue_full_drops:5,write_errors:7,write_count:20}}
});
const recoveredLegacyRow = mockDoc.getElementById('vpn-fwd-routes-tbody').children[0];
assert.notStrictEqual(recoveredLegacyRow.children[3].style.color,'var(--danger)');
assert.notStrictEqual(recoveredLegacyRow.children[4].style.color,'var(--warning)');
assert(recoveredLegacyRow.children[4].textContent.includes('cumulative errors'));
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent,'All route queues clear');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open,false);
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available:true,forwarder_queue_capacity:100,
    forwarder_route_queues:{peer:{capacity:100,occupancy:80,queue_full_drops:5}}
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'Pressure Detected');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, true);

// Recovered KPIs keep lifetime evidence descriptive and show current availability.
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,health_assessment:{status:'HEALTHY',summary:'Recovered'},
 drop_categories:{total_drops:99,total_drop_rate_pps:0},
 forward_latency:{stalls:7,stalls_recent:0,p95_ms:300,p95_health_ms:0,p95_health_samples:0,oldest_in_flight_ms:0},
 backends:{eligibility_known:true,healthy_count:1,enabled_count:1,disabled_count:2,total_count:3}
});
assert.strictEqual(mockDoc.getElementById('vpn-kpi-packet-loss').style.color,'');
assert(mockDoc.getElementById('vpn-kpi-packet-loss').textContent.includes('cumulative'));
assert.strictEqual(mockDoc.getElementById('vpn-kpi-slow-writes').style.color,'');
assert(mockDoc.getElementById('vpn-kpi-slow-writes').textContent.includes('unavailable'));
assert.strictEqual(mockDoc.getElementById('vpn-kpi-backends').style.color,'');
assert(mockDoc.getElementById('vpn-kpi-backends').textContent.includes('1 / 1'));
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 drop_categories:{total_drops:100,total_drop_rate_pps:2},
 forward_latency:{stalls:8,stalls_recent:1,p95_ms:300,p95_health_ms:150,p95_health_samples:1}
});
assert.strictEqual(mockDoc.getElementById('vpn-kpi-packet-loss').style.color,'var(--danger)');
assert.strictEqual(mockDoc.getElementById('vpn-kpi-slow-writes').style.color,'var(--danger)');
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 forward_latency:{p95_health_ms:0,p95_health_samples:1,stalls_recent:0},
 backends:{eligibility_known:true,healthy_count:0,enabled_count:0,disabled_count:3,total_count:3}
});
assert(mockDoc.getElementById('vpn-kpi-slow-writes').textContent.includes('0.0ms'));
assert(!mockDoc.getElementById('vpn-kpi-slow-writes').textContent.includes('unavailable'));
assert.strictEqual(mockDoc.getElementById('vpn-kpi-backends').style.color,'var(--danger)');

mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 rates:{available:false,rx_bps:0,tx_bps:0},
 drop_categories:{rates_available:false,total_drops:0,total_drop_rate_pps:0}
});
assert(mockDoc.getElementById('vpn-kpi-throughput').textContent.includes('unavailable'));
assert(mockDoc.getElementById('vpn-kpi-packet-loss').textContent.includes('unavailable'));
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 rates:{available:true,rx_bps:0,tx_bps:0},
 drop_categories:{rates_available:true,total_drops:0,total_drop_rate_pps:0}
});
assert(!mockDoc.getElementById('vpn-kpi-throughput').textContent.includes('unavailable'));
assert(!mockDoc.getElementById('vpn-kpi-packet-loss').textContent.includes('unavailable'));

console.log('ISSUE_424_PASS');
`, f1, f2)

		cmd := exec.Command(nodePath, "-e", runnerScript)
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Issue 424 JSDOM tests failed: %v\nOutput:\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "ISSUE_424_PASS") {
			t.Fatalf("Issue 424 JSDOM tests did not output ISSUE_424_PASS\nOutput:\n%s", string(out))
		}
	})
}

func TestVPNHistoryChartLatencyAvailability(t *testing.T) {
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Skipf("node binary not found: %v", err)
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	templateData, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	sparkline, err := extractJSFunction(string(templateData), "function vpnGenerateSparklineSVG")
	if err != nil {
		t.Fatal(err)
	}
	render, err := extractJSFunction(string(templateData), "function vpnRenderHistoryCharts")
	if err != nil {
		t.Fatal(err)
	}
	script := `const assert = require('assert');
const chart = {innerHTML:''};
const document = {getElementById:id => id === 'vpn-chart-latency' ? chart : null};
` + sparkline + "\n" + render + `
vpnRenderHistoryCharts({window_15m:[
    {fwd_p95_ms:200,fwd_p95_samples:1},
    {fwd_p95_ms:200,fwd_p95_samples:0},
    {fwd_p95_ms:0,fwd_p95_samples:1}
]});
const stroke = chart.innerHTML.match(/<path d="([^"]+)" fill="none"/);
assert(stroke, 'observed latency must remain visible');
assert.strictEqual((stroke[1].match(/M /g) || []).length, 2, 'missing latency must break the line');
assert(!stroke[1].includes(' L '), 'isolated observations must not connect across the gap');
assert(stroke[1].includes('M 2.0 2.0') && stroke[1].includes('M 198.0 38.0'), 'gaps must preserve observation x positions');
assert.strictEqual((chart.innerHTML.match(/<circle /g) || []).length, 2, 'zero and slow observations must both be visible');
vpnRenderHistoryCharts({window_15m:[{fwd_p95_ms:200,fwd_p95_samples:0}]});
assert(chart.innerHTML.includes('No data'), 'idle history must be unavailable');
assert(!chart.innerHTML.includes('<path'), 'unavailable history must not invent zero/slow curves');
vpnRenderHistoryCharts({window_15m:[{fwd_p95_ms:0,fwd_p95_samples:1}]});
assert(!chart.innerHTML.includes('No data'), 'a measured zero is available');
vpnRenderHistoryCharts({window_15m:[{fwd_p95_ms:20}]});
assert(!chart.innerHTML.includes('No data'), 'old payloads remain readable');
`
	cmd := exec.Command(nodePath, "-e", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("history renderer: %v\n%s", err, out)
	}
}

func TestVPNCompleteRouteTooltipContract(t *testing.T) {
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Skipf("node binary not found: %v", err)
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := extractJSFunction(string(data), "function vpnFormatPeerKey")
	if err != nil {
		t.Fatal(err)
	}
	render, err := extractJSFunction(string(data), "function vpnRenderForwarderHealth")
	if err != nil {
		t.Fatal(err)
	}
	// Marshal the production schema: a newly populated field cannot silently
	// disappear between the status payload and the complete tooltip.
	route := vpn.ProblemRouteItem{
		PeerKey: "abcd...wxyz", AssignedIP: "192.0.2.8", BackendID: 38,
		Occupancy: 23, Capacity: 100, HighWater: 47, UtilizationPct: 23, HighWaterPct: 47,
		Drops: 17, P95WriteMS: 18, HasPressure: true, PressureNote: "Recent write errors: 19",
		WriteCount: 101, WriteErrors: 19, WriteStalls: 20, WritesInFlight: 21,
		OldestWriteMS: 22, MaxWriteMS: 24, P95WriteSamples: 25, QueueFullDropsRecent: 26,
		WriteErrorsRecent: 27, WriteStallsRecent: 28, SessionAgeSec: 29, LastTrafficAgeSec: 30,
		Traffic: forwarder.TrafficSnapshot{RxBytes: 31, TxBytes: 32, RxPackets: 33, TxPackets: 34,
			RxBytesPerSec: 35, TxBytesPerSec: 36, RxPps: 37, TxPps: 39, Available: true, WindowSec: 40},
	}
	encoded, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	script := "const route = " + string(encoded) + ";\n" + expandedDOMMock + "\n" + peer + "\n" + render + `
vpnRenderForwarderHealth({forwarder_available:true,forwarder_queue_capacity:100,problem_routes:[route]});
const title = document.getElementById('vpn-fwd-routes-tbody').children[0].children[0].title;
const labels = {
 peer_key:'Peer',assigned_ip:'Assigned address',backend_id:'Backend',
 occupancy:'Queue occupancy',capacity:'Queue capacity',high_water:'Queue high water',
 utilization_pct:'Queue utilization (%)',high_water_pct:'High water (%)',
 drops:'Queue drops (cumulative)',p95_write_ms:'Write p95 (historical ms)',
 has_pressure:'Current pressure',pressure_note:'Pressure reason',
 write_count:'Writes admitted',write_errors:'Write errors (cumulative)',write_stalls:'Write stalls (cumulative)',
 writes_in_flight:'Writes in flight',oldest_write_ms:'Oldest write (ms)',max_write_ms:'Max write (historical ms)',
 p95_write_samples:'Write percentile samples',queue_full_drops_recent:'Recent queue drops',
 write_errors_recent:'Recent write errors',write_stalls_recent:'Recent write stalls',
 session_age_sec:'Session age (s)',last_traffic_age_sec:'Last traffic age (s)',traffic:'Directional traffic'
};
assert.deepStrictEqual(Object.keys(route).sort(),Object.keys(labels).sort(),'payload/tooltip field contract drifted');
for (const key of Object.keys(route)) {
 if (key === 'traffic') {
  for (const name of Object.keys(route.traffic)) {
   assert(title.includes('Directional traffic '+name.replace(/_/g,' ')+': '+route.traffic[name]), name);
  }
 } else assert(title.includes(labels[key]+': '+route[key]),key);
}
route.traffic.available=false; route.last_traffic_age_sec=-1;route.p95_write_samples=0;
vpnRenderForwarderHealth({forwarder_available:true,forwarder_queue_capacity:100,problem_routes:[route]});
const unknown = document.getElementById('vpn-fwd-routes-tbody').children[0].children[0].title;
assert(unknown.includes('Directional traffic rx bytes per sec: Unavailable'));
assert(unknown.includes('Write p95 (historical ms): Unavailable'));
assert(unknown.includes('Last traffic age (s): Unavailable'));
vpnRenderForwarderHealth({forwarder_available:true,forwarder_queue_capacity:100,backends:{backends:[
 {server_name:'Server 1',enabled:true,health_state:'active',traffic_available:false},
 {server_name:'Server 2',enabled:true,health_state:'active',traffic_available:true,rx_bytes_per_sec:0,tx_bytes_per_sec:0,rx_pps:0,tx_pps:0},
 {server_name:'Server 3',enabled:false,health_state:'active',traffic_available:true,rx_bytes_per_sec:125,tx_bytes_per_sec:250,rx_pps:2,tx_pps:3}
]}});
const rows=document.getElementById('vpn-diag-be-traffic').children;
assert(rows[0].textContent.includes('Traffic unavailable'));
assert(!rows[1].textContent.includes('unavailable') && rows[1].textContent.includes('RX 0'));
assert(rows[2].textContent.includes('Disabled') && rows[2].textContent.includes('1.00 Kbps') && rows[2].textContent.includes('2.00 Kbps'));

`
	cmd := exec.Command(nodePath, "-e", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("complete route tooltip: %v\n%s", err, out)
	}
}

const expandedDOMMock = `const assert = require('assert');
class Element {
 constructor() { this.children=[];this._text='';this.innerHTML='';this.style={};this.className='';this.title=''; }
 set textContent(s) { this._text=String(s);this.children=[]; }
 get textContent() { return this._text; }
 appendChild(child) { this.children.push(child);return child; }
 setAttribute() {}
}
const elements = new Map();
const document = {
 getElementById(id) { if (!elements.has(id)) elements.set(id,new Element());return elements.get(id); },
 createElement() { return new Element(); }
};
const _ = key => key;
`

func TestVPNCompleteHistoryAllWindowRenderers(t *testing.T) {
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Skipf("node binary not found: %v", err)
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"directions", "packets", "sessions-routes", "backend-latency", "reasons", "backends"} {
		if !strings.Contains(string(data), `id="vpn-chart-`+id+`"`) {
			t.Fatalf("missing history chart %s", id)
		}
	}
	sparkline, err := extractJSFunction(string(data), "function vpnGenerateSparklineSVG")
	if err != nil {
		t.Fatal(err)
	}
	render, err := extractJSFunction(string(data), "function vpnRenderHistoryCharts")
	if err != nil {
		t.Fatal(err)
	}
	script := expandedDOMMock + "\n" + sparkline + "\n" + render + `
let vpnHistoryWindow='15m';
const originalSparkline = vpnGenerateSparklineSVG;
const seen=[];
vpnGenerateSparklineSVG = (values,...args) => {seen.push(values);return originalSparkline(values,...args);};
function entry(id,label) {
 const children=document.getElementById(id).children;
 const index=children.findIndex(e=>e.textContent===label+' ('+vpnHistoryWindow+')');
 assert(index>=0,'missing labelled series '+label+' in '+vpnHistoryWindow);
 return children[index+1].innerHTML;
}
const series={};
for (const [i,w] of ['15m','1h','6h','24h'].entries()) {
 const value=i+1;
 series['window_'+w]=[{
  t:100,rx_bps:999,tx_bps:999,rx_pps:999,tx_pps:999,traffic_available:false,
  q_pct:0,drop_rate:999,drop_rates_available:false,
  drop_reason_rates:{return_queue_full:999,client_backend_device_queue_full:999},
  fwd_p95_ms:999,fwd_p95_samples:0,be_p95_ms:999,be_latency_samples:0,sessions:0,routes:0,backends:[]
 },{
  t:110,rx_bps:value,tx_bps:2*value,rx_pps:3*value,tx_pps:4*value,traffic_available:true,
  q_pct:5*value,drop_rate:6*value,drop_rates_available:true,
  drop_reason_rates:{return_queue_full:2*value,client_backend_device_queue_full:4*value},
  fwd_p95_ms:7*value,fwd_p95_samples:1,be_p95_ms:8*value,be_latency_samples:1,sessions:9*value,routes:10*value,
  backends:[{id:3,rx_bps:11*value,tx_bps:12*value,rx_pps:13*value,tx_pps:14*value,
   traffic_available:true,probe_latency_ms:15*value,probe_available:true,routable:true}]
 },{
  t:120,rx_bps:0,tx_bps:0,rx_pps:0,tx_pps:0,traffic_available:true,q_pct:0,drop_rate:0,
  drop_rates_available:true,drop_reason_rates:{return_queue_full:0,client_backend_device_queue_full:0},
  fwd_p95_ms:0,fwd_p95_samples:1,be_p95_ms:0,be_latency_samples:0,sessions:0,routes:0,
  backends:[{id:3,rx_bps:0,tx_bps:0,rx_pps:0,tx_pps:0,traffic_available:true,probe_available:false}]
 }];
}
for (const [i,w] of ['15m','1h','6h','24h'].entries()) {
 vpnHistoryWindow=w;seen.length=0;vpnRenderHistoryCharts(series);
 const v=i+1;
 assert.deepStrictEqual(seen.slice(0,4),[[null,3*v,0],[0,5*v,0],[null,6*v,0],[null,7*v,0]]);
 assert.deepStrictEqual(seen.slice(4,11),[[null,v,0],[null,2*v,0],[null,3*v,0],[null,4*v,0],[0,9*v,0],[0,10*v,0],[null,8*v,null]]);
 assert.deepStrictEqual(seen.slice(11),[[null,4*v,0],[null,2*v,0],[null,11*v,0],[null,12*v,0],[null,13*v,0],[null,14*v,0],[null,15*v,null]]);
 for (const [id,label] of [
  ['vpn-chart-directions','RX client to backend (bps)'],['vpn-chart-directions','TX backend to client (bps)'],
  ['vpn-chart-packets','RX packets/s'],['vpn-chart-packets','TX packets/s'],
  ['vpn-chart-sessions-routes','Active sessions'],['vpn-chart-sessions-routes','Active routes'],
  ['vpn-chart-backend-latency','Eligible backend probe p95 (ms)'],
  ['vpn-chart-reasons','return queue full (drops/s)'],['vpn-chart-reasons','client backend device queue full (drops/s)'],
  ['vpn-chart-backends','Backend 3 RX (bps)'],['vpn-chart-backends','Backend 3 TX (bps)'],
  ['vpn-chart-backends','Backend 3 RX packets/s'],['vpn-chart-backends','Backend 3 TX packets/s'],
  ['vpn-chart-backends','Backend 3 Probe latency (ms)']
 ]) assert(entry(id,label).includes('<svg'),label);
}
vpnHistoryWindow='15m';
vpnRenderHistoryCharts({window_15m:[]});
assert(document.getElementById('vpn-chart-reasons').textContent.includes('No data (15m)'), 'empty reason window must remain visible');
assert(document.getElementById('vpn-chart-backends').textContent.includes('No data (15m)'), 'empty fleet window must remain visible');
vpnRenderHistoryCharts({window_15m:[series.window_15m[0]]});
assert(document.getElementById('vpn-chart-backends').textContent.includes('No data (15m)'), 'pre-provision fleet context must remain visible');
assert(document.getElementById('vpn-chart-throughput').innerHTML.includes('No data'));
assert(document.getElementById('vpn-chart-drops').innerHTML.includes('No data'));
assert(entry('vpn-chart-directions','RX client to backend (bps)').includes('No data'));
assert(entry('vpn-chart-reasons','return queue full (drops/s)').includes('No data'));
// Retired/re-registered backend IDs form gaps, never zero-filled continuity.
vpnRenderHistoryCharts({window_15m:[
 {backends:[{id:3,rx_bps:10,traffic_available:true}]},{backends:[]},
 {backends:[{id:3,rx_bps:0,traffic_available:true}]}
]});
const gap=entry('vpn-chart-backends','Backend 3 RX (bps)');
assert.strictEqual((gap.match(/<circle /g)||[]).length,2);
const gapStroke=gap.match(/<path d="([^"]+)" fill="none"/);
assert(gapStroke && !gapStroke[1].includes(' L '),'isolated backend samples must not bridge lifecycle gap');
vpnRenderHistoryCharts({window_15m:[{backends:Array.from({length:129},(_,id)=>({id})),backends_omitted:5}]});
assert.strictEqual(document.getElementById('vpn-chart-backends').children.length,128*5*2,'fleet churn renderer must remain bounded');
assert(document.getElementById('vpn-history-fleet-note').textContent.includes('5 omitted'));
`
	cmd := exec.Command(nodePath, "-e", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("complete history renderers: %v\n%s", err, out)
	}
}

// An unavailable forwarder must erase every rendered history surface. The
// history render path produces two DOM shapes (injected SVG markup in the four
// sparkline containers, appended element children in the renderSeries
// containers), so seeding real stale state and then asserting both shapes are
// empty is what makes this regression meaningful. Starting from empty
// containers would prove nothing.
func TestVPNUnavailableForwarderClearsStaleHistoryState(t *testing.T) {
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Skipf("node binary not found: %v", err)
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"vpn-chart-throughput", "vpn-chart-packets", "vpn-chart-queue", "vpn-chart-latency",
		"vpn-chart-drops", "vpn-chart-directions", "vpn-chart-reasons",
		"vpn-chart-sessions-routes", "vpn-chart-backends", "vpn-chart-backend-latency",
		"vpn-diag-be-traffic", "vpn-history-fleet-note",
	} {
		if !strings.Contains(string(data), `id="`+id+`"`) {
			t.Fatalf("missing stale-clearing target %s", id)
		}
	}
	formatPeerKey, err := extractJSFunction(string(data), "function vpnFormatPeerKey")
	if err != nil {
		t.Fatal(err)
	}
	sparkline, err := extractJSFunction(string(data), "function vpnGenerateSparklineSVG")
	if err != nil {
		t.Fatal(err)
	}
	history, err := extractJSFunction(string(data), "function vpnRenderHistoryCharts")
	if err != nil {
		t.Fatal(err)
	}
	health, err := extractJSFunction(string(data), "function vpnRenderForwarderHealth")
	if err != nil {
		t.Fatal(err)
	}
	setWindow, err := extractJSFunction(string(data), "function vpnSetHistoryWindow")
	if err != nil {
		t.Fatal(err)
	}
	toggleRoutes, err := extractJSFunction(string(data), "function vpnToggleShowAllRoutes")
	if err != nil {
		t.Fatal(err)
	}
	script := expandedDOMMock + "\n" + formatPeerKey + "\n" + sparkline + "\n" + history + "\n" + health + "\n" + setWindow + "\n" + toggleRoutes + `
let vpnHistoryWindow='15m';
let vpnLastStatus=null;
let vpnShowAllRoutes=false;
// The window-toggle control is a persistent button group with no stale data
// of its own; the mock only needs it to answer a querySelectorAll probe.
document.getElementById('vpn-history-window-toggles').querySelectorAll=()=>[];
const SVG_CHARTS=['vpn-chart-throughput','vpn-chart-queue','vpn-chart-drops','vpn-chart-latency'];
const SERIES_CHARTS=['vpn-chart-directions','vpn-chart-packets','vpn-chart-sessions-routes',
 'vpn-chart-backend-latency','vpn-chart-reasons','vpn-chart-backends'];
// Seed realistic stale state: measured series render SVG into the sparkline
// containers and label/child pairs into the renderSeries containers.
vpnRenderHistoryCharts({window_15m:[
 {t:100,rx_bps:900,tx_bps:900,rx_pps:90,tx_pps:90,traffic_available:true,q_pct:12,drop_rate:3,
  drop_rates_available:true,drop_reason_rates:{return_queue_full:3},fwd_p95_ms:41,fwd_p95_samples:1,
  be_p95_ms:33,be_latency_samples:1,sessions:4,routes:3,backends_omitted:5,
  backends:[{id:3,rx_bps:900,tx_bps:900,rx_pps:90,tx_pps:90,traffic_available:true,probe_latency_ms:33,probe_available:true}]},
 {t:160,rx_bps:1200,tx_bps:1200,rx_pps:120,tx_pps:120,traffic_available:true,q_pct:18,drop_rate:4,
  drop_rates_available:true,drop_reason_rates:{return_queue_full:4},fwd_p95_ms:52,fwd_p95_samples:1,
  be_p95_ms:44,be_latency_samples:1,sessions:6,routes:5,backends_omitted:5,
  backends:[{id:3,rx_bps:1200,tx_bps:1200,rx_pps:120,tx_pps:120,traffic_available:true,probe_latency_ms:44,probe_available:true}]}
]});
vpnRenderForwarderHealth({forwarder_available:true,forwarder_queue_capacity:100,
	healthAssessment: {status: 'HEALTHY', summary: 'Operational forwarding', conditions: []},
	rates: {available: true, rx_bps: 1000000, tx_bps: 0, rx_pps: 50, tx_pps: 0},
	all_routes: [{peer_key: 'peer12345678', capacity: 100, occupancy: 0, drops: 0, has_pressure: false}],
	problem_routes: [],
	historical_series:{window_15m:[
  {t:100,rx_bps:900,tx_bps:900,traffic_available:true,q_pct:12,drop_rate:3,drop_rates_available:true,
   drop_reason_rates:{return_queue_full:3},fwd_p95_ms:41,fwd_p95_samples:1,be_p95_ms:33,be_latency_samples:1,
   sessions:4,routes:3,backends_omitted:5,
   backends:[{id:3,rx_bps:900,tx_bps:900,traffic_available:true,probe_latency_ms:33,probe_available:true}]},
  {t:160,rx_bps:1200,tx_bps:1200,traffic_available:true,q_pct:18,drop_rate:4,drop_rates_available:true,
   drop_reason_rates:{return_queue_full:4},fwd_p95_ms:52,fwd_p95_samples:1,be_p95_ms:44,be_latency_samples:1,
   sessions:6,routes:5,backends_omitted:5,
   backends:[{id:3,rx_bps:1200,tx_bps:1200,traffic_available:true,probe_latency_ms:44,probe_available:true}]}
 ]},
 backends:{backends:[
 {server_name:'Server 1',enabled:true,health_state:'active',traffic_available:true,
  rx_bytes_per_sec:900,tx_bytes_per_sec:1200,rx_pps:90,tx_pps:120}
 ]}});
// The available poll must cache a real series, otherwise the toggles below
// have nothing to resurrect and the cache-clearing guard would go untested.
assert(vpnLastStatus&&vpnLastStatus.historical_series,'available poll must cache its series');
assert.strictEqual(document.getElementById('vpn-fwd-status-text').textContent,'vpn_forwarder_healthy','available poll must render Healthy');
assert.strictEqual(document.getElementById('vpn-kpi-throughput').textContent,'1.00 Mbps / 50.0 pps','available poll must render throughput');
for (const id of SVG_CHARTS) {
 assert(document.getElementById(id).innerHTML.includes('<svg'),'seed must render SVG in '+id);
}
for (const id of SERIES_CHARTS) {
 assert(document.getElementById(id).children.length>0,'seed must render series children in '+id);
}
assert(document.getElementById('vpn-diag-be-traffic').children.length>0,'seed must render backend traffic rows');
assert(document.getElementById('vpn-history-fleet-note').textContent.length>0,'seed must render the fleet note');

// The transition under test.
vpnRenderForwarderHealth({forwarder_available:false});
for (const id of SVG_CHARTS) {
 const el=document.getElementById(id);
 assert(!el.innerHTML.includes('<svg'),'stale SVG remains in '+id);
 assert(!el.innerHTML.includes('<path'),'stale curve remains in '+id);
 assert.strictEqual(el.innerHTML,'','sparkline container must be emptied in '+id);
 assert.strictEqual(el.textContent,'','sparkline container text must be emptied in '+id);
}
for (const id of SERIES_CHARTS) {
 const el=document.getElementById(id);
 assert.strictEqual(el.children.length,0,'stale series children remain in '+id);
 assert.strictEqual(el.textContent,'','series container text must be emptied in '+id);
 assert(!el.innerHTML.includes('<svg'),'no placeholder SVG may be injected into '+id);
}
const beTraffic=document.getElementById('vpn-diag-be-traffic');
assert.strictEqual(beTraffic.children.length,0,'backend traffic rows must be cleared');
assert.strictEqual(beTraffic.textContent,'','backend traffic text must be cleared');
const fleetNote=document.getElementById('vpn-history-fleet-note');
assert.strictEqual(fleetNote.textContent,'','fleet omission note must be cleared');
assert.strictEqual(fleetNote.innerHTML,'','fleet omission note markup must be cleared');
// No invented data anywhere in the unavailable state.
for (const id of SVG_CHARTS.concat(SERIES_CHARTS).concat(['vpn-diag-be-traffic','vpn-history-fleet-note'])) {
 const el=document.getElementById(id);
 assert(!el.innerHTML.includes('<path'),'unavailable state must not invent curves in '+id);
 assert(!el.innerHTML.includes('<circle'),'unavailable state must not invent points in '+id);
}
const ALL_KPIS = [
 'vpn-kpi-throughput', 'vpn-kpi-routes-sessions', 'vpn-kpi-queue-pressure',
 'vpn-kpi-packet-loss', 'vpn-kpi-client-engine', 'vpn-kpi-peer-sync',
 'vpn-kpi-backends', 'vpn-kpi-slow-writes'
];
const DETAIL_PANEL_IDS = [
 'vpn-fwd-queue', 'vpn-fwd-peak', 'vpn-fwd-drops-queue-full', 'vpn-fwd-drops-no-route',
 'vpn-fwd-drops-packet-too-large', 'vpn-fwd-write-errors',
 'vpn-diag-throughput', 'vpn-diag-packets', 'vpn-diag-ewma5m', 'vpn-diag-ewma1h',
 'vpn-diag-queue-occ', 'vpn-diag-queue-peak', 'vpn-diag-queue-dur50', 'vpn-diag-queue-dur80',
 'vpn-diag-queue-drops', 'vpn-diag-lat-percentiles', 'vpn-diag-lat-max', 'vpn-diag-lat-inflight',
 'vpn-diag-lat-stalls', 'vpn-diag-lat-errors', 'vpn-diag-drops-client', 'vpn-diag-drops-return',
 'vpn-diag-drops-total', 'vpn-diag-vtun-upstream', 'vpn-diag-vtun-nexus', 'vpn-diag-engine-status',
 'vpn-diag-peers-status', 'vpn-diag-sync-failures', 'vpn-diag-peer-sync-op-failures',
 'vpn-diag-peer-sync-invalid', 'vpn-diag-peer-sync-enqueue', 'vpn-diag-peer-sync-reconcile',
 'vpn-diag-peer-sync-error', 'vpn-diag-peer-sync-restart', 'vpn-diag-hs-freshness',
 'vpn-diag-routing-counts', 'vpn-diag-be-counts', 'vpn-diag-be-latency', 'vpn-diag-be-skew',
 'vpn-diag-be-drops', 'vpn-diag-res-cpu', 'vpn-diag-res-mem', 'vpn-diag-res-goroutines',
 'vpn-diag-res-gc', 'vpn-diag-res-fd'
];

function assertAllSurfacesCleared(context) {
 assert.strictEqual(document.getElementById('vpn-fwd-status-badge').className, 'badge', context + ': status badge className');
 assert.strictEqual(document.getElementById('vpn-fwd-status-text').textContent, 'vpn_forwarder_unavailable', context + ': status text');
 assert.strictEqual(document.getElementById('vpn-fwd-headline-summary').textContent, 'vpn_forwarder_unavailable', context + ': headline');
 const problemList = document.getElementById('vpn-fwd-problem-list');
 assert.strictEqual(problemList.textContent, '', context + ': problem list text');
 assert.strictEqual(problemList.style.display, 'none', context + ': problem list display');

 for (const id of ALL_KPIS) {
  assert.strictEqual(document.getElementById(id).textContent, '-', context + ': KPI ' + id);
 }
 for (const id of DETAIL_PANEL_IDS) {
  assert.strictEqual(document.getElementById(id).textContent, '-', context + ': detail elem ' + id);
 }

 const routBadge = document.getElementById('vpn-diag-routing-badge');
 assert.strictEqual(routBadge.className, 'badge', context + ': routing badge className');
 assert.strictEqual(routBadge.textContent, '-', context + ': routing badge text');
 const routAlerts = document.getElementById('vpn-diag-routing-alerts');
 assert.strictEqual(routAlerts.textContent, '', context + ': routing alerts text');
 assert.strictEqual(routAlerts.style.display, 'none', context + ': routing alerts display');

 assert.strictEqual(document.getElementById('vpn-fwd-routes-badge').textContent, '0', context + ': routes badge');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-summary-status').textContent, 'vpn_forwarder_unavailable', context + ': routes summary');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-tbody').children.length, 0, context + ': route rows');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-table').style.display, 'none', context + ': routes table');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-empty').style.display, 'block', context + ': routes empty div');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-details').open, false, context + ': routes details');

 assert.strictEqual(document.getElementById('vpn-diag-be-traffic').children.length, 0, context + ': backend traffic rows');
 assert.strictEqual(document.getElementById('vpn-history-fleet-note').textContent, '', context + ': fleet note text');
 assert.strictEqual(document.getElementById('vpn-history-fleet-note').innerHTML, '', context + ': fleet note markup');

 for (const id of SVG_CHARTS) {
  const el = document.getElementById(id);
  assert.strictEqual(el.innerHTML, '', context + ': sparkline markup in ' + id);
  assert.strictEqual(el.textContent, '', context + ': sparkline text in ' + id);
 }
 for (const id of SERIES_CHARTS) {
  const el = document.getElementById(id);
  assert.strictEqual(el.children.length, 0, context + ': series children in ' + id);
  assert.strictEqual(el.textContent, '', context + ': series text in ' + id);
 }
}

assertAllSurfacesCleared('immediately after forwarder_available: false');

// The cleared state must be terminal: toggling the route filter or switching
// history windows without a new poll must NOT resurrect stale available diagnostics.
vpnToggleShowAllRoutes(); // Toggle 1: show all routes
assertAllSurfacesCleared('after route toggle 1');

vpnToggleShowAllRoutes(); // Toggle 2: show problem routes only
assertAllSurfacesCleared('after route toggle 2');

for (const w of ['1h', '6h', '24h', '15m']) {
 vpnSetHistoryWindow(w);
 assertAllSurfacesCleared('after switching history window to ' + w);
}

// Deliver a fresh available response and verify live data returns cleanly.
const freshAvailableStatus = {
 forwarder_available: true,
 forwarder_queue_capacity: 200,
 listener_running: true,
 health_assessment: { status: 'HEALTHY', summary: 'Operational forwarding restored', conditions: [] },
 rates: { available: true, rx_bps: 2000000, tx_bps: 0, rx_pps: 100, tx_pps: 0 },
 all_routes: [{ peer_key: 'peer87654321', capacity: 200, occupancy: 5, drops: 0, has_pressure: false }],
 problem_routes: [],
 historical_series: {
  window_15m: [
   { t: 200, rx_bps: 2000, tx_bps: 2000, traffic_available: true, q_pct: 10, drop_rate: 0, drop_rates_available: true,
     drop_reason_rates: { return_queue_full: 0 }, fwd_p95_ms: 30, fwd_p95_samples: 1, be_p95_ms: 25, be_latency_samples: 1,
     sessions: 2, routes: 1, backends_omitted: 0,
     backends: [{ id: 4, rx_bps: 2000, tx_bps: 2000, traffic_available: true, probe_latency_ms: 25, probe_available: true }] }
  ]
 },
 backends: {
  backends: [
   { server_name: 'Server 2', enabled: true, health_state: 'active', traffic_available: true,
     rx_bytes_per_sec: 2000, tx_bytes_per_sec: 2000, rx_pps: 100, tx_pps: 100 }
  ]
 }
};
vpnRenderForwarderHealth(freshAvailableStatus);
assert(vpnLastStatus && vpnLastStatus.historical_series, 'fresh poll must cache status');
assert.strictEqual(document.getElementById('vpn-fwd-status-text').textContent, 'vpn_forwarder_healthy', 'fresh poll restores Healthy');
assert.strictEqual(document.getElementById('vpn-kpi-throughput').textContent, '2.00 Mbps / 100.0 pps', 'fresh poll restores throughput');
assert.strictEqual(document.getElementById('vpn-diag-be-traffic').children.length, 1, 'fresh poll restores backend rows');
for (const id of SVG_CHARTS) assert(document.getElementById(id).innerHTML.includes('<svg'), 'fresh poll restores SVG in ' + id);
for (const id of SERIES_CHARTS) assert(document.getElementById(id).children.length > 0, 'fresh poll restores series in ' + id);

// Sequence 2: Polling error response (null status) must also invalidate cache
// and not resurrect on local toggles.
vpnRenderForwarderHealth(null);
assertAllSurfacesCleared('after null polling failure');

vpnToggleShowAllRoutes();
assertAllSurfacesCleared('after null route toggle 1');
vpnToggleShowAllRoutes();
assertAllSurfacesCleared('after null route toggle 2');
vpnSetHistoryWindow('1h');
assertAllSurfacesCleared('after null window 1h');
vpnSetHistoryWindow('15m');
assertAllSurfacesCleared('after null window 15m');

// Recovery from null status when live poll succeeds
vpnRenderForwarderHealth(freshAvailableStatus);
assert.strictEqual(document.getElementById('vpn-fwd-status-text').textContent, 'vpn_forwarder_healthy', 'recovery after null poll');
assert.strictEqual(document.getElementById('vpn-kpi-throughput').textContent, '2.00 Mbps / 100.0 pps', 'recovery throughput after null poll');
assert.strictEqual(document.getElementById('vpn-diag-be-traffic').children.length, 1, 'recovery backend rows after null poll');

`
	cmd := exec.Command(nodePath, "-e", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unavailable-forwarder history clearing: %v\n%s", err, out)
	}
}

func TestVPNPanelRateAvailability(t *testing.T) {
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Skipf("node binary not found: %v", err)
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	health, err := extractJSFunction(string(data), "function vpnRenderForwarderHealth")
	if err != nil {
		t.Fatal(err)
	}
	script := expandedDOMMock + "\n" + health + `
let vpnLastStatus = null;
let vpnShowAllRoutes = false;

// 1. Both rate flags false: detail panels must show explicit unavailable text, NOT measured zero.
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: false, rx_bps: 0, tx_bps: 0, rx_pps: 0, tx_pps: 0, rx_bps_avg_5m: 0, tx_bps_avg_5m: 0, rx_bps_avg_1h: 0, tx_bps_avg_1h: 0 },
	drop_categories: { rates_available: false, client_drop_rate_pps: 0, client_total_drops: 12, return_drop_rate_pps: 0, return_total_drops: 34, total_drop_rate_pps: 0, total_drops: 46 }
});

assert.strictEqual(document.getElementById('vpn-kpi-throughput').textContent, 'Traffic unavailable', 'KPI throughput must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Traffic unavailable', 'detail throughput must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Traffic unavailable', 'detail packets must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-ewma5m').textContent, 'Traffic unavailable', 'detail ewma5m must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-ewma1h').textContent, 'Traffic unavailable', 'detail ewma1h must be unavailable');

assert.strictEqual(document.getElementById('vpn-kpi-packet-loss').textContent, 'Loss rate unavailable (46 cumulative)', 'KPI loss must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, 'Loss rate unavailable (12 cumulative)', 'detail client drops must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, 'Loss rate unavailable (34 cumulative)', 'detail return drops must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, 'Loss rate unavailable (46 cumulative)', 'detail total drops must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').style.color, '', 'unavailable client drop rate must not be colored danger');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').style.color, '', 'unavailable return drop rate must not be colored danger');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').style.color, '', 'unavailable total drop rate must not be colored danger');

// 2. Independent flags: Traffic unavailable, Loss available (legitimate idle zero loss).
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: false, rx_bps: 0, tx_bps: 0, rx_pps: 0, tx_pps: 0 },
	drop_categories: { rates_available: true, client_drop_rate_pps: 0, client_total_drops: 5, return_drop_rate_pps: 0, return_total_drops: 2, total_drop_rate_pps: 0, total_drops: 7 }
});
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, '0.00 pps (5 cumulative)', 'available zero client loss must show measured rate');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, '0.00 pps (2 cumulative)', 'available zero return loss must show measured rate');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, '0.00 pps (7 cumulative)', 'available zero total loss must show measured rate');
assert.strictEqual(document.getElementById('vpn-kpi-packet-loss').textContent, '0.00 pps (7 cumulative)');

// 3. Independent flags: Traffic available (legitimate idle zero), Loss unavailable.
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: true, rx_bps: 0, tx_bps: 0, rx_pps: 0, tx_pps: 0, rx_bps_avg_5m: 0, tx_bps_avg_5m: 0, rx_bps_avg_1h: 0, tx_bps_avg_1h: 0 },
	drop_categories: { rates_available: false, client_drop_rate_pps: 0, client_total_drops: 0, return_drop_rate_pps: 0, return_total_drops: 0, total_drop_rate_pps: 0, total_drops: 0 }
});
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Rx: 0 bps | Tx: 0 bps', 'available zero traffic must show measured rate');
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Rx: 0.0 pps | Tx: 0.0 pps', 'available zero packet rate must show measured rate');
assert.strictEqual(document.getElementById('vpn-diag-ewma5m').textContent, 'Rx: 0 bps | Tx: 0 bps');
assert.strictEqual(document.getElementById('vpn-diag-ewma1h').textContent, 'Rx: 0 bps | Tx: 0 bps');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, 'Loss rate unavailable (0 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, 'Loss rate unavailable (0 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, 'Loss rate unavailable (0 cumulative)');

// 4. Positive measured rates retain formatting and danger highlight.
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: true, rx_bps: 1000000, tx_bps: 500000, rx_pps: 100, tx_pps: 50, rx_bps_avg_5m: 800000, tx_bps_avg_5m: 400000, rx_bps_avg_1h: 600000, tx_bps_avg_1h: 300000 },
	drop_categories: { rates_available: true, client_drop_rate_pps: 2.5, client_total_drops: 10, return_drop_rate_pps: 1.0, return_total_drops: 4, total_drop_rate_pps: 3.5, total_drops: 14 }
});
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Rx: 1.00 Mbps | Tx: 500.00 Kbps');
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Rx: 100.0 pps | Tx: 50.0 pps');
assert.strictEqual(document.getElementById('vpn-diag-ewma5m').textContent, 'Rx: 800.00 Kbps | Tx: 400.00 Kbps');
assert.strictEqual(document.getElementById('vpn-diag-ewma1h').textContent, 'Rx: 600.00 Kbps | Tx: 300.00 Kbps');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, '2.50 pps (10 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').style.color, 'var(--danger)');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, '1.00 pps (4 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').style.color, 'var(--danger)');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, '3.50 pps (14 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').style.color, 'var(--danger)');

// 5. False availability dominates placeholder numeric values in payload.
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: false, rx_bps: 999999, tx_bps: 999999, rx_pps: 999, tx_pps: 999, rx_bps_avg_5m: 999999, tx_bps_avg_5m: 999999, rx_bps_avg_1h: 999999, tx_bps_avg_1h: 999999 },
	drop_categories: { rates_available: false, client_drop_rate_pps: 99.9, client_total_drops: 5, return_drop_rate_pps: 99.9, return_total_drops: 5, total_drop_rate_pps: 199.8, total_drops: 10 }
});
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-ewma5m').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-ewma1h').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, 'Loss rate unavailable (5 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, 'Loss rate unavailable (5 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, 'Loss rate unavailable (10 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').style.color, '');

// 6. Legacy payload without flags preserves numeric rendering.
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { rx_bps: 0, tx_bps: 0, rx_pps: 0, tx_pps: 0, rx_bps_avg_5m: 0, tx_bps_avg_5m: 0, rx_bps_avg_1h: 0, tx_bps_avg_1h: 0 },
	drop_categories: { client_drop_rate_pps: 0, client_total_drops: 0, return_drop_rate_pps: 0, return_total_drops: 0, total_drop_rate_pps: 0, total_drops: 0 }
});
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Rx: 0 bps | Tx: 0 bps');
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Rx: 0.0 pps | Tx: 0.0 pps');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, '0.00 pps (0 cumulative)');
`
	cmd := exec.Command(nodePath, "-e", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("panel rate availability: %v\n%s", err, out)
	}
}
