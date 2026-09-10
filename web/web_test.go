package web

import (
	"encoding/json"
	"io/fs"
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
		"id=\"icon-key\"",
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
