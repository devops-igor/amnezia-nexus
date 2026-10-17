package web

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

func TestPhase5VPNAndUsersModernization(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	vpnStr := fixture.TemplateHTML
	backendsStr := fixture.BackendsJS
	pageStr := fixture.PageJS

	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	// 1. Assert vpn.html, backends.js, and page.js modernizations
	requiredVPNTokens := []string{
		"href=\"#icon-shield\"",
		"href=\"#icon-network\"",
		"href=\"#icon-server\"",
		"href=\"#icon-plus\"",
		"href=\"#icon-pencil\"",
		"href=\"#icon-activity\"",
		"href=\"#icon-x\"",
		"vpnBackendsTable",
		"vpnTableContainer",
		"data-sort-type",
		"vpn-listener-badge",
		"vpn-public-endpoint",
		"/static/js/vpn/page.js",
	}
	for _, token := range requiredVPNTokens {
		if !strings.Contains(vpnStr, token) {
			t.Errorf("vpn.html missing required modernized token %q", token)
		}
	}

	requiredPageTokens := []string{
		"API.get",
		"NexusTable",
		"NexusTelemetry.poll",
		"Telemetry.formatBytes",
	}
	for _, token := range requiredPageTokens {
		if !strings.Contains(pageStr, token) {
			t.Errorf("page.js missing required modernized token %q", token)
		}
	}

	requiredBackendTokens := []string{
		"href=\"#icon-trash\"",
		"UI.confirm",
		"UI.toast",
		"API.post",
		"API.request",
		"vpn_delete",
		"vpn_confirm_delete",
	}
	for _, token := range requiredBackendTokens {
		if !strings.Contains(backendsStr, token) {
			t.Errorf("backends.js missing required modernized token %q", token)
		}
	}

	// Ensure raw confirm(), apiCall(), showToast() are eliminated from vpn.html, backends.js, and page.js
	for name, src := range map[string]string{"vpn.html": vpnStr, "backends.js": backendsStr, "page.js": pageStr} {
		if strings.Contains(src, "if (!confirm(") || strings.Contains(src, "if(!confirm(") {
			t.Errorf("%s should not use raw confirm(), must use UI.confirm", name)
		}
		if strings.Contains(src, "apiCall(") {
			t.Errorf("%s should not use apiCall(), must use API client", name)
		}
		if strings.Contains(src, "showToast(") {
			t.Errorf("%s should not use showToast(), must use UI.toast", name)
		}
	}

	// 2. Assert users.html and users.js modernizations
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
		"userConnsTable",
		"/static/js/users.js",
	}
	for _, token := range requiredUsersTokens {
		if !strings.Contains(usersStr, token) {
			t.Errorf("users.html missing required modernized token %q", token)
		}
	}

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	usersJsData, err := fs.ReadFile(staticFS, "js/users.js")
	if err != nil {
		t.Fatalf("failed to read js/users.js: %v", err)
	}
	usersJsStr := string(usersJsData)

	requiredUsersJsTokens := []string{
		"href=\"#icon-trash\"",
		"UI.confirm",
		"UI.copy",
		"UI.toast",
		"API.get",
		"API.post",
		"NexusTable",
		"Telemetry.formatBytes",
	}
	for _, token := range requiredUsersJsTokens {
		if !strings.Contains(usersJsStr, token) {
			t.Errorf("users.js missing required modernized token %q", token)
		}
	}

	// Ensure raw confirm(), apiCall(), showToast() are eliminated from users.html and users.js
	for name, src := range map[string]string{"users.html": usersStr, "users.js": usersJsStr} {
		if strings.Contains(src, "if (!confirm(") || strings.Contains(src, "if(!confirm(") {
			t.Errorf("%s should not use raw confirm(), must use UI.confirm", name)
		}
		if strings.Contains(src, "apiCall(") {
			t.Errorf("%s should not use apiCall(), must use API client", name)
		}
		if strings.Contains(src, "showToast(") {
			t.Errorf("%s should not use showToast(), must use UI.toast", name)
		}
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
	fixture := NewVPNTestFixture(t)
	vpnStr := fixture.TemplateHTML
	backendsStr := fixture.BackendsJS
	pageStr := fixture.PageJS

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
	if strings.Contains(vpnStr, "width:8px") || strings.Contains(vpnStr, "height:8px") ||
		strings.Contains(backendsStr, "width:8px") || strings.Contains(backendsStr, "height:8px") {
		t.Errorf("vpn dashboard should not contain broken 8px dot toggle button")
	}
	if !strings.Contains(backendsStr, `href="#icon-pause"`) {
		t.Errorf("backends.js missing href=\"#icon-pause\" for active backend toggle")
	}
	if !strings.Contains(backendsStr, `href="#icon-play"`) {
		t.Errorf("backends.js missing href=\"#icon-play\" for disabled backend toggle")
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
		if !strings.Contains(backendsStr, token) {
			t.Errorf("backends.js missing required latency token %q", token)
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
		if !strings.Contains(pageStr, opt) {
			t.Errorf("page.js missing NexusTable option %q", opt)
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

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	usersJsData, err := fs.ReadFile(staticFS, "js/users.js")
	if err != nil {
		t.Fatalf("failed to read js/users.js: %v", err)
	}
	usersJsStr := string(usersJsData)

	if !strings.Contains(usersJsStr, `showUserConnectionConfig`) {
		t.Errorf("users.js missing showUserConnectionConfig")
	}

	// 3. server page: No #icon-key, connections config button uses #icon-file-text
	serverData, err := fs.ReadFile(templatesFS, "server.html")
	if err != nil {
		t.Fatalf("failed to read server.html: %v", err)
	}
	serverStr := string(serverData)

	telemetryData, err := fs.ReadFile(staticFS, "js/server_telemetry.js")
	if err != nil {
		t.Fatalf("failed to read js/server_telemetry.js: %v", err)
	}
	serverCombinedStr := serverStr + "\n" + string(telemetryData)

	if strings.Contains(serverCombinedStr, `href="#icon-key"`) {
		t.Errorf("server page must not contain href=\"#icon-key\"")
	}
	if !strings.Contains(serverCombinedStr, `href="#icon-file-text"`) {
		t.Errorf("server page must contain href=\"#icon-file-text\" for client config button")
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

	// Assert page.js JS fallback uses simplified strings
	pageData, err := fs.ReadFile(staticFS, "js/vpn/page.js")
	if err != nil {
		t.Fatalf("failed to read js/vpn/page.js: %v", err)
	}
	pageStr := string(pageData)
	if !strings.Contains(pageStr, `'Auto: %s'`) {
		t.Errorf("page.js missing 'Auto: %%s' fallback")
	}
	if !strings.Contains(pageStr, `'Auto-detect'`) {
		t.Errorf("page.js missing 'Auto-detect' fallback")
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
