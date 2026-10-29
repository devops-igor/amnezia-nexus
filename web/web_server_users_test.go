package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

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

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	serverActionsData, err := fs.ReadFile(staticFS, "js/server_actions.js")
	if err != nil {
		t.Fatalf("failed to read js/server_actions.js: %v", err)
	}
	serverTelemetryData, err := fs.ReadFile(staticFS, "js/server_telemetry.js")
	if err != nil {
		t.Fatalf("failed to read js/server_telemetry.js: %v", err)
	}
	serverCombinedStr := serverStr + "\n" + string(serverActionsData) + "\n" + string(serverTelemetryData)

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
		if !strings.Contains(serverCombinedStr, token) {
			t.Errorf("server page missing required modernized token %q", token)
		}
	}

	// Ensure raw confirm(), apiCall(), showToast() are not used in server page
	if strings.Contains(serverCombinedStr, "if (!confirm(") || strings.Contains(serverCombinedStr, "if(!confirm(") {
		t.Errorf("server page should not use raw confirm(), must use UI.confirm")
	}
	if strings.Contains(serverCombinedStr, "apiCall(") {
		t.Errorf("server page should not use apiCall(), must use API client")
	}
	if strings.Contains(serverCombinedStr, "showToast(") {
		t.Errorf("server page should not use showToast(), must use UI.toast")
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

	usersJsData, err := fs.ReadFile(staticFS, "js/users.js")
	if err != nil {
		t.Fatalf("failed to read js/users.js: %v", err)
	}
	usersJsStr := string(usersJsData)

	// 1. Assert users.js references #icon-pause and #icon-play for user toggle controls
	if !strings.Contains(usersJsStr, `href="#icon-pause"`) {
		t.Errorf("users.js missing href=\"#icon-pause\" for active user toggle control")
	}
	if !strings.Contains(usersJsStr, `href="#icon-play"`) {
		t.Errorf("users.js missing href=\"#icon-play\" for disabled user toggle control")
	}

	// 2. Assert users.html and users.js do not contain the old dot toggle markup for user toggling
	assertNoBadgeDot := func(name, content string) error {
		if strings.Contains(content, "badge-dot") {
			return fmt.Errorf("%s must not contain legacy dot toggle markup (badge-dot)", name)
		}
		return nil
	}
	for name, content := range map[string]string{
		"users.html": usersStr,
		"users.js":   usersJsStr,
	} {
		if err := assertNoBadgeDot(name, content); err != nil {
			t.Error(err)
		}
	}

	// Negative mutation test: verify that injecting badge-dot into usersJsStr fails closed
	t.Run("BadgeDotProhibitionMutationFailsClosed", func(t *testing.T) {
		mutatedJs := strings.Replace(usersJsStr, `class="badge ${roleClass}"`, `class="badge badge-dot ${roleClass}"`, 1)
		if !strings.Contains(mutatedJs, "badge-dot") {
			t.Fatal("failed to apply badge-dot mutation to users.js")
		}
		if err := assertNoBadgeDot("users.js", mutatedJs); err == nil {
			t.Errorf("negative mutation test failed: injecting badge-dot into users.js did not fail closed")
		}
	})

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
	if !strings.Contains(usersJsStr, `btn-danger-hover`) {
		t.Errorf("users.js missing btn-danger-hover class on delete action buttons")
	}
	if !strings.Contains(usersJsStr, `btn-success-hover`) {
		t.Errorf("users.js missing btn-success-hover class on play toggle button")
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

	// 7. Assert vpn.css contains #usersContainer, #usersGrid, and #userConnsTable width rules
	cssData, err := fs.ReadFile(staticFS, "css/vpn.css")
	if err != nil {
		t.Fatalf("failed to read css/vpn.css: %v", err)
	}
	cssStr := string(cssData)
	if !strings.Contains(cssStr, "#usersContainer {\n    width: 100%;\n    min-width: 100%;\n}") {
		t.Errorf("vpn.css missing #usersContainer width rules")
	}
	if !strings.Contains(cssStr, "#usersGrid {\n    width: 100%;\n    min-width: 100%;\n}") {
		t.Errorf("vpn.css missing #usersGrid width rules")
	}
	if !strings.Contains(cssStr, "#userConnsTable {\n    width: 100%;\n    min-width: 100%;\n}") {
		t.Errorf("vpn.css missing #userConnsTable width rules")
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

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	serverActionsData, err := fs.ReadFile(staticFS, "js/server_actions.js")
	if err != nil {
		t.Fatalf("failed to read js/server_actions.js: %v", err)
	}
	serverTelemetryData, err := fs.ReadFile(staticFS, "js/server_telemetry.js")
	if err != nil {
		t.Fatalf("failed to read js/server_telemetry.js: %v", err)
	}
	serverCombinedStr := serverStr + "\n" + string(serverActionsData) + "\n" + string(serverTelemetryData)

	// 1. Verify that server.html contains NO Cyrillic characters (regex [\x{0400}-\x{04FF}])
	cyrillicRe := regexp.MustCompile(`[\x{0400}-\x{04FF}]`)
	if matches := cyrillicRe.FindAllString(serverStr, -1); len(matches) > 0 {
		t.Errorf("server.html contains hardcoded Cyrillic characters (%d occurrences): %v", len(matches), matches)
	}
	if matches := cyrillicRe.FindAllString(string(serverActionsData), -1); len(matches) > 0 {
		t.Errorf("server_actions.js contains hardcoded Cyrillic characters (%d occurrences): %v", len(matches), matches)
	}
	if matches := cyrillicRe.FindAllString(string(serverTelemetryData), -1); len(matches) > 0 {
		t.Errorf("server_telemetry.js contains hardcoded Cyrillic characters (%d occurrences): %v", len(matches), matches)
	}

	// 2. Verify server page references required translation tokens
	requiredTokens := []string{
		"${_('start_install')}",
		"_('port_telemt_hint')",
		"${_('config')}",
	}
	for _, token := range requiredTokens {
		if !strings.Contains(serverCombinedStr, token) {
			t.Errorf("server page missing required token %q", token)
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
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	usersJsData, err := fs.ReadFile(staticFS, "js/users.js")
	if err != nil {
		t.Fatalf("failed to read js/users.js: %v", err)
	}
	usersJsStr := string(usersJsData)

	// Check Server 0 display name mapping
	if !strings.Contains(usersJsStr, `(Number(c.server_id) === 0) ? 'Cluster (Auto)'`) {
		t.Errorf("users.js must render 'Cluster (Auto)' when server_id is 0")
	}

	// Check that action buttons pass connection ID
	if !strings.Contains(usersJsStr, `onclick="copyUserConnectionDirect('${UI.escapeJs(c.id)}', ${Number(c.server_id)}`) {
		t.Errorf("users.js copyUserConnectionDirect must pass connection ID")
	}
	if !strings.Contains(usersJsStr, `onclick="showUserConnectionConfig('${UI.escapeJs(c.id)}', ${Number(c.server_id)}`) {
		t.Errorf("users.js showUserConnectionConfig must pass connection ID")
	}
	if !strings.Contains(usersJsStr, `onclick="unlinkUserConnection('${UI.escapeJs(c.id)}', ${Number(c.server_id)}`) {
		t.Errorf("users.js unlinkUserConnection must pass connection ID")
	}

	// Check fallback/direct connection endpoint calls
	if !strings.Contains(usersJsStr, `/api/connections/${connId}/delete`) {
		t.Errorf("users.js unlinkUserConnection must support /api/connections/${connId}/delete")
	}
	if !strings.Contains(usersJsStr, `/api/connections/${connId}/config`) {
		t.Errorf("users.js showUserConnectionConfig/copyUserConnectionDirect must support /api/connections/${connId}/config")
	}
}

func TestUsersTemplatePageSize(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("failed to get static sub FS: %v", err)
	}

	usersJsData, err := fs.ReadFile(staticFS, "js/users.js")
	if err != nil {
		t.Fatalf("failed to read js/users.js: %v", err)
	}
	usersJsStr := string(usersJsData)

	if !strings.Contains(usersJsStr, "let pageSize = 12;") {
		t.Errorf("users.js must configure 'let pageSize = 12;' for 3-column responsive grid layout")
	}
	if strings.Contains(usersJsStr, "let pageSize = 10;") {
		t.Errorf("users.js must not contain obsolete 'let pageSize = 10;'")
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

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	serverTelemetryData, err := fs.ReadFile(staticFS, "js/server_telemetry.js")
	if err != nil {
		t.Fatalf("failed to read js/server_telemetry.js: %v", err)
	}
	serverTelemetryStr := string(serverTelemetryData)

	// 0. Verify server.html includes server_telemetry.js script tag and minimal bootstrap
	const expectedTelemetryScript = `<script src="/static/js/server_telemetry.js`
	if !strings.Contains(serverStr, expectedTelemetryScript) {
		t.Errorf("server.html missing script tag %q", expectedTelemetryScript)
	}
	if !strings.Contains(serverStr, "initServerTelemetry()") {
		t.Errorf("server.html must bootstrap telemetry with initServerTelemetry()")
	}

	// 1. Verify STATS_REFRESH_INTERVAL_MS definition
	const expectedInterval = "const STATS_REFRESH_INTERVAL_MS = 30000;"
	if !strings.Contains(serverTelemetryStr, expectedInterval) {
		t.Errorf("server_telemetry.js must define %q", expectedInterval)
	}

	// 2. Verify registration of Telemetry.poll for server-stats and server-reachability
	expectedStatsPoll := "Telemetry.poll('server-stats-' + SERVER_ID, loadServerStats, STATS_REFRESH_INTERVAL_MS);"
	if !strings.Contains(serverTelemetryStr, expectedStatsPoll) {
		t.Errorf("server_telemetry.js missing Telemetry.poll for server-stats: expected %q", expectedStatsPoll)
	}

	expectedReachPoll := "Telemetry.poll('server-reachability-' + SERVER_ID, updateReachability, STATS_REFRESH_INTERVAL_MS);"
	if !strings.Contains(serverTelemetryStr, expectedReachPoll) {
		t.Errorf("server_telemetry.js missing Telemetry.poll for server-reachability: expected %q", expectedReachPoll)
	}

	// 3. Verify no bare setInterval(updateReachability) remains
	if strings.Contains(serverTelemetryStr, "setInterval(updateReachability") {
		t.Errorf("server_telemetry.js must not contain bare unmanaged 'setInterval(updateReachability'")
	}

	// 4. Verify error preservation behavior in loadServerStats
	if !strings.Contains(serverTelemetryStr, "if (!stats || typeof stats !== 'object'") {
		t.Errorf("server_telemetry.js loadServerStats must validate stats payload before DOM updates")
	}
	expectedZeroCheck := "stats.ram_total === 0 && stats.disk_total === 0"
	if !strings.Contains(serverTelemetryStr, expectedZeroCheck) {
		t.Errorf("server_telemetry.js loadServerStats must check for zero totals: expected %q", expectedZeroCheck)
	}

	if !strings.Contains(serverTelemetryStr, "return stats;") {
		t.Errorf("server_telemetry.js loadServerStats must return stats payload")
	}

	if !strings.Contains(serverTelemetryStr, "throw err;") {
		t.Errorf("server_telemetry.js loadServerStats must re-throw errors for Telemetry.poll failure tracking")
	}

	loadStatsBlock, err := extractJSFunction(serverTelemetryStr, "async function loadServerStats")
	if err != nil {
		t.Fatalf("server_telemetry.js missing loadServerStats function: %v", err)
	}
	if strings.Contains(loadStatsBlock, "innerHTML = ''") || strings.Contains(loadStatsBlock, "innerHTML = \"\"") {
		t.Errorf("loadServerStats must not blank DOM innerHTML on error")
	}
	if !strings.Contains(loadStatsBlock, "catch (err)") || !strings.Contains(loadStatsBlock, "throw err;") {
		t.Errorf("loadServerStats must include catch (err) and re-throw error")
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

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	serverActionsData, err := fs.ReadFile(staticFS, "js/server_actions.js")
	if err != nil {
		t.Fatalf("failed to read js/server_actions.js: %v", err)
	}
	serverCombinedStr := serverStr + "\n" + string(serverActionsData)

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
		if !strings.Contains(serverCombinedStr, elem) {
			t.Errorf("server.html or server_actions.js missing required edit host element %q", elem)
		}
	}

	// Ensure no hardcoded Cyrillic was added to server.html or server_actions.js
	cyrillicRe := regexp.MustCompile(`[\x{0400}-\x{04FF}]`)
	if matches := cyrillicRe.FindAllString(serverCombinedStr, -1); len(matches) > 0 {
		t.Errorf("server.html or server_actions.js contains hardcoded Cyrillic characters: %v", matches)
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

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	serverActionsData, err := fs.ReadFile(staticFS, "js/server_actions.js")
	if err != nil {
		t.Fatalf("failed to read js/server_actions.js: %v", err)
	}
	serverCombinedStr := serverStr + "\n" + string(serverActionsData)

	indexData, err := fs.ReadFile(templatesFS, "index.html")
	if err != nil {
		t.Fatalf("failed to read index.html: %v", err)
	}
	indexStr := string(indexData)

	for _, tmpl := range []struct {
		name    string
		content string
	}{
		{"server.html", serverCombinedStr},
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

func TestIssue542UsersPageFiveSupportedLocalesMatrix(t *testing.T) {
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	// 1. Verify all 5 supported languages exist and contain core users management keys
	supportedLanguages := []string{"en.json", "ru.json", "fr.json", "zh.json", "fa.json"}
	coreUsersKeys := []string{
		"users_title",
		"nav_users",
		"add_user",
		"add_connection",
		"delete_user_title",
		"delete_user_confirm",
		"config",
	}

	for _, langFile := range supportedLanguages {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", langFile, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
		}
		for _, k := range coreUsersKeys {
			val, ok := dict[k]
			if !ok || strings.TrimSpace(val) == "" {
				t.Errorf("%s missing or empty required users key %q", langFile, k)
			}
		}
	}

	// 2. French (fr.json) specific key verification
	frData, err := fs.ReadFile(transFS, "fr.json")
	if err != nil {
		t.Fatalf("failed to read fr.json: %v", err)
	}
	var frDict map[string]string
	if err := json.Unmarshal(frData, &frDict); err != nil {
		t.Fatalf("failed to parse fr.json: %v", err)
	}
	expectedFr := map[string]string{
		"users_title":         "Utilisateurs",
		"nav_users":           "Utilisateurs",
		"add_connection":      "Ajouter une connexion",
		"delete_user_title":   "Supprimer l'utilisateur",
		"delete_user_confirm": "Supprimer l'utilisateur ? Ses connexions seront supprimées.",
	}
	for k, want := range expectedFr {
		if got := frDict[k]; got != want {
			t.Errorf("fr.json[%q] = %q, want %q", k, got, want)
		}
	}

	// 3. Fallback verification: unsupported locale (e.g. es.json) is not bundled
	if _, err := fs.ReadFile(transFS, "es.json"); err == nil {
		t.Errorf("es.json should not exist in bundled translations; es must rely on en fallback")
	}
}
