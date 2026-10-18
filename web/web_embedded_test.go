package web

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
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
		"css/tokens.css",
		"css/base.css",
		"css/layout.css",
		"css/components.css",
		"css/tables.css",
		"css/server.css",
		"css/vpn.css",
		"js/qrcode.min.js",
		"js/api.js",
		"js/captcha.js",
		"js/ui.js",
		"js/tables.js",
		"js/telemetry.js",
		"favicon.svg",
		"js/vpn/backends.js",
		"js/vpn/health_problems.js",
		"js/vpn/health_summary.js",
		"js/vpn/charts.js",
		"js/vpn/sessions.js",
		"js/vpn/page.js",
		"js/users.js",
		"js/server_actions.js",
		"js/server_telemetry.js",
	}
	for _, file := range staticFiles {
		subData, err := fs.ReadFile(staticFS, file)
		if err != nil {
			t.Errorf("static/%s missing from GetStaticSubFS: %v", file, err)
			continue
		}
		if len(bytes.TrimSpace(subData)) == 0 {
			t.Errorf("static/%s in GetStaticSubFS is empty or whitespace", file)
		}
		embedData, err := fs.ReadFile(StaticFS, "static/"+file)
		if err != nil {
			t.Errorf("static/%s missing from StaticFS: %v", file, err)
			continue
		}
		if len(bytes.TrimSpace(embedData)) == 0 {
			t.Errorf("static/%s in StaticFS is empty or whitespace", file)
		}
		if !bytes.Equal(subData, embedData) {
			t.Errorf("static/%s content mismatch between GetStaticSubFS and StaticFS", file)
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

	tokensData, err := fs.ReadFile(staticFS, "css/tokens.css")
	if err != nil {
		t.Fatalf("failed to read css/tokens.css: %v", err)
	}
	tokensCSS := string(tokensData)

	layoutData, err := fs.ReadFile(staticFS, "css/layout.css")
	if err != nil {
		t.Fatalf("failed to read css/layout.css: %v", err)
	}
	baseCSSData, err := fs.ReadFile(staticFS, "css/base.css")
	if err != nil {
		t.Fatalf("failed to read css/base.css: %v", err)
	}
	layoutAndBaseCSS := string(layoutData) + "\n" + string(baseCSSData)

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
		if !strings.Contains(tokensCSS, token) {
			t.Errorf("tokens.css missing required design token %q", token)
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
		if !strings.Contains(layoutAndBaseCSS, cls) {
			t.Errorf("layout.css / base.css missing required layout class %q", cls)
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

	// 3. Assert all template and JS translation keys in users.html and users.js exist across all 5 languages
	usersData, err := fs.ReadFile(templatesFS, "users.html")
	if err != nil {
		t.Fatalf("failed to read users.html: %v", err)
	}
	usersStr := string(usersData)

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	usersJsData, err := fs.ReadFile(staticFS, "js/users.js")
	if err != nil {
		t.Fatalf("failed to read js/users.js: %v", err)
	}
	usersJsStr := string(usersJsData)

	tmplRe := regexp.MustCompile(`\{\{\s*_\s*"([^"]+)"\s*\}\}`)
	jsRe := regexp.MustCompile(`_\(\s*['"]([^'"]+)['"]\s*\)`)

	usersKeys := make(map[string]struct{})
	for _, m := range tmplRe.FindAllStringSubmatch(usersStr, -1) {
		usersKeys[m[1]] = struct{}{}
	}
	for _, m := range jsRe.FindAllStringSubmatch(usersStr, -1) {
		usersKeys[m[1]] = struct{}{}
	}
	for _, m := range jsRe.FindAllStringSubmatch(usersJsStr, -1) {
		usersKeys[m[1]] = struct{}{}
	}

	for k := range usersKeys {
		for _, langFile := range languages {
			if val, ok := dicts[langFile][k]; !ok || strings.TrimSpace(val) == "" {
				t.Errorf("%s missing or empty translation for users key %q", langFile, k)
			}
		}
	}
}

func TestIssue351MobileLogoutOcclusionAndStackingContext(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	layoutBytes, err := fs.ReadFile(staticFS, "css/layout.css")
	if err != nil {
		t.Fatalf("failed to read css/layout.css: %v", err)
	}
	baseCSSBytes, err := fs.ReadFile(staticFS, "css/base.css")
	if err != nil {
		t.Fatalf("failed to read css/base.css: %v", err)
	}
	css := string(layoutBytes) + "\n" + string(baseCSSBytes)

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

func TestServerStaticAssetsProductionServing(t *testing.T) {
	staticSubFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	serverAssets := []string{
		"js/server_actions.js",
		"js/server_telemetry.js",
	}

	for _, relPath := range serverAssets {
		t.Run(relPath, func(t *testing.T) {
			expectedBytes, err := fs.ReadFile(staticSubFS, relPath)
			if err != nil {
				t.Fatalf("failed to read embedded %s from GetStaticSubFS: %v", relPath, err)
			}
			if len(bytes.TrimSpace(expectedBytes)) == 0 {
				t.Fatalf("embedded %s is empty or whitespace", relPath)
			}

			directEmbedBytes, err := fs.ReadFile(StaticFS, "static/"+relPath)
			if err != nil {
				t.Fatalf("failed to read direct embedded %s from StaticFS: %v", relPath, err)
			}
			if !bytes.Equal(expectedBytes, directEmbedBytes) {
				t.Fatalf("content mismatch between StaticFS and GetStaticSubFS for %s", relPath)
			}
		})
	}

	t.Run("NonExistentServerAssetFailsRead", func(t *testing.T) {
		_, err := fs.ReadFile(staticSubFS, "js/nonexistent_server_script.js")
		if err == nil {
			t.Fatalf("expected error reading non-existent server asset from staticSubFS, got nil")
		}
	})
}

var canonicalStylesheetOrder = []string{
	"tokens",
	"base",
	"layout",
	"components",
	"tables",
	"server",
	"vpn",
}

var cssLinkRegex = regexp.MustCompile(`href="/static/css/(\w+)\.css`)

func TestStyleCSSConcatenationParity(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	var concatenated strings.Builder
	for _, name := range canonicalStylesheetOrder {
		mod := "css/" + name + ".css"
		data, err := fs.ReadFile(staticFS, mod)
		if err != nil {
			t.Fatalf("failed to read %s: %v", mod, err)
		}
		concatenated.Write(data)
	}

	styleData, err := fs.ReadFile(staticFS, "css/style.css")
	if err != nil {
		t.Fatalf("failed to read css/style.css: %v", err)
	}

	if concatenated.String() != string(styleData) {
		t.Fatal("style.css does not match concatenation of the 7 modular stylesheets")
	}
}

func TestStylesheetTemplateLoadOrder(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	templatesToCheck := []string{"base.html", "login.html", "setup.html", "change_password.html"}
	for _, tmpl := range templatesToCheck {
		t.Run(tmpl, func(t *testing.T) {
			data, err := fs.ReadFile(templatesFS, tmpl)
			if err != nil {
				t.Fatalf("failed to read %s: %v", tmpl, err)
			}

			matches := cssLinkRegex.FindAllStringSubmatch(string(data), -1)
			extractedOrder := make([]string, 0, len(matches))
			for _, m := range matches {
				if len(m) > 1 {
					extractedOrder = append(extractedOrder, m[1])
				}
			}

			if !slices.Equal(canonicalStylesheetOrder, extractedOrder) {
				t.Fatalf("%s stylesheet link order mismatch:\n got:  %v\n want: %v", tmpl, extractedOrder, canonicalStylesheetOrder)
			}
		})
	}
}
