package web

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

var canonicalVPNScripts = []string{
	"/static/js/vpn/backends.js",
	"/static/js/vpn/health_problems.js",
	"/static/js/vpn/health_summary.js",
	"/static/js/vpn/charts.js",
	"/static/js/vpn/sessions.js",
	"/static/js/vpn/page.js",
}

var coreScripts = []string{
	"/static/js/qrcode.min.js",
	"/static/js/api.js",
	"/static/js/ui.js",
	"/static/js/tables.js",
	"/static/js/telemetry.js",
}

func getVPNFuncMap() template.FuncMap {
	return template.FuncMap{
		"_": func(key string, args ...any) string {
			return key
		},
		"has_role": func(u any, roles ...string) bool {
			return true
		},
		"upper": func(s any) string {
			return strings.ToUpper(fmt.Sprint(s))
		},
		"safe_js": func(s any) template.JS {
			return template.JS(fmt.Sprint(s))
		},
	}
}

func renderBaseAndVPNTemplate(t *testing.T) string {
	t.Helper()

	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	tmpl, err := template.New("base.html").Funcs(getVPNFuncMap()).ParseFS(templatesFS, "base.html", "vpn.html")
	if err != nil {
		t.Fatalf("failed to parse base.html and vpn.html: %v", err)
	}

	data := map[string]any{
		"title":             "VPN Test",
		"lang":              "en",
		"active_page":       "vpn",
		"csrf_token":        "csrf-test-token",
		"translations_json": "{}",
		"current_user":      map[string]any{"Username": "admin", "Role": "admin"},
		"site_settings": map[string]any{
			"Title":    "Amnezia",
			"Subtitle": "Nexus",
		},
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("failed to execute template: %v", err)
	}

	return buf.String()
}

func renderVPNScriptsBlock(t *testing.T) string {
	t.Helper()

	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	tmpl, err := template.New("vpn.html").Funcs(getVPNFuncMap()).ParseFS(templatesFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to parse vpn.html: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "scripts", nil); err != nil {
		t.Fatalf("failed to execute scripts block in vpn.html: %v", err)
	}
	return buf.String()
}

func findElementByTagAndClass(n *html.Node, tag, class string) *html.Node {
	if n.Type == html.ElementNode && n.Data == tag {
		for _, a := range n.Attr {
			if a.Key == "class" {
				for _, c := range strings.Fields(a.Val) {
					if c == class {
						return n
					}
				}
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findElementByTagAndClass(c, tag, class); found != nil {
			return found
		}
	}
	return nil
}

func collectScriptNodes(n *html.Node) []*html.Node {
	var scripts []*html.Node
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "script" {
			scripts = append(scripts, node)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return scripts
}

func getAttr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}

func hasAttr(n *html.Node, key string) bool {
	_, ok := getAttr(n, key)
	return ok
}

func getNodeText(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return sb.String()
}

func nodeText(n *html.Node) string {
	return getNodeText(n)
}

func validateClassicExecutionAttributes(s *html.Node) error {
	if hasAttr(s, "async") {
		return errors.New("script must not have async attribute")
	}
	if hasAttr(s, "defer") {
		return errors.New("script must not have defer attribute")
	}
	if hasAttr(s, "nomodule") {
		return errors.New("script must not have nomodule attribute")
	}
	rawType, hasType := getAttr(s, "type")
	if hasType {
		normType := strings.ToLower(strings.TrimSpace(rawType))
		if normType != "" && normType != "text/javascript" && normType != "application/javascript" {
			return fmt.Errorf("script has non-classic type %q", rawType)
		}
	}
	return nil
}

// validateScriptElement verifies that a script node has the expected src,
// executes strictly as a classic blocking script (no async, defer, or nomodule),
// has an allowed classic JavaScript MIME type (or omitted), and has an empty body.
func validateScriptElement(s *html.Node, expectedSrc string) error {
	if err := validateClassicExecutionAttributes(s); err != nil {
		return err
	}
	if !hasAttr(s, "src") {
		return fmt.Errorf("script missing src attribute, expected %q", expectedSrc)
	}
	src, _ := getAttr(s, "src")
	if src != expectedSrc {
		return fmt.Errorf("expected src %q, got %q", expectedSrc, src)
	}
	body := strings.TrimSpace(nodeText(s))
	if len(body) != 0 {
		return fmt.Errorf("script %q must have empty body, got: %q", src, body)
	}
	return nil
}

// validateVPNScriptsBlock enforces that the scripts block has strictly the 6 canonical
// classic blocking scripts with empty bodies and zero extra scripts.
func validateVPNScriptsBlock(scriptsHTML string) error {
	doc, err := html.Parse(strings.NewReader(scriptsHTML))
	if err != nil {
		return fmt.Errorf("failed to parse scripts block: %w", err)
	}
	scripts := collectScriptNodes(doc)
	if len(scripts) != len(canonicalVPNScripts) {
		return fmt.Errorf("expected strictly %d <script> elements in scripts block, got %d",
			len(canonicalVPNScripts), len(scripts))
	}
	for i, s := range scripts {
		if err := validateScriptElement(s, canonicalVPNScripts[i]); err != nil {
			return fmt.Errorf("script index %d in scripts block: %w", i, err)
		}
	}
	return nil
}

// validateRenderedVPNPage verifies script placement, canonical ordering, classic execution mode,
// zero content-area scripts, strict pre-bootstrap core sequence, zero unexpected inline scripts,
// and strict precedence of base bootstrap over VPN scripts.
func validateRenderedVPNPage(renderedHTML string) error {
	doc, err := html.Parse(strings.NewReader(renderedHTML))
	if err != nil {
		return fmt.Errorf("failed to parse rendered HTML: %w", err)
	}

	// 1. Assert content area (main.app-main) contains ZERO <script> elements
	mainContent := findElementByTagAndClass(doc, "main", "app-main")
	if mainContent == nil {
		return errors.New("could not find <main class=\"app-main\"> in rendered document")
	}

	contentScripts := collectScriptNodes(mainContent)
	if len(contentScripts) > 0 {
		return fmt.Errorf("expected 0 <script> elements inside content area (main.app-main), found %d", len(contentScripts))
	}

	// 2. Assert script elements across document
	allScripts := collectScriptNodes(doc)
	if len(allScripts) == 0 {
		return errors.New("no <script> elements found in rendered page")
	}

	// 3. Find index of base inline bootstrap script (contains window.I18N or window.translations)
	bootstrapIdx := -1
	for i, s := range allScripts {
		body := getNodeText(s)
		if strings.Contains(body, "window.I18N") || strings.Contains(body, "window.translations") {
			bootstrapIdx = i
			break
		}
	}
	if bootstrapIdx == -1 {
		return errors.New("base inline bootstrap / I18N script not found in rendered page")
	}

	// 4. Verify exact sequence of scripts before base bootstrap:
	// Exactly 1 theme inline script, followed by the core scripts in exact sequence.
	expectedPreBootstrapCount := 1 + len(coreScripts)
	if bootstrapIdx != expectedPreBootstrapCount {
		return fmt.Errorf("expected strictly %d scripts before base bootstrap, found %d",
			expectedPreBootstrapCount, bootstrapIdx)
	}

	// Check index 0: inline theme script
	themeScript := allScripts[0]
	if hasAttr(themeScript, "src") {
		return errors.New("inline theme script must not have src attribute")
	}
	if err := validateClassicExecutionAttributes(themeScript); err != nil {
		return fmt.Errorf("inline theme script execution attribute validation failed: %w", err)
	}
	themeBody := strings.TrimSpace(nodeText(themeScript))
	if len(themeBody) == 0 {
		return errors.New("inline theme script must have non-empty body")
	}
	if !strings.Contains(themeBody, "data-theme") && !strings.Contains(themeBody, "theme") {
		return errors.New("expected inline theme script at index 0")
	}

	// Check indices 1..len(coreScripts): strictly core prerequisite scripts in exact order
	for j, core := range coreScripts {
		s := allScripts[1+j]
		if err := validateScriptElement(s, core); err != nil {
			return fmt.Errorf("core prerequisite script index %d before bootstrap: %w", j, err)
		}
	}

	// 5. Verify the base bootstrap script itself at bootstrapIdx
	bootstrapScript := allScripts[bootstrapIdx]
	if hasAttr(bootstrapScript, "src") {
		return errors.New("base bootstrap script must not have src attribute")
	}
	if err := validateClassicExecutionAttributes(bootstrapScript); err != nil {
		return fmt.Errorf("base bootstrap script execution attribute validation failed: %w", err)
	}
	bootstrapBody := nodeText(bootstrapScript)
	if !strings.Contains(bootstrapBody, "window.I18N") && !strings.Contains(bootstrapBody, "window.translations") {
		return errors.New("base bootstrap script must contain translation initialization")
	}

	// 6. Ensure NO VPN companion scripts exist at or before bootstrapIdx
	for i := 0; i <= bootstrapIdx; i++ {
		src, _ := getAttr(allScripts[i], "src")
		for _, vpnScript := range canonicalVPNScripts {
			if src == vpnScript {
				return fmt.Errorf("VPN script %q placed at or before base bootstrap (index %d vs %d)",
					src, i, bootstrapIdx)
			}
		}
	}

	// 7. Scripts after base bootstrap must be strictly the 6 canonical VPN scripts, with zero extra
	scriptsAfterBootstrap := allScripts[bootstrapIdx+1:]
	if len(scriptsAfterBootstrap) != len(canonicalVPNScripts) {
		return fmt.Errorf("expected strictly %d <script> elements after base bootstrap, found %d",
			len(canonicalVPNScripts), len(scriptsAfterBootstrap))
	}

	for i, s := range scriptsAfterBootstrap {
		if err := validateScriptElement(s, canonicalVPNScripts[i]); err != nil {
			return fmt.Errorf("script index %d after bootstrap: %w", i, err)
		}
	}

	return nil
}

func TestRenderedVPNTemplateScriptPlacementAndOrder(t *testing.T) {
	// 1. Verify isolated scripts block
	scriptsHTML := renderVPNScriptsBlock(t)
	if err := validateVPNScriptsBlock(scriptsHTML); err != nil {
		t.Fatalf("scripts block validation failed: %v", err)
	}

	// 2. Verify full rendered page
	pageHTML := renderBaseAndVPNTemplate(t)
	if err := validateRenderedVPNPage(pageHTML); err != nil {
		t.Fatalf("full page validation failed: %v", err)
	}
}

func TestRenderedVPNTemplateRejectAsyncMutant(t *testing.T) {
	rendered := renderBaseAndVPNTemplate(t)
	mutated := strings.Replace(rendered, `src="/static/js/vpn/backends.js"`, `src="/static/js/vpn/backends.js" async`, 1)
	if mutated == rendered {
		t.Fatal("failed to apply async mutation")
	}
	err := validateRenderedVPNPage(mutated)
	if err == nil {
		t.Fatal("expected validateRenderedVPNPage to reject async mutant, but it passed")
	}
	if !strings.Contains(err.Error(), "async") {
		t.Fatalf("expected error mentioning 'async', got: %v", err)
	}

	// Also check scripts block
	scriptsBlock := renderVPNScriptsBlock(t)
	mutatedBlock := strings.Replace(scriptsBlock, `src="/static/js/vpn/backends.js"`, `src="/static/js/vpn/backends.js" async`, 1)
	if err := validateVPNScriptsBlock(mutatedBlock); err == nil || !strings.Contains(err.Error(), "async") {
		t.Fatalf("expected validateVPNScriptsBlock to reject async mutant, got: %v", err)
	}
}

func TestRenderedVPNTemplateRejectInlineScriptMutant(t *testing.T) {
	rendered := renderBaseAndVPNTemplate(t)
	mutated := strings.Replace(rendered, `<script src="/static/js/vpn/page.js"></script>`,
		`<script src="/static/js/vpn/page.js"></script><script>window.unexpectedInline = true</script>`, 1)
	if mutated == rendered {
		t.Fatal("failed to apply inline script mutation")
	}
	err := validateRenderedVPNPage(mutated)
	if err == nil {
		t.Fatal("expected validateRenderedVPNPage to reject inline script mutant, but it passed")
	}

	scriptsBlock := renderVPNScriptsBlock(t)
	mutatedBlock := strings.Replace(scriptsBlock, `<script src="/static/js/vpn/page.js"></script>`,
		`<script src="/static/js/vpn/page.js"></script><script>window.unexpectedInline = true</script>`, 1)
	if err := validateVPNScriptsBlock(mutatedBlock); err == nil {
		t.Fatal("expected validateVPNScriptsBlock to reject inline script mutant, but it passed")
	}
}

func TestRenderedVPNTemplateRejectExtraScriptMutant(t *testing.T) {
	rendered := renderBaseAndVPNTemplate(t)
	mutated := strings.Replace(rendered, `<script src="/static/js/vpn/page.js"></script>`,
		`<script src="/static/js/vpn/page.js"></script><script src="/static/js/vpn/extra.js"></script>`, 1)
	if mutated == rendered {
		t.Fatal("failed to apply extra script mutation")
	}
	err := validateRenderedVPNPage(mutated)
	if err == nil {
		t.Fatal("expected validateRenderedVPNPage to reject extra script mutant, but it passed")
	}

	scriptsBlock := renderVPNScriptsBlock(t)
	mutatedBlock := strings.Replace(scriptsBlock, `<script src="/static/js/vpn/page.js"></script>`,
		`<script src="/static/js/vpn/page.js"></script><script src="/static/js/vpn/extra.js"></script>`, 1)
	if err := validateVPNScriptsBlock(mutatedBlock); err == nil {
		t.Fatal("expected validateVPNScriptsBlock to reject extra script mutant, but it passed")
	}
}

func TestRenderedVPNTemplateRejectOrderMutant(t *testing.T) {
	rendered := renderBaseAndVPNTemplate(t)
	// Swap backends.js and health_problems.js
	b1 := `<script src="/static/js/vpn/backends.js"></script>`
	b2 := `<script src="/static/js/vpn/health_problems.js"></script>`
	mutated := strings.Replace(rendered, b1, "__PLACEHOLDER__", 1)
	mutated = strings.Replace(mutated, b2, b1, 1)
	mutated = strings.Replace(mutated, "__PLACEHOLDER__", b2, 1)
	if mutated == rendered {
		t.Fatal("failed to apply order mutation")
	}
	err := validateRenderedVPNPage(mutated)
	if err == nil {
		t.Fatal("expected validateRenderedVPNPage to reject order mutant, but it passed")
	}

	scriptsBlock := renderVPNScriptsBlock(t)
	mutatedBlock := strings.Replace(scriptsBlock, b1, "__PLACEHOLDER__", 1)
	mutatedBlock = strings.Replace(mutatedBlock, b2, b1, 1)
	mutatedBlock = strings.Replace(mutatedBlock, "__PLACEHOLDER__", b2, 1)
	if err := validateVPNScriptsBlock(mutatedBlock); err == nil {
		t.Fatal("expected validateVPNScriptsBlock to reject order mutant, but it passed")
	}
}

func TestRenderedVPNTemplateRejectDeferAndNonClassicTypeMutants(t *testing.T) {
	rendered := renderBaseAndVPNTemplate(t)
	scriptsBlock := renderVPNScriptsBlock(t)

	typeMutants := []struct {
		name      string
		targetSrc string
		attr      string
	}{
		{"Defer", `/static/js/vpn/charts.js`, `defer`},
		{"ModuleLowercase", `/static/js/vpn/sessions.js`, `type="module"`},
		{"ModuleUppercase", `/static/js/vpn/sessions.js`, `type="MODULE"`},
		{"ModuleWhitespace", `/static/js/vpn/sessions.js`, `type=" module"`},
		{"ApplicationJSON", `/static/js/vpn/sessions.js`, `type="application/json"`},
		{"TextPlain", `/static/js/vpn/sessions.js`, `type="text/plain"`},
		{"NoModule", `/static/js/vpn/sessions.js`, `nomodule`},
	}

	for _, tc := range typeMutants {
		t.Run(tc.name, func(t *testing.T) {
			origTarget := fmt.Sprintf(`src="%s"`, tc.targetSrc)
			mutatedTarget := fmt.Sprintf(`src="%s" %s`, tc.targetSrc, tc.attr)

			// Page check
			mutatedPage := strings.Replace(rendered, origTarget, mutatedTarget, 1)
			if mutatedPage == rendered {
				t.Fatalf("failed to apply %s mutation to rendered page", tc.name)
			}
			if err := validateRenderedVPNPage(mutatedPage); err == nil {
				t.Fatalf("expected validateRenderedVPNPage to reject %s mutant, but it passed", tc.name)
			}

			// Block check
			mutatedBlock := strings.Replace(scriptsBlock, origTarget, mutatedTarget, 1)
			if mutatedBlock == scriptsBlock {
				t.Fatalf("failed to apply %s mutation to scripts block", tc.name)
			}
			if err := validateVPNScriptsBlock(mutatedBlock); err == nil {
				t.Fatalf("expected validateVPNScriptsBlock to reject %s mutant, but it passed", tc.name)
			}
		})
	}
}

func TestRenderedVPNTemplateRejectPreBootstrapMutants(t *testing.T) {
	rendered := renderBaseAndVPNTemplate(t)

	t.Run("VPNPrecedingBootstrapRejected", func(t *testing.T) {
		mutated := strings.Replace(rendered, `<head>`, `<head><script src="/static/js/vpn/page.js"></script>`, 1)
		if mutated == rendered {
			t.Fatal("failed to apply VPN preceding bootstrap mutation")
		}
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatal("expected validateRenderedVPNPage to reject VPN script preceding bootstrap, but it passed")
		}
	})

	t.Run("InlineScriptInHeadBeforeBootstrap", func(t *testing.T) {
		mutated := strings.Replace(rendered, `<head>`, `<head><script>window.unexpectedHead = true;</script>`, 1)
		if mutated == rendered {
			t.Fatal("failed to apply inline script in head mutation")
		}
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatal("expected validateRenderedVPNPage to reject extra inline script in head, but it passed")
		}
	})

	t.Run("InlineScriptInBodyBeforeBootstrap", func(t *testing.T) {
		mutated := strings.Replace(rendered, `<script>`, `<script>window.unexpectedBody = true;</script><script>`, 2)
		if mutated == rendered {
			t.Fatal("failed to apply inline script in body mutation")
		}
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatal("expected validateRenderedVPNPage to reject extra inline script before bootstrap, but it passed")
		}
	})

	t.Run("DecoyI18NInHead", func(t *testing.T) {
		mutated := strings.Replace(rendered, `<head>`, `<head><script>window.I18N = {};</script>`, 1)
		if mutated == rendered {
			t.Fatal("failed to apply decoy I18N mutation")
		}
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatal("expected validateRenderedVPNPage to reject decoy I18N in head, but it passed")
		}
	})

	t.Run("CoreScriptOrderSwapped", func(t *testing.T) {
		s1 := `<script src="/static/js/qrcode.min.js"></script>`
		s2 := `<script src="/static/js/api.js"></script>`
		mutated := strings.Replace(rendered, s1, "__PLACEHOLDER__", 1)
		mutated = strings.Replace(mutated, s2, s1, 1)
		mutated = strings.Replace(mutated, "__PLACEHOLDER__", s2, 1)
		if mutated == rendered {
			t.Fatal("failed to apply core script swap mutation")
		}
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatal("expected validateRenderedVPNPage to reject swapped core scripts, but it passed")
		}
	})

	t.Run("CoreScriptNonClassicType", func(t *testing.T) {
		mutated := strings.Replace(rendered, `src="/static/js/tables.js"`, `src="/static/js/tables.js" type="module"`, 1)
		if mutated == rendered {
			t.Fatal("failed to apply core script non-classic type mutation")
		}
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatal("expected validateRenderedVPNPage to reject core script module type, but it passed")
		}
	})

	t.Run("CoreScriptNomodule", func(t *testing.T) {
		mutated := strings.Replace(rendered, `src="/static/js/telemetry.js"`, `src="/static/js/telemetry.js" nomodule`, 1)
		if mutated == rendered {
			t.Fatal("failed to apply core script nomodule mutation")
		}
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatal("expected validateRenderedVPNPage to reject core script nomodule attribute, but it passed")
		}
	})
}

func TestRenderedVPNTemplateRejectBootstrapMutants(t *testing.T) {
	rendered := renderBaseAndVPNTemplate(t)

	mutateBootstrap := func(t *testing.T, tagReplacement string) string {
		t.Helper()
		const marker = "window.I18N"
		idx := strings.Index(rendered, marker)
		if idx == -1 {
			t.Fatalf("translation bootstrap marker %q not found in rendered template", marker)
		}
		scriptIdx := strings.LastIndex(rendered[:idx], "<script>")
		if scriptIdx == -1 {
			t.Fatalf("opening <script> tag before translation bootstrap marker not found; prefix: %q", rendered[max(0, idx-100):idx])
		}
		return rendered[:scriptIdx] + tagReplacement + rendered[scriptIdx+len("<script>"):]
	}

	t.Run("BootstrapApplicationJSON", func(t *testing.T) {
		mutated := mutateBootstrap(t, `<script type="application/json">`)
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatalf("expected validateRenderedVPNPage to reject bootstrap type application/json, but it passed")
		}
	})

	t.Run("BootstrapTextPlain", func(t *testing.T) {
		mutated := mutateBootstrap(t, `<script type="text/plain">`)
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatalf("expected validateRenderedVPNPage to reject bootstrap type text/plain, but it passed")
		}
	})

	t.Run("BootstrapModule", func(t *testing.T) {
		mutated := mutateBootstrap(t, `<script type="module">`)
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatalf("expected validateRenderedVPNPage to reject bootstrap type module, but it passed")
		}
	})

	t.Run("BootstrapModuleUppercase", func(t *testing.T) {
		mutated := mutateBootstrap(t, `<script type="MODULE">`)
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatalf("expected validateRenderedVPNPage to reject bootstrap type MODULE, but it passed")
		}
	})

	t.Run("BootstrapEmptySrc", func(t *testing.T) {
		mutated := mutateBootstrap(t, `<script src="">`)
		if err := validateRenderedVPNPage(mutated); err == nil {
			t.Fatalf("expected validateRenderedVPNPage to reject bootstrap src=\"\", but it passed")
		}
	})

	t.Run("BootstrapValidClassicMIME", func(t *testing.T) {
		mutated := mutateBootstrap(t, `<script type="text/javascript">`)
		if err := validateRenderedVPNPage(mutated); err != nil {
			t.Fatalf("expected validateRenderedVPNPage to accept valid classic MIME type text/javascript, got: %v", err)
		}
	})
}

func TestStaticVPNScriptHTTPServing(t *testing.T) {
	staticSubFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	server := httptest.NewServer(http.StripPrefix("/static/", http.FileServer(http.FS(staticSubFS))))
	defer server.Close()

	client := server.Client()

	for _, vpnScriptPath := range canonicalVPNScripts {
		t.Run(vpnScriptPath, func(t *testing.T) {
			relPath := strings.TrimPrefix(vpnScriptPath, "/static/")
			expectedBytes, err := fs.ReadFile(staticSubFS, relPath)
			if err != nil {
				t.Fatalf("failed to read embedded %s: %v", relPath, err)
			}
			if len(bytes.TrimSpace(expectedBytes)) == 0 {
				t.Fatalf("embedded %s is empty or whitespace", relPath)
			}

			url := server.URL + vpnScriptPath
			resp, err := client.Get(url)
			if err != nil {
				t.Fatalf("HTTP GET %s failed: %v", url, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected HTTP 200 for %s, got %d", vpnScriptPath, resp.StatusCode)
			}

			contentType := resp.Header.Get("Content-Type")
			if !strings.Contains(contentType, "javascript") {
				t.Errorf("expected Content-Type containing 'javascript' for %s, got %q",
					vpnScriptPath, contentType)
			}

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed reading response body for %s: %v", vpnScriptPath, err)
			}

			if !bytes.Equal(bodyBytes, expectedBytes) {
				t.Errorf("served bytes do not match embedded bytes for %s (len served=%d, len embedded=%d)",
					vpnScriptPath, len(bodyBytes), len(expectedBytes))
			}
		})
	}

	// Negative test: non-existent static file returns 404
	t.Run("NonExistentVPNScriptReturns404", func(t *testing.T) {
		resp, err := client.Get(server.URL + "/static/js/vpn/nonexistent_module.js")
		if err != nil {
			t.Fatalf("HTTP GET failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected HTTP 404 for non-existent asset, got %d", resp.StatusCode)
		}
	})
}
