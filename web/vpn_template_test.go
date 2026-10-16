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

	"github.com/go-chi/chi/v5"
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

func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return true
		}
	}
	return false
}

func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
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
		src := getAttr(s, "src")
		expectedSrc := canonicalVPNScripts[i]
		if src != expectedSrc {
			return fmt.Errorf("script index %d in scripts block: expected src %q, got %q", i, expectedSrc, src)
		}
		if hasAttr(s, "async") {
			return fmt.Errorf("script %q must not have async attribute", src)
		}
		if hasAttr(s, "defer") {
			return fmt.Errorf("script %q must not have defer attribute", src)
		}
		if getAttr(s, "type") == "module" {
			return fmt.Errorf("script %q must not have type=\"module\"", src)
		}
		body := strings.TrimSpace(getNodeText(s))
		if body != "" {
			return fmt.Errorf("script %q must have empty body, got: %q", src, body)
		}
	}
	return nil
}

// validateRenderedVPNPage verifies script placement, canonical ordering, classic execution mode,
// zero content-area scripts, and strict precedence of base bootstrap over VPN scripts.
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

	// 4. Verify core prerequisite scripts appear before the bootstrap script
	for _, core := range coreScripts {
		coreFound := false
		for i := 0; i < bootstrapIdx; i++ {
			if getAttr(allScripts[i], "src") == core {
				coreFound = true
				break
			}
		}
		if !coreFound {
			return fmt.Errorf("core prerequisite script %q missing or not before bootstrap script", core)
		}
	}

	// 5. Ensure NO VPN companion scripts exist at or before bootstrapIdx
	for i := 0; i <= bootstrapIdx; i++ {
		src := getAttr(allScripts[i], "src")
		for _, vpnScript := range canonicalVPNScripts {
			if src == vpnScript {
				return fmt.Errorf("VPN script %q placed at or before base bootstrap (index %d vs %d)",
					src, i, bootstrapIdx)
			}
		}
	}

	// 6. Scripts after base bootstrap must be strictly the 6 canonical VPN scripts, with zero extra
	scriptsAfterBootstrap := allScripts[bootstrapIdx+1:]
	if len(scriptsAfterBootstrap) != len(canonicalVPNScripts) {
		return fmt.Errorf("expected strictly %d <script> elements after base bootstrap, found %d",
			len(canonicalVPNScripts), len(scriptsAfterBootstrap))
	}

	for i, s := range scriptsAfterBootstrap {
		src := getAttr(s, "src")
		expectedSrc := canonicalVPNScripts[i]
		if src != expectedSrc {
			return fmt.Errorf("script index %d after bootstrap: expected src %q, got %q", i, expectedSrc, src)
		}
		if hasAttr(s, "async") {
			return fmt.Errorf("script %q must not have async attribute", src)
		}
		if hasAttr(s, "defer") {
			return fmt.Errorf("script %q must not have defer attribute", src)
		}
		if getAttr(s, "type") == "module" {
			return fmt.Errorf("script %q must not have type=\"module\"", src)
		}
		body := strings.TrimSpace(getNodeText(s))
		if body != "" {
			return fmt.Errorf("script %q must have empty body, got: %q", src, body)
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

func TestRenderedVPNTemplateRejectDeferAndModuleMutants(t *testing.T) {
	rendered := renderBaseAndVPNTemplate(t)

	t.Run("DeferMutantRejected", func(t *testing.T) {
		mutated := strings.Replace(rendered, `src="/static/js/vpn/charts.js"`, `src="/static/js/vpn/charts.js" defer`, 1)
		err := validateRenderedVPNPage(mutated)
		if err == nil || !strings.Contains(err.Error(), "defer") {
			t.Fatalf("expected error mentioning 'defer', got: %v", err)
		}
	})

	t.Run("ModuleMutantRejected", func(t *testing.T) {
		mutated := strings.Replace(rendered, `src="/static/js/vpn/sessions.js"`, `src="/static/js/vpn/sessions.js" type="module"`, 1)
		err := validateRenderedVPNPage(mutated)
		if err == nil || !strings.Contains(err.Error(), "module") {
			t.Fatalf("expected error mentioning 'module', got: %v", err)
		}
	})

	t.Run("VPNPrecedingBootstrapRejected", func(t *testing.T) {
		// Inject a VPN script into the head before bootstrap
		mutated := strings.Replace(rendered, `<head>`, `<head><script src="/static/js/vpn/page.js"></script>`, 1)
		err := validateRenderedVPNPage(mutated)
		if err == nil {
			t.Fatal("expected error when VPN script precedes base bootstrap, got nil")
		}
	})
}

func TestStaticVPNScriptHTTPServing(t *testing.T) {
	staticSubFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	// Serve through Chi router with production Cache-Control header middleware matching internal/router/router.go:serveStatic
	r := chi.NewRouter()
	fileServer := http.FileServer(http.FS(staticSubFS))
	r.Handle("/static/*", http.StripPrefix("/static", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fileServer.ServeHTTP(w, req)
	})))

	server := httptest.NewServer(r)
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

			cacheControl := resp.Header.Get("Cache-Control")
			if cacheControl != "public, max-age=86400" {
				t.Errorf("expected Cache-Control 'public, max-age=86400' for %s, got %q",
					vpnScriptPath, cacheControl)
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

	// Negative test: non-existent static file returns 404 without redirect or HTML fallback
	t.Run("NonExistentVPNScriptReturns404", func(t *testing.T) {
		resp, err := client.Get(server.URL + "/static/js/vpn/nonexistent_module.js")
		if err != nil {
			t.Fatalf("HTTP GET failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected HTTP 404 for non-existent asset, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/html") {
			t.Errorf("expected non-HTML response for 404 static asset, got %q", ct)
		}
	})
}
