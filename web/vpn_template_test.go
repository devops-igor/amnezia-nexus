package web

import (
	"bytes"
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

func renderBaseAndVPNTemplate(t *testing.T) string {
	t.Helper()

	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	funcMap := template.FuncMap{
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

	tmpl, err := template.New("base.html").Funcs(funcMap).ParseFS(templatesFS, "base.html", "vpn.html")
	if err != nil {
		t.Fatalf("failed to parse base.html and vpn.html: %v", err)
	}

	data := map[string]any{
		"title":        "VPN Test",
		"lang":         "en",
		"active_page":  "vpn",
		"csrf_token":   "csrf-test-token",
		"current_user": map[string]any{"Username": "admin", "Role": "admin"},
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

func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
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

func TestRenderedVPNTemplateScriptPlacementAndOrder(t *testing.T) {
	rendered := renderBaseAndVPNTemplate(t)

	doc, err := html.Parse(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("failed to parse rendered HTML: %v", err)
	}

	// 1. Assert content area (main.app-main) contains ZERO <script> elements
	mainContent := findElementByTagAndClass(doc, "main", "app-main")
	if mainContent == nil {
		t.Fatal("could not find <main class=\"app-main\"> in rendered document")
	}

	contentScripts := collectScriptNodes(mainContent)
	if len(contentScripts) > 0 {
		var scriptSources []string
		for _, s := range contentScripts {
			if src := getAttr(s, "src"); src != "" {
				scriptSources = append(scriptSources, src)
			} else {
				scriptSources = append(scriptSources, "inline:"+strings.TrimSpace(getNodeText(s)))
			}
		}
		t.Fatalf("expected 0 <script> elements inside content area (main.app-main), found %d: %v",
			len(contentScripts), scriptSources)
	}

	// 2. Assert script elements across document and check placement & canonical order
	allScripts := collectScriptNodes(doc)
	if len(allScripts) == 0 {
		t.Fatal("no <script> elements found in rendered page")
	}

	// Verify core scripts appear before VPN companion scripts
	var scriptSrcs []string
	for _, s := range allScripts {
		if src := getAttr(s, "src"); src != "" {
			scriptSrcs = append(scriptSrcs, src)
		}
	}

	for _, core := range coreScripts {
		coreIdx := -1
		for i, src := range scriptSrcs {
			if src == core {
				coreIdx = i
				break
			}
		}
		if coreIdx == -1 {
			t.Errorf("core prerequisite script %q missing from rendered page", core)
			continue
		}
		// Must precede all VPN scripts
		for _, vpnScript := range canonicalVPNScripts {
			for j, src := range scriptSrcs {
				if src == vpnScript && j < coreIdx {
					t.Errorf("VPN script %q (index %d) appears before core prerequisite %q (index %d)",
						vpnScript, j, core, coreIdx)
				}
			}
		}
	}

	// Verify each VPN companion script appears exactly once, in canonical order
	vpnScriptIndices := make(map[string]int)
	for _, vpnScript := range canonicalVPNScripts {
		count := 0
		firstIdx := -1
		for i, src := range scriptSrcs {
			if src == vpnScript {
				count++
				if firstIdx == -1 {
					firstIdx = i
				}
			}
		}
		if count != 1 {
			t.Errorf("expected script %q to appear exactly once, appeared %d times", vpnScript, count)
		}
		vpnScriptIndices[vpnScript] = firstIdx
	}

	// Assert strict ascending canonical order
	for i := 0; i < len(canonicalVPNScripts)-1; i++ {
		current := canonicalVPNScripts[i]
		next := canonicalVPNScripts[i+1]
		idxCurr := vpnScriptIndices[current]
		idxNext := vpnScriptIndices[next]
		if idxCurr >= idxNext {
			t.Errorf("canonical script ordering violation: %s (idx %d) must precede %s (idx %d)",
				current, idxCurr, next, idxNext)
		}
	}

	// 3. Assert VPN scripts have empty bodies (classic external scripts)
	for _, s := range allScripts {
		src := getAttr(s, "src")
		for _, vpnScript := range canonicalVPNScripts {
			if src == vpnScript {
				bodyText := strings.TrimSpace(getNodeText(s))
				if bodyText != "" {
					t.Errorf("expected script %q to have empty body, got: %q", vpnScript, bodyText)
				}
			}
		}
	}
}

func TestStaticVPNScriptHTTPServing(t *testing.T) {
	staticSubFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	// Match the production router's static file handler pattern:
	// r.Handle("/static/*", http.StripPrefix("/static", http.FileServer(http.FS(staticSubFS))))
	handler := http.StripPrefix("/static", http.FileServer(http.FS(staticSubFS)))
	server := httptest.NewServer(handler)
	defer server.Close()

	client := server.Client()

	for _, vpnScriptPath := range canonicalVPNScripts {
		t.Run(vpnScriptPath, func(t *testing.T) {
			// Read embedded expected bytes
			relPath := strings.TrimPrefix(vpnScriptPath, "/static/")
			expectedBytes, err := fs.ReadFile(staticSubFS, relPath)
			if err != nil {
				t.Fatalf("failed to read embedded %s: %v", relPath, err)
			}
			if len(bytes.TrimSpace(expectedBytes)) == 0 {
				t.Fatalf("embedded %s is empty or whitespace", relPath)
			}

			// Issue HTTP GET request
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
