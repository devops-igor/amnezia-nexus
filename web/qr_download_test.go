package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"strings"
	"testing"
)

// extractPanelQR finds and extracts the balanced <div ... id="panel-qr"> element from template content.
func extractPanelQR(t *testing.T, content string) string {
	t.Helper()
	panelIdx := strings.Index(content, `id="panel-qr"`)
	if panelIdx == -1 {
		t.Fatalf("id=\"panel-qr\" not found in template")
	}

	startIdx := strings.LastIndex(content[:panelIdx], "<div")
	if startIdx == -1 {
		t.Fatalf("opening <div for id=\"panel-qr\" not found")
	}

	depth := 0
	endIdx := -1
	inTag := false
	isClosing := false
	tagBuf := strings.Builder{}

	for i := startIdx; i < len(content); i++ {
		ch := content[i]
		if ch == '<' {
			inTag = true
			isClosing = (i+1 < len(content) && content[i+1] == '/')
			tagBuf.Reset()
			continue
		}
		if ch == '>' {
			inTag = false
			tagStr := strings.TrimSpace(tagBuf.String())
			parts := strings.Fields(tagStr)
			if len(parts) > 0 {
				name := strings.TrimPrefix(parts[0], "/")
				name = strings.ToLower(name)
				if name == "div" {
					if isClosing {
						depth--
						if depth == 0 {
							endIdx = i + 1
							break
						}
					} else {
						depth++
					}
				}
			}
			continue
		}
		if inTag {
			tagBuf.WriteByte(ch)
		}
	}

	if endIdx == -1 {
		t.Fatalf("could not find balanced closing </div> for panel-qr")
	}
	return content[startIdx:endIdx]
}

func TestQRPanelsAcrossTemplates(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	tests := []struct {
		filename        string
		expectedAction  string
		expectedSubstrs []string
	}{
		{
			filename:       "server.html",
			expectedAction: "UI.downloadQRCode",
			expectedSubstrs: []string{
				`UI.downloadQRCode('qrCode', (currentConfigName || 'vpn_config') + '_qr.png')`,
				`{{ _ "download" }} QR`,
			},
		},
		{
			filename:       "my_connections.html",
			expectedAction: "downloadQRCode()",
			expectedSubstrs: []string{
				`downloadQRCode()`,
				`{{ _ "download" }} QR`,
			},
		},
		{
			filename:       "user_share.html",
			expectedAction: "downloadQRCode",
			expectedSubstrs: []string{
				`{{ _ "download" }} QR`,
				`qrcode`,
			},
		},
		{
			filename:       "users.html",
			expectedAction: "UI.downloadQRCode",
			expectedSubstrs: []string{
				`UI.downloadQRCode('qrCode', (currentConfigName || 'vpn_config') + '_qr.png')`,
				`{{ _ "download" }} QR`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			data, err := fs.ReadFile(templatesFS, tt.filename)
			if err != nil {
				t.Fatalf("failed to read template %s: %v", tt.filename, err)
			}
			content := string(data)

			panelQR := extractPanelQR(t, content)

			// 1. Must NOT contain mismatched .conf download button or label
			if strings.Contains(panelQR, "download_conf") {
				t.Errorf("%s: #panel-qr must not contain mismatched download_conf label: %s", tt.filename, panelQR)
			}
			if strings.Contains(panelQR, ".conf") {
				t.Errorf("%s: #panel-qr must not contain mismatched .conf download: %s", tt.filename, panelQR)
			}
			if strings.Contains(panelQR, "UI.downloadFile") {
				t.Errorf("%s: #panel-qr must not contain UI.downloadFile: %s", tt.filename, panelQR)
			}

			// 2. Must contain QR download action
			if !strings.Contains(panelQR, tt.expectedAction) {
				t.Errorf("%s: #panel-qr missing expected QR download action %q: %s", tt.filename, tt.expectedAction, panelQR)
			}

			// 3. Must contain expected substrings
			for _, sub := range tt.expectedSubstrs {
				if !strings.Contains(panelQR, sub) {
					t.Errorf("%s: #panel-qr missing expected substring %q", tt.filename, sub)
				}
			}
		})
	}
}

func TestUIDownloadQRCodeSignatures(t *testing.T) {
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	uiData, err := fs.ReadFile(staticFS, "js/ui.js")
	if err != nil {
		t.Fatalf("failed to read js/ui.js: %v", err)
	}
	uiStr := string(uiData)

	requiredSignatures := []string{
		"root.downloadQRCode",
		"downloadQRCode: downloadQRCode",
		"function downloadQRCode(containerOrId, filename)",
		"canvas.toDataURL('image/png')",
		"img.src",
		"Unable to export QR image",
	}

	for _, sig := range requiredSignatures {
		if !strings.Contains(uiStr, sig) {
			t.Errorf("js/ui.js missing required signature %q", sig)
		}
	}
}

func TestQRTemplateExecution(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	funcMap := template.FuncMap{
		"_":        func(k string, args ...any) string { return k },
		"has_role": func(u any, roles ...string) bool { return true },
		"json": func(v any) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
		"slice_str": func(s string, start, end int) string {
			if start < 0 {
				start = 0
			}
			if end > len(s) {
				end = len(s)
			}
			return s[start:end]
		},
		"format_bytes": func(b any) string { return "0 B" },
		"upper":        func(s any) string { return strings.ToUpper(fmt.Sprint(s)) },
		"safe_js":      func(s any) template.JS { return template.JS(fmt.Sprint(s)) },
		"str":          func(v any) string { return fmt.Sprint(v) },
		"proto_title":  func(p any) string { return fmt.Sprint(p) },
		"is_installed": func(v any) bool { return true },
		"format_time":  func(t any) string { return "" },
		"lower":        func(s any) string { return strings.ToLower(fmt.Sprint(s)) },
		"is_admin": func(u any) bool {
			if m, ok := u.(map[string]any); ok {
				if r, ok := m["Role"].(string); ok {
					return strings.EqualFold(r, "admin")
				}
			}
			return false
		},
		"get": func(target any, key any, defaultVal ...any) any {
			if len(defaultVal) > 0 {
				return defaultVal[0]
			}
			return nil
		},
	}

	templates := []string{"server.html", "my_connections.html", "user_share.html", "users.html"}
	for _, tmplName := range templates {
		t.Run(tmplName, func(t *testing.T) {
			tmpl, err := template.New("base.html").Funcs(funcMap).ParseFS(templatesFS, "base.html", tmplName)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", tmplName, err)
			}

			data := map[string]any{
				"title":             "Test Title",
				"lang":              "en",
				"active_page":       "test",
				"csrf_token":        "token-123",
				"translations_json": "{}",
				"current_user":      map[string]any{"ID": "1", "Username": "admin", "Role": "admin"},
				"site_settings":     map[string]any{"Title": "Amnezia", "Subtitle": "Nexus"},
				"server":            map[string]any{"ID": 42, "Name": "srv-test", "Host": "127.0.0.1"},
				"servers":           []any{map[string]any{"ID": 42, "Name": "srv-test"}},
				"connections":       []any{},
				"share_user":        map[string]any{"Username": "alice"},
				"token":             "tok-abc",
				"users":             []any{},
			}

			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, data); err != nil {
				t.Fatalf("failed to execute %s: %v", tmplName, err)
			}

			rendered := buf.String()
			panelQR := extractPanelQR(t, rendered)

			if strings.Contains(panelQR, "download_conf") {
				t.Errorf("rendered %s #panel-qr must not contain download_conf: %s", tmplName, panelQR)
			}
			if !strings.Contains(panelQR, "download") || !strings.Contains(panelQR, "QR") {
				t.Errorf("rendered %s #panel-qr missing download QR action: %s", tmplName, panelQR)
			}
		})
	}
}

func TestUIDownloadQRCodeJSDOM(t *testing.T) {
	nodePath := requireJSDOM(t)

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	uiData, err := fs.ReadFile(staticFS, "js/ui.js")
	if err != nil {
		t.Fatalf("failed to read js/ui.js: %v", err)
	}
	uiJSJSON, err := json.Marshal(string(uiData))
	if err != nil {
		t.Fatalf("failed to marshal ui.js: %v", err)
	}

	script := fmt.Sprintf(`%s
const uiCode = %s;

const dom = new JSDOM('<!DOCTYPE html><html><body><div id="qrCanvas"></div><div id="qrImg"></div><div id="qrEmpty"></div></body></html>', {
    runScripts: 'dangerously',
    pretendToBeVisual: true,
});

const w = dom.window;
const d = w.document;

// Execute ui.js in JSDOM context
const scriptEl = d.createElement('script');
scriptEl.textContent = uiCode;
d.body.appendChild(scriptEl);

assert(typeof w.UI === 'object', 'window.UI must be an object');
assert(typeof w.UI.downloadQRCode === 'function', 'UI.downloadQRCode must be a function');
assert(typeof w.downloadQRCode === 'function', 'window.downloadQRCode must be a function');

let clickCount = 0;
let lastClickedAnchor = null;
const origCreateElement = d.createElement.bind(d);
d.createElement = function(tagName) {
    const el = origCreateElement(tagName);
    if (tagName.toLowerCase() === 'a') {
        el.click = function() {
            clickCount++;
            lastClickedAnchor = {
                href: el.href,
                download: el.download
            };
        };
    }
    return el;
};

// Case 1: Canvas element present in container
const canvasDiv = d.getElementById('qrCanvas');
const canvas = d.createElement('canvas');
canvas.toDataURL = (mime) => 'data:image/png;base64,CANVAS_DATA';
canvasDiv.appendChild(canvas);

clickCount = 0;
lastClickedAnchor = null;
w.UI.downloadQRCode('qrCanvas', 'test_vpn_qr.png');
assert.strictEqual(clickCount, 1, 'Canvas QR should trigger anchor click');
assert.strictEqual(lastClickedAnchor.download, 'test_vpn_qr.png', 'Download filename should match');
assert.strictEqual(lastClickedAnchor.href, 'data:image/png;base64,CANVAS_DATA', 'Download href should match canvas data');

// Case 2: Img fallback element present in container
const imgDiv = d.getElementById('qrImg');
const img = d.createElement('img');
img.src = 'data:image/png;base64,IMG_DATA';
imgDiv.appendChild(img);

clickCount = 0;
lastClickedAnchor = null;
w.UI.downloadQRCode('qrImg', 'image_vpn');
assert.strictEqual(clickCount, 1, 'Img QR should trigger anchor click');
assert.strictEqual(lastClickedAnchor.download, 'image_vpn.png', 'Filename without .png should have .png appended');
assert.strictEqual(lastClickedAnchor.href, 'data:image/png;base64,IMG_DATA', 'Download href should match img src');

// Case 3: Empty container triggers toast error
clickCount = 0;
lastClickedAnchor = null;
w.UI.downloadQRCode('qrEmpty', 'empty.png');
assert.strictEqual(clickCount, 0, 'Empty container should not trigger click');
const toastEl = d.querySelector('.toast');
assert(toastEl, 'Toast notification element should be created on error');
assert(toastEl.textContent.includes('Unable to export QR image'), 'Toast should display error message');

// Case 4: Non-existent container triggers toast
clickCount = 0;
lastClickedAnchor = null;
w.UI.downloadQRCode('nonExistentContainer', 'test.png');
assert.strictEqual(clickCount, 0, 'Non-existent container should not trigger click');

console.log('UI_DOWNLOAD_QR_TESTS_OK');
`, jsdomBootstrapSnippet, string(uiJSJSON))

	out, err := execNodeScript(nodePath, script)
	if err != nil {
		t.Fatalf("node test execution failed: %v\nOutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "UI_DOWNLOAD_QR_TESTS_OK") {
		t.Fatalf("node test output missing success marker: %s", string(out))
	}
}
