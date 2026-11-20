package web

// Visibility contract for the profile statement on the client configuration
// modal (#917 P3).
//
// The modal is shared by every connection type, but only an AmneziaWG profile
// ever carried the panel's gateway resolver, so the statement must appear for
// that protocol alone. The protocol is already known to the code that fills the
// modal: the server renders it on the row (`data-proto`) and returns it in the
// create response, and the shipped `syncProfileNotice` is the single place the
// decision is made.
//
// These assertions run that shipped renderer in JSDOM against the markup the
// template actually produces, and cover the stale-flag case the modal invites:
// it is reopened for a different protocol on the same page, so visibility left
// over from the previous profile must not persist. The description link is
// asserted with the visibility, because it must never point at a hidden
// paragraph.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"testing"
)

// renderMyConnectionsModalPartsForNotice renders the shipped page template and
// returns the modal markup and the inline controller script, each rendered on
// its own so the JSDOM document carries only what this page produces.
func renderMyConnectionsModalPartsForNotice(t *testing.T) (markup, script string) {
	t.Helper()

	funcs := template.FuncMap{
		"_":           func(k string, args ...any) string { return k },
		"json":        func(v any) (string, error) { b, err := json.Marshal(v); return string(b), err },
		"proto_title": func(p any) string { return fmt.Sprint(p) },
		"slice_str": func(s string, start, end int) string {
			if start < 0 {
				start = 0
			}
			if end > len(s) {
				end = len(s)
			}
			return s[start:end]
		},
		"upper":       func(s any) string { return strings.ToUpper(fmt.Sprint(s)) },
		"lower":       func(s any) string { return strings.ToLower(fmt.Sprint(s)) },
		"str":         func(v any) string { return fmt.Sprint(v) },
		"format_time": func(v any) string { return "" },
		"is_admin":    func(u any) bool { return true },
	}

	tmpl, err := template.New("my_connections.html").Funcs(funcs).ParseFS(TemplatesFS, "templates/my_connections.html")
	if err != nil {
		t.Fatalf("parse my_connections.html: %v", err)
	}

	data := map[string]any{
		"current_user": map[string]any{"Role": "admin"},
		"servers":      []any{},
		"connections":  []any{},
	}

	var content, scripts bytes.Buffer
	if err := tmpl.ExecuteTemplate(&content, "content", data); err != nil {
		t.Fatalf("render content block: %v", err)
	}
	if err := tmpl.ExecuteTemplate(&scripts, "scripts", data); err != nil {
		t.Fatalf("render scripts block: %v", err)
	}

	markup = content.String()
	scriptBlock := scripts.String()
	open := strings.Index(scriptBlock, "<script>")
	closeIdx := strings.LastIndex(scriptBlock, "</script>")
	if open < 0 || closeIdx <= open {
		t.Fatalf("rendered scripts block has no inline script body:\n%s", scriptBlock)
	}
	script = scriptBlock[open+len("<script>") : closeIdx]

	// Guard the fixture itself: the assertions below are meaningless if the
	// rendered modal does not carry the paragraph and the download button.
	for _, token := range []string{
		`id="profileRegenerateNotice"`,
		`id="profileDownloadBtn"`,
		`id="configModal"`,
	} {
		if !strings.Contains(markup, token) {
			t.Fatalf("rendered modal markup is missing %s", token)
		}
	}
	if !strings.Contains(script, "function syncProfileNotice") {
		t.Fatal("rendered controller script has no syncProfileNotice; the fixture is wrong")
	}
	return markup, script
}

// noticeVisibilityScript drives the shipped modal renderer per protocol and
// prints one JSON result line. Every case starts from a freshly rendered page,
// except the last one, which deliberately reopens the same modal.
const noticeVisibilityScript = `%s
const html = '<!DOCTYPE html><html><body>' + %q + '</body></html>';

function state(w) {
    const notice = w.document.getElementById('profileRegenerateNotice');
    const btn = w.document.getElementById('profileDownloadBtn');
    const described = btn.getAttribute('aria-describedby');
    return {
        hidden: notice.hidden === true,
        display: w.getComputedStyle(notice).display,
        describedby: described,
        describedTargetHidden: described ? w.document.getElementById(described) === notice && notice.hidden : null,
        text: (notice.textContent || '').trim(),
    };
}

async function freshWindow() {
    const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'https://review.invalid' });
    const w = dom.window;
    w._ = k => k;
    w.UI = {
        toast: () => {},
        modal: { open: () => {}, close: () => {} },
        formatBytes: n => String(n),
        escapeHtml: s => String(s),
    };
    w.QRCode = function () { return {}; };
    w.API = { post: async () => ({ config: 'rendered-config', vpn_link: '' }) };
    const s = w.document.createElement('script');
    s.textContent = %q;
    w.document.body.appendChild(s);
    return w;
}

(async () => {
    const seen = {};

    const awg = await freshWindow();
    await awg.showMyConfig(1, 'awg-profile', 'awg');
    seen.awg = state(awg);

    const vless = await freshWindow();
    await vless.showMyConfig(2, 'vless-profile', 'vless');
    seen.vless = state(vless);

    const naive = await freshWindow();
    await naive.showMyConfig(3, 'naive-profile', 'naive');
    seen.naive = state(naive);

    const telemt = await freshWindow();
    await telemt.showMyConfig(4, 'mtproxyl-profile', 'telemt');
    seen.telemt = state(telemt);

    // Reopen the same modal twice: AmneziaWG, then VLESS, then AmneziaWG again.
    const reopened = await freshWindow();
    await reopened.showMyConfig(5, 'first-awg', 'awg');
    seen.reopenAwgFirst = state(reopened);
    await reopened.showMyConfig(6, 'then-vless', 'vless');
    seen.reopenVless = state(reopened);
    await reopened.showMyConfig(7, 'awg-again', 'awg');
    seen.reopenAwgAgain = state(reopened);

    for (const name of Object.keys(seen)) {
        const r = seen[name];
        console.log('VISIBILITY ' + name + ' hidden=' + r.hidden + ' display=' + r.display +
            ' describedby=' + String(r.describedby) + ' text=' + JSON.stringify(r.text));
    }
    console.log('VISIBILITY_RESULT ' + JSON.stringify(seen));
})().catch(e => {
    console.error(e && e.stack ? e.stack : String(e));
    process.exit(1);
});
`

type noticeVisibilityState struct {
	Hidden                bool    `json:"hidden"`
	Display               string  `json:"display"`
	DescribedBy           *string `json:"describedby"`
	DescribedTargetHidden *bool   `json:"describedTargetHidden"`
	Text                  string  `json:"text"`
}

func TestProfileNoticeVisibilityByProtocol(t *testing.T) {
	nodePath := requireJSDOM(t)
	markup, script := renderMyConnectionsModalPartsForNotice(t)

	out, err := execNodeScript(nodePath, fmt.Sprintf(noticeVisibilityScript, jsdomBootstrapSnippet, markup, script))
	if err != nil {
		t.Fatalf("JSDOM visibility run failed: %v\nOutput:\n%s", err, string(out))
	}
	outStr := string(out)
	if strings.Contains(outStr, "JSDOM_NOT_AVAILABLE") {
		t.Fatalf("jsdom is not available: %s", outStr)
	}

	const marker = "VISIBILITY_RESULT "
	idx := strings.Index(outStr, marker)
	if idx < 0 {
		t.Fatalf("visibility run produced no result line:\n%s", outStr)
	}
	line := outStr[idx+len(marker):]
	if end := strings.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	var seen map[string]noticeVisibilityState
	if err := json.Unmarshal([]byte(line), &seen); err != nil {
		t.Fatalf("parse visibility result %q: %v", line, err)
	}
	for _, row := range strings.Split(outStr, "\n") {
		if strings.HasPrefix(row, "VISIBILITY ") {
			t.Log(row)
		}
	}

	requireShown := func(name string) {
		t.Helper()
		state, ok := seen[name]
		if !ok {
			t.Fatalf("no result for %q; the scenario did not run", name)
		}
		if state.Hidden {
			t.Errorf("%s: the statement is hidden for an AmneziaWG profile", name)
		}
		if state.Display == "none" {
			t.Errorf("%s: computed display is none for an AmneziaWG profile", name)
		}
		if state.DescribedBy == nil || *state.DescribedBy != "profileRegenerateNotice" {
			t.Errorf("%s: aria-describedby = %v, want profileRegenerateNotice", name, state.DescribedBy)
		}
		if state.DescribedTargetHidden == nil || *state.DescribedTargetHidden {
			t.Errorf("%s: the description link does not resolve to the visible statement paragraph", name)
		}
		if strings.TrimSpace(state.Text) == "" {
			t.Errorf("%s: the statement carries no text", name)
		}
	}

	requireHidden := func(name string) {
		t.Helper()
		state, ok := seen[name]
		if !ok {
			t.Fatalf("no result for %q; the scenario did not run", name)
		}
		if !state.Hidden {
			t.Errorf("%s: the statement is visible for a protocol that never used the gateway resolver", name)
		}
		if state.Display != "none" {
			t.Errorf("%s: computed display = %q, want none", name, state.Display)
		}
		if state.DescribedBy != nil {
			t.Errorf("%s: aria-describedby points at %q while the statement is hidden", name, *state.DescribedBy)
		}
	}

	requireShown("awg")
	requireHidden("vless")
	requireHidden("naive")
	requireHidden("telemt")

	// Same modal, three different profiles: the flag must follow the profile
	// being shown, not the previous one.
	requireShown("reopenAwgFirst")
	requireHidden("reopenVless")
	requireShown("reopenAwgAgain")
}
