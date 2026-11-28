package handlers

// Harness for the per-card save model tests (#888).
//
// The page is not reimplemented here. The test renders /settings through the
// real handler, reads the script elements from that HTML in document order,
// loads each one from the embedded static files, and runs them in JSDOM with a
// fetch that answers like the panel. The real api.js and ui.js are loaded, so a
// request that fails without opting out of the global toast raises exactly the
// toast an operator would see.
//
// Because the script list comes from the rendered page, the same test also runs
// against an older revision of the page and fails there for the behavioural
// reason, not because a file is missing.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

var settingsScriptSrc = regexp.MustCompile(`<script[^>]+src="([^"]+)"`)

// settingsPageScripts returns the static scripts the rendered page loads, in
// order, as {path, source} pairs. Scripts the harness does not need are skipped.
func settingsPageScripts(t *testing.T, page string) [][2]string {
	t.Helper()
	skip := map[string]bool{"qrcode.min.js": true, "telemetry.js": true, "tables.js": true}
	var out [][2]string
	for _, m := range settingsScriptSrc.FindAllStringSubmatch(page, -1) {
		path := strings.SplitN(m[1], "?", 2)[0]
		if skip[path[strings.LastIndex(path, "/")+1:]] {
			continue
		}
		body, err := web.StaticFS.ReadFile(strings.TrimPrefix(path, "/"))
		if err != nil {
			t.Fatalf("the rendered page loads %s, which is not embedded: %v", path, err)
		}
		out = append(out, [2]string{path, string(body)})
	}
	return out
}

// settingsHarnessHead builds the JSDOM page from the rendered HTML and loads the
// scripts in the order the page loads them. fetch is the real panel over HTTP.
const settingsHarnessHead = `
const {VirtualConsole} = require('jsdom');
const vc = new VirtualConsole();
vc.on('jsdomError', () => {});
const dom = new JSDOM(CFG.page, {runScripts: 'outside-only', url: CFG.base + CFG.path, virtualConsole: vc});
const w = dom.window;
const doc = w.document;
w.I18N = CFG.dict;
w._ = k => w.I18N[k] || k;
const realFetch = fetch;
let saveGate = null;
let saveHeld = 0;
let failSave = false;
// holdWhen(url, opts) may return a promise a request waits on; failWhen(url, opts)
// makes it fail like a dropped connection. Both see every request the page makes.
let holdWhen = null;
let failWhen = null;
let refuseWhen = null;
let held = 0;
const isPost = o => String((o && o.method) || 'GET').toUpperCase() === 'POST';
// The two policy cards talk to an endpoint the handler fixture does not mount, so
// a small in-memory double answers it. policyRefuse makes the next PUT a 422.
const policyDouble = {
  refuse: false,
  puts: [],
  record: {enabled: false, proxy_exceptions: [], inventory_override: [],
    sync_interval_seconds: 21600,
    status: {enabled: false, cidr_count: 0, sync_state: 'disabled'}}
};
const jsonResponse = (body, status) => new Response(JSON.stringify(body), {status: status || 200, headers: {'content-type': 'application/json'}});
function policyAnswer(u, o) {
  const path = String(u).split('?')[0];
  const method = String((o && o.method) || 'GET').toUpperCase();
  if (path === '/api/vpn/policy/stats') return jsonResponse({proxy_bytes: 0, direct_bytes: 0, proxy_drops: 0, direct_drops: 0});
  if (path !== '/api/vpn/policy') return null;
  if (method === 'PUT') {
    const body = JSON.parse(o.body);
    policyDouble.puts.push(body);
    if (policyDouble.refuse) return jsonResponse({error: 'activation_failed', detail: 'direct egress is unavailable'}, 422);
    policyDouble.record = Object.assign({}, policyDouble.record, body, {status: {enabled: body.enabled, sync_state: 'disabled'}});
    return jsonResponse(Object.assign({status: 'ok', policy_status: policyDouble.record.status}, policyDouble.record));
  }
  return jsonResponse(policyDouble.record);
}
w.fetch = async (u, o) => {
  const isSave = String(u).indexOf('/api/settings/save') === 0;
  if (isSave && failSave) throw new TypeError('Failed to fetch');
  if (isSave && saveGate) { saveHeld++; await saveGate; }
  if (failWhen && failWhen(u, o)) throw new TypeError('Failed to fetch');
  if (holdWhen) { const gate = holdWhen(u, o); if (gate) { held++; await gate; } }
  // refuseWhen answers like a server that looked at the request and said no. It is
  // applied after any hold, so a request can be slow and then refused. The real
  // handler is not reached, which is the point: the page must treat any refusal the
  // same way, whichever card sent it.
  if (refuseWhen && refuseWhen(u, o)) return jsonResponse({error: 'validation_failed', detail: 'refused by the test'}, 422);
  const fake = policyAnswer(u, o);
  if (fake) return fake;
  return realFetch(CFG.base + u, o);
};
for (const s of CFG.scripts) { w.eval(s.source); }
const toasts = [];
const originalToast = w.UI.toast;
w.UI.toast = (message, type, duration) => { toasts.push({message, type}); return originalToast(message, type, duration); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, label, ms) {
  const end = Date.now() + (ms || 4000);
  while (Date.now() < end) { if (fn()) return; await sleep(20); }
  throw new Error('timed out waiting for ' + label);
}
// openTab starts a second, independent page against the same server: its own
// window, scripts and fetch, so it behaves like another browser tab. Its saves
// are never held. The returned helpers mirror the ones above for that window.
async function openTab() {
  const vc2 = new VirtualConsole();
  vc2.on('jsdomError', () => {});
  const d2 = new JSDOM(CFG.page, {runScripts: 'outside-only', url: CFG.base + CFG.path, virtualConsole: vc2});
  const w2 = d2.window;
  w2.I18N = CFG.dict;
  w2._ = k => w2.I18N[k] || k;
  w2.fetch = (u, o) => realFetch(CFG.base + u, o);
  for (const s of CFG.scripts) { w2.eval(s.source); }
  await new Promise(r => { if (w2.document.readyState === 'complete') r(); else w2.addEventListener('load', r); });
  await sleep(500);
  const d = w2.document;
  return {
    w: w2,
    type(id, value) { const el = d.getElementById(id); el.value = value; el.dispatchEvent(new w2.Event('input', {bubbles: true})); },
    toggle(id, on) { const el = d.getElementById(id); el.checked = on; el.dispatchEvent(new w2.Event('change', {bubbles: true})); },
    commit(id) { d.getElementById(id).querySelector('[data-commit]').click(); },
    status(id) { return d.getElementById(id).querySelector('[data-status]'); },
    close() { w2.close(); }
  };
}
const card = id => doc.getElementById(id);
const commitOf = id => card(id).querySelector('[data-commit]');
const badgeOf = id => card(id).querySelector('[data-dirty]');
const statusOf = id => card(id).querySelector('[data-status]');
const errorOf = id => card(id).querySelector('[data-error]');
const shown = el => !!el && !el.hidden && !el.classList.contains('hidden') && el.textContent.trim() !== '';
function type(id, value) {
  const el = doc.getElementById(id);
  el.value = value;
  el.dispatchEvent(new w.Event('input', {bubbles: true}));
}
function toggle(id, on) {
  const el = doc.getElementById(id);
  el.checked = on;
  el.dispatchEvent(new w.Event('change', {bubbles: true}));
}
async function stored() { return (await realFetch(CFG.base + '/api/settings')).json(); }
const settled = () => sleep(250);
// The page is ready once load has fired and the controllers have made their first reads.
const ready = new Promise(r => {
  if (doc.readyState === 'complete') r(); else w.addEventListener('load', r);
}).then(() => sleep(500));
`

// seedSettingsForPage stores a known starting point, including write-only
// secrets, so a test can tell a preserved value from a wiped one.
func seedSettingsForPage(t *testing.T, h *Handlers) {
	t.Helper()
	ctx := context.Background()
	seed := map[string]any{
		"appearance": models.AppearanceSettings{Title: "Seed Title", Logo: "S", Subtitle: "Seed Sub", Language: "en"},
		"captcha":    models.CaptchaSettings{Enabled: false},
		"limits":     models.ConnectionLimits{MaxConnectionsPerUser: 10, ConnectionRateLimitCount: 5, ConnectionRateLimitWindow: 60},
		"ssl": models.SSLSettings{
			Enabled: false, Domain: "seed.example.test", PanelPort: 5000,
			CertText: probeCertText, KeyText: probeKeyText,
		},
		"telegram": map[string]any{"enabled": true, "bot_token": probeBotToken, "chat_id": "-100seed"},
	}
	for key, value := range seed {
		if err := h.db.SetSetting(ctx, key, value); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
}

// settingsHarnessOptions selects what the harness server mounts beyond the
// default. By default the notification read is the one injected failure: the
// handler fixture always builds a notification service, so the real handler
// answers 200, and the route returns the 503 the handler itself sends when that
// service is absent, so the page meets a second unrelated subsystem failure
// during load. liveNotifications routes the real notification handlers instead,
// for tests that need that card to load and save.
//
// storeBeforeRender replaces stored sections after the standard seed and before
// the page is rendered, so a card can be loaded with a value its markup would
// reject as an entry. That is a state this build defines: an empty appearance
// field means "use the built-in one" and a zero connection limit means "use the
// default", and the rendered inputs show exactly what storage holds.
type settingsHarnessOptions struct {
	liveNotifications bool
	storeBeforeRender map[string]any
	// path is the page a scenario runs against: "" is /settings, and "/routing"
	// is the page the policy cards moved to (#987). The cards a page renders are
	// the cards a scenario may drive, so a scenario about a moved card declares
	// where it lives instead of the harness guessing.
	path string
}

// pagePath is the path the scenario renders and the URL its window reports.
func (o settingsHarnessOptions) pagePath() string {
	if o.path == "" {
		return "/settings"
	}
	return o.path
}

// settingsHarnessServerWith exposes the settings and hosting handlers over HTTP as
// an administrator. The settings and catalog handlers are the real ones: with no
// provider key configured the catalog handler answers 400, which is the hosting
// error an appearance save used to surface.
func settingsHarnessServerWith(t *testing.T, h *Handlers, opts settingsHarnessOptions) *httptest.Server {
	t.Helper()
	t.Setenv("GIGAHOST_API_KEY", "")
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := middleware.WithSession(req.Context(), &models.SessionData{
				UserID: "admin-1", Username: "admin", Role: models.RoleAdmin,
			})
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Get("/api/settings", h.GetSettingsHandler)
	r.Post("/api/settings/save", h.SaveSettingsHandler)
	r.Get("/api/admin/hosting/gigahost/catalog", h.GigahostCatalogHandler)
	if opts.liveNotifications {
		r.Get("/api/notifications/settings", h.GetNotificationSettingsHandler)
		r.Post("/api/notifications/settings", h.SaveNotificationSettingsHandler)
		r.Get("/api/notifications/history", h.GetNotificationHistoryHandler)
	} else {
		r.Get("/api/notifications/settings", func(w http.ResponseWriter, _ *http.Request) {
			h.JSONError(w, http.StatusServiceUnavailable, "notifications_unavailable", "Notification service is not configured")
		})
	}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

// runSettingsScenario renders the real /settings page, loads the scripts that
// page names, and runs scenario against it. The scenario is the body of an
// async function with the helpers from settingsHarnessHead in scope.
func runSettingsScenario(t *testing.T, h *Handlers, scenario string) string {
	t.Helper()
	return runSettingsScenarioWith(t, h, settingsHarnessOptions{}, scenario)
}

// runRoutingScenario is runSettingsScenario against the Routing page: the same
// harness, the same real modules, on the page the cards it drives now render.
func runRoutingScenario(t *testing.T, h *Handlers, scenario string) string {
	t.Helper()
	return runSettingsScenarioWith(t, h, settingsHarnessOptions{path: "/routing"}, scenario)
}

// runHostingScenario is runSettingsScenario against the Servers page: the page the
// hosting card and the credential commit it owns now render on.
func runHostingScenario(t *testing.T, h *Handlers, scenario string) string {
	t.Helper()
	return runSettingsScenarioWith(t, h, settingsHarnessOptions{path: "/"}, scenario)
}

// runSettingsScenarioWith is runSettingsScenario with the harness server options.
func runSettingsScenarioWith(t *testing.T, h *Handlers, opts settingsHarnessOptions, scenario string) string {
	t.Helper()
	node := gigahostOrderStatusNode(t)
	seedSettingsForPage(t, h)
	for key, value := range opts.storeBeforeRender {
		if err := h.db.SetSetting(context.Background(), key, value); err != nil {
			t.Fatalf("store %s before render: %v", key, err)
		}
	}
	var page string
	switch opts.pagePath() {
	case "/routing":
		page = renderRoutingPageFor(t, h, models.RoleAdmin)
	case "/":
		page = renderServersPageAs(t, h, models.RoleAdmin)
	default:
		page = renderSettingsPageFor(t, h, models.RoleAdmin)
	}
	srv := settingsHarnessServerWith(t, h, opts)

	enRaw, err := web.TranslationsFS.ReadFile("translations/en.json")
	if err != nil {
		t.Fatalf("read en dictionary: %v", err)
	}
	var dict map[string]string
	if err := json.Unmarshal(enRaw, &dict); err != nil {
		t.Fatalf("decode en dictionary: %v", err)
	}
	var scripts []map[string]string
	for _, s := range settingsPageScripts(t, page) {
		scripts = append(scripts, map[string]string{"path": s[0], "source": s[1]})
	}
	cfg, err := json.Marshal(map[string]any{
		"page": page, "base": srv.URL, "dict": dict, "scripts": scripts, "path": opts.pagePath(),
	})
	if err != nil {
		t.Fatalf("encode harness config: %v", err)
	}
	// The configuration is large, so it travels by file: one environment string
	// is capped well below the size of the page and its scripts.
	cfgPath := filepath.Join(t.TempDir(), "harness.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatalf("write harness config: %v", err)
	}

	script := gigahostOrderStatusJSDOMBootstrap +
		"\nconst CFG = JSON.parse(fs.readFileSync(process.env.SETTINGS_HARNESS_CFG, 'utf8'));\n" +
		settingsHarnessHead +
		"\n(async () => {\nawait ready;\n" + scenario +
		"\nconsole.log('SETTINGS_SCENARIO_OK');\nw.close();\nprocess.exit(0);\n})().catch(err => { console.error(err && err.stack || err); process.exit(1); });\n"

	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "SETTINGS_HARNESS_CFG="+cfgPath)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
		t.Skip("jsdom is not available in this Node environment")
	}
	if err != nil || !strings.Contains(string(out), "SETTINGS_SCENARIO_OK") {
		t.Fatalf("settings scenario failed: %v\n%s", err, out)
	}
	return string(out)
}
