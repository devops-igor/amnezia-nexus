package web

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var notificationTemplateKeyPattern = regexp.MustCompile(`_ "(notifications_[a-z_]+)"`)

func TestNotificationsSettingsTemplateContract(t *testing.T) {
	templateBytes, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings template: %v", err)
	}
	partialBytes, err := TemplatesFS.ReadFile("templates/settings_notifications.html")
	if err != nil {
		t.Fatalf("read notification settings partial: %v", err)
	}
	templateText := string(templateBytes)
	cardText := string(partialBytes)

	requiredIDs := []string{
		"notificationsCard",
		"notificationSettingsForm",
		"notifications_enabled",
		"notificationFields",
		"notifications_url",
		"notifications_token",
		"notifications_min_severity",
		"notifications_cooldown",
		"notificationSaveBtn",
		"notificationSaveBtnText",
		"notificationSaveSpinner",
		"notificationTestBtn",
		"notificationTestBtnText",
		"notificationTestSpinner",
		"notificationTestResult",
		"notificationHistory",
	}
	for _, id := range requiredIDs {
		if !strings.Contains(cardText, `id="`+id+`"`) {
			t.Errorf("notification partial is missing element %q", id)
		}
	}
	if !strings.Contains(templateText, `/static/js/notifications_settings.js?v={{ .app_version }}`) {
		t.Error("notification module must load with a cache-busting version parameter")
	}
	if !strings.Contains(cardText, `{{ if is_admin .current_user }}`) {
		t.Error("notification card must be guarded by the admin role")
	}
	for _, category := range []string{"server_health", "backend_health", "provisioning", "updates", "failover"} {
		if !strings.Contains(cardText, `data-category="`+category+`"`) {
			t.Errorf("notification partial is missing category toggle %q", category)
		}
	}

	moduleBytes, err := StaticFS.ReadFile("static/js/notifications_settings.js")
	if err != nil {
		t.Fatalf("read notification module: %v", err)
	}
	moduleText := string(moduleBytes)
	used := map[string]bool{}
	for _, templateSource := range []string{templateText, cardText} {
		for _, match := range notificationTemplateKeyPattern.FindAllStringSubmatch(templateSource, -1) {
			used[match[1]] = true
		}
	}
	moduleKeyPattern := regexp.MustCompile(`translate\('(notifications_[a-z_]+)'`)
	for _, match := range moduleKeyPattern.FindAllStringSubmatch(moduleText, -1) {
		// Dynamic keys such as 'notifications_status_' + status are covered by
		// the explicit status keys below rather than this static scan.
		if strings.HasSuffix(match[1], "_") {
			continue
		}
		used[match[1]] = true
	}
	for _, status := range []string{"sent", "pending", "uncertain", "failed", "suppressed", "dropped"} {
		used["notifications_status_"+status] = true
	}
	for _, language := range []string{"en", "fr", "ru", "zh", "fa"} {
		dictionaryBytes, err := TranslationsFS.ReadFile("translations/" + language + ".json")
		var dictionary map[string]string
		if err == nil {
			err = json.Unmarshal(dictionaryBytes, &dictionary)
		}
		if err != nil {
			t.Fatalf("read %s translations: %v", language, err)
		}
		for key := range used {
			if value, ok := dictionary[key]; !ok || strings.TrimSpace(value) == "" {
				t.Errorf("translation %s is missing %q", language, key)
			}
		}
	}
}

func TestNotificationsSettingsModuleBehaviour(t *testing.T) {
	nodePath := requireJSDOM(t)
	moduleBytes, err := StaticFS.ReadFile("static/js/notifications_settings.js")
	if err != nil {
		t.Fatalf("read module: %v", err)
	}
	encodedModule, _ := json.Marshal(string(moduleBytes))

	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const markup = `+"`"+`
<div id="notificationsCard">
  <input type="checkbox" id="notifications_enabled">
  <div id="notificationFields">
    <input id="notifications_url">
    <input type="password" id="notifications_token">
    <select id="notifications_min_severity"><option value="info">i</option><option value="warning">w</option><option value="critical">c</option></select>
    <input type="number" id="notifications_cooldown">
    <input type="checkbox" class="notification-category" data-category="server_health">
    <input type="checkbox" class="notification-category" data-category="backend_health">
    <input type="checkbox" class="notification-category" data-category="provisioning">
    <input type="checkbox" class="notification-category" data-category="updates">
    <input type="checkbox" class="notification-category" data-category="failover">
  </div>
  <button id="notificationSaveBtn"><span id="notificationSaveBtnText"></span><div id="notificationSaveSpinner" class="hidden"></div></button>
  <button id="notificationTestBtn"><span id="notificationTestBtnText"></span><div id="notificationTestSpinner" class="hidden"></div></button>
  <p id="notificationTestResult"></p>
  <div id="notificationHistory"></div>
</div>`+"`"+`;
const dom = new JSDOM(markup, {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
const toasts = [];
w.UI = {toast:(text,kind)=>toasts.push({text,kind})};

let resolveRead;
const readGate = new Promise(resolve => { resolveRead = resolve; });
const posts = [];
const settingsAnswer = {
  enabled:true, url:'https://gotify.example.test', app_token_set:true,
  min_severity:'warning', cooldown_seconds:30, max_attempts:4,
  categories:{server_health:true, backend_health:false, provisioning:true, updates:true, failover:true}
};
w.API = {
  get: async url => {
    if (url.indexOf('/api/notifications/settings') === 0) return readGate;
    if (url.indexOf('/api/notifications/history') === 0) {
      return {events:[{event:{summary:'<img src=x onerror=evil()>',severity:'warning',category:'server_health',occurred_at:'2026-11-17T10:00:00Z'},
        delivery:{status:'sent',last_error:''}}]};
    }
    throw new Error('unexpected GET ' + url);
  },
  post: async (url, body) => {
    posts.push({url, body});
    if (url === '/api/notifications/settings') return Object.assign({}, settingsAnswer, body, {app_token_set:true});
    if (url === '/api/notifications/test') return {status:'sent'};
    throw new Error('unexpected POST ' + url);
  }
};

w.eval(%s);
(async()=>{
  const ui = w.NotificationSettingsUI;

  // A mutation attempted before the initial read settles must not submit
  // markup defaults over the stored policy.
  const early = await ui.save();
  assert.equal(early, false, 'save before load must be refused');
  assert.equal(posts.length, 0, 'no POST may happen before the read resolves');

  resolveRead(settingsAnswer);
  await new Promise(resolve => w.setTimeout(resolve, 15));
  assert.equal(w.document.getElementById('notifications_enabled').checked, true);
  assert.equal(w.document.getElementById('notifications_url').value, 'https://gotify.example.test');
  assert.equal(w.document.getElementById('notifications_token').value, '');
  assert.equal(w.document.getElementById('notifications_token').placeholder, '********');
  assert.equal(w.document.getElementById('notifications_min_severity').value, 'warning');
  assert.equal(w.document.getElementById('notifications_cooldown').value, '30');
  const categories = Array.from(w.document.querySelectorAll('.notification-category'));
  assert.equal(categories.find(c => c.getAttribute('data-category') === 'backend_health').checked, false);
  assert.equal(categories.find(c => c.getAttribute('data-category') === 'server_health').checked, true);

  // History is rendered as text: an event summary is untrusted input.
  const history = w.document.getElementById('notificationHistory');
  assert.ok(history.textContent.indexOf('<img src=x onerror=evil()>') !== -1);
  assert.equal(history.querySelector('img'), null);

  // Saving posts the visible policy and leaves the token blank to preserve it.
  const saved = await ui.save(true);
  assert.equal(saved, true);
  const savePost = posts.find(p => p.url === '/api/notifications/settings');
  assert.equal(savePost.body.app_token, '');
  assert.equal(savePost.body.max_attempts, 4);
  assert.equal(savePost.body.cooldown_seconds, 30);

  // A test saves first, then sends through the API and reports the real result.
  const beforeTest = posts.length;
  await ui.testConnection();
  assert.equal(posts.length, beforeTest + 2, 'test must save then send');
  assert.equal(posts[posts.length - 1].url, '/api/notifications/test');
  assert.match(w.document.getElementById('notificationTestResult').textContent, /accepted/i);
  console.log('NOTIFICATIONS_UI_OK');
})().catch(err => { console.error(err && err.stack || err); process.exit(1); });
`, encodedModule)

	out, err := execNodeScript(nodePath, script)
	if err != nil {
		t.Fatalf("notification module scenario failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "NOTIFICATIONS_UI_OK") {
		t.Fatalf("scenario did not complete: %s", out)
	}
}
