package web

import (
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// settingsScriptPath is the page script the settings template loads. It is the
// code that used to sit in an inline script block at the end of settings.html.
const settingsScriptPath = "static/js/settings.js"

// templateScriptRefOffsets returns where src loads path as a script, in document
// order, whatever cache identity the tag declares for it.
//
// A shell names a module either literally with the release version or through
// asset_url when the module's bytes move with a delivery. Both spellings are the
// same reference to the same module, so a matcher pinned to one of them reports
// a module that is loaded as absent and an order assertion built on it fails for
// a reason that has nothing to do with order. Locating the reference through the
// tag classifier the asset-identity checks already use keeps presence and load
// order asserted against the reference rather than against one spelling of its
// query: a module that is absent, or that loads after the page script, still
// fails. The path must match exactly, so a neighbouring module whose name begins
// the same way is not mistaken for it.
func templateScriptRefOffsets(src, path string) []int {
	var offsets []int
	for _, loc := range assetTagPattern.FindAllStringIndex(src, -1) {
		tag := src[loc[0]:loc[1]]
		if !strings.HasPrefix(tag, "<script") {
			continue
		}
		if named, _, _, ok := classifyAssetTag(tag); ok && named == path {
			offsets = append(offsets, loc[0])
		}
	}
	return offsets
}

// settingsTemplateText returns the settings page markup: the page shell followed
// by every section file under templates/settings/, in name order. Tests that
// assert on markup read it instead of settings.html alone, because the sections
// live in their own files.
func settingsTemplateText(t *testing.T) string {
	t.Helper()
	shell, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings template: %v", err)
	}
	entries, err := fs.ReadDir(TemplatesFS, "templates/settings")
	if err != nil {
		t.Fatalf("list settings sections: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	var text strings.Builder
	text.Write(shell)
	// The commit control, dirty badge and feedback regions every card shares.
	shared, err := TemplatesFS.ReadFile("templates/settings_save_controls.html")
	if err != nil {
		t.Fatalf("read shared save controls: %v", err)
	}
	text.WriteString("\n")
	text.Write(shared)
	for _, name := range names {
		section, err := TemplatesFS.ReadFile("templates/settings/" + name)
		if err != nil {
			t.Fatalf("read settings section %s: %v", name, err)
		}
		text.WriteString("\n")
		text.Write(section)
	}
	return text.String()
}

// serversHostingTemplateText returns the markup of the page that hosts the hosting
// controls: the Servers shell, the hosting card it includes, and the shared save
// controls that card renders. The controls moved off Settings with the card, so a test
// about them reads this rather than the Settings surface.
func serversHostingTemplateText(t *testing.T) string {
	t.Helper()
	var text strings.Builder
	for _, path := range []string{
		"templates/index.html",
		"templates/servers_hosting.html",
		"templates/settings_save_controls.html",
	} {
		body, err := TemplatesFS.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text.Write(body)
		text.WriteString("\n")
	}
	return text.String()
}

// hostingPageScript returns the hosting card's controller as the browser receives it.
// It is the half of the Settings page script that moved with the card.
func hostingPageScript(t *testing.T) string {
	t.Helper()
	script, err := StaticFS.ReadFile("static/js/gigahost_hosting.js")
	if err != nil {
		t.Fatalf("read the hosting controller: %v", err)
	}
	if strings.TrimSpace(string(script)) == "" {
		t.Fatal("the hosting controller is empty")
	}
	return string(script)
}

// settingsPageScript returns the settings page script as the browser receives it.
func settingsPageScript(t *testing.T) string {
	t.Helper()
	script, err := StaticFS.ReadFile(settingsScriptPath)
	if err != nil {
		t.Fatalf("read settings page script: %v", err)
	}
	if strings.TrimSpace(string(script)) == "" {
		t.Fatal("settings page script is empty")
	}
	return string(script)
}

// hostingScriptPath is the controller the Servers shell loads for the hosting card.
const hostingScriptPath = "static/js/gigahost_hosting.js"

// TestServersShellLoadsHostingModulesBeforeTheHostingController pins the structure of the
// relocation: the hosting card is included once by the Servers shell, its controller runs
// after every module whose globals it calls, and the Settings shell loads none of them.
func TestServersShellLoadsHostingModulesBeforeTheHostingController(t *testing.T) {
	shellBytes, err := TemplatesFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatalf("read the servers shell: %v", err)
	}
	shell := string(shellBytes)
	cardBytes, err := TemplatesFS.ReadFile("templates/servers_hosting.html")
	if err != nil {
		t.Fatalf("read the hosting card: %v", err)
	}
	card := string(cardBytes)
	settingsBytes, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read the settings shell: %v", err)
	}
	settingsShell := string(settingsBytes)

	if got := strings.Count(shell, `{{ template "servers_hosting" . }}`); got != 1 {
		t.Errorf("the servers shell includes the hosting card %d times, want 1", got)
	}
	// The credential card keeps the id the settings save model publishes against, so the
	// relocated form still commits through the shipped save path.
	if !strings.Contains(card, `id="gigahostCard"`) || !strings.Contains(card, `data-settings-card="gigahost"`) {
		t.Error("the hosting card lost the id and section the settings save model addresses")
	}

	controllerRefs := templateScriptRefOffsets(shell, "/"+hostingScriptPath)
	if len(controllerRefs) == 0 {
		t.Fatal("the servers shell does not load the hosting controller")
	}
	if len(controllerRefs) != 1 {
		t.Errorf("the servers shell loads the hosting controller %d times, want 1", len(controllerRefs))
	}
	modules := []string{
		"settings_cards.js", "settings_save.js", "gigahost_catalog_status.js",
		"gigahost_setup.js", "gigahost_setup_intents.js", "gigahost_order_status_model.js",
		"gigahost_order_status.js", "gigahost_placement.js", "gigahost_account_association.js",
	}
	for _, module := range modules {
		refs := templateScriptRefOffsets(shell, "/static/js/"+module)
		if len(refs) == 0 || refs[0] > controllerRefs[0] {
			t.Errorf("module %s must load before the hosting controller", module)
		}
	}

	// The block is gone from Settings, controllers included: a module left behind would
	// keep running against a page whose card it binds no longer exists. The shared save
	// model stays on Settings, where the other cards still commit through it.
	hostingModules := []string{"gigahost_hosting.js", "gigahost_catalog_status.js", "gigahost_setup.js",
		"gigahost_setup_intents.js", "gigahost_order_status_model.js", "gigahost_order_status.js",
		"gigahost_placement.js", "gigahost_account_association.js"}
	for _, module := range hostingModules {
		if refs := templateScriptRefOffsets(settingsShell, "/static/js/"+module); len(refs) != 0 {
			t.Errorf("the settings shell still loads %s", module)
		}
	}
	for _, action := range []string{`templates/settings/gigahost.html`, `{{ template "settings_gigahost" . }}`} {
		if strings.Contains(settingsShell, action) {
			t.Errorf("the settings shell still carries the hosting block: %s", action)
		}
	}
}

// TestSettingsPageSplitContract pins the structure of the split: the shell holds
// no inline script, loads the page script after every module it depends on, and
// includes each section file exactly once.
func TestSettingsPageSplitContract(t *testing.T) {
	shellBytes, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings template: %v", err)
	}
	shell := string(shellBytes)

	entries, err := fs.ReadDir(TemplatesFS, "templates/settings")
	if err != nil {
		t.Fatalf("list settings sections: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no settings section files found")
	}
	for _, entry := range entries {
		body, err := TemplatesFS.ReadFile("templates/settings/" + entry.Name())
		if err != nil {
			t.Fatalf("read settings section %s: %v", entry.Name(), err)
		}
		if strings.Contains(string(body), "<script") {
			t.Errorf("settings section %s must not contain a script element", entry.Name())
		}
		name := "settings_" + strings.TrimSuffix(entry.Name(), ".html")
		if !strings.Contains(string(body), `{{- define "`+name+`" -}}`) {
			t.Errorf("settings section %s must define %q", entry.Name(), name)
		}
		if got := strings.Count(shell, `{{ template "`+name+`" . }}`); got != 1 {
			t.Errorf("settings shell includes %q %d times, want 1", name, got)
		}
	}

	// No inline script: every script element in the shell has a src attribute.
	for offset := 0; ; {
		start := strings.Index(shell[offset:], "<script")
		if start < 0 {
			break
		}
		start += offset
		tagEnd := strings.Index(shell[start:], ">")
		if tagEnd < 0 {
			t.Fatal("unterminated script tag in settings shell")
		}
		if !strings.Contains(shell[start:start+tagEnd], "src=") {
			t.Error("settings shell must not contain an inline script block")
		}
		offset = start + tagEnd
	}

	// The page script runs after every module whose globals it calls. Each
	// reference is located in whichever identity form the shell declares, so a
	// module this delivery moved onto its own bytes is still found and still has
	// to load first.
	pageScriptRefs := templateScriptRefOffsets(shell, "/"+settingsScriptPath)
	if len(pageScriptRefs) == 0 {
		t.Fatal("settings shell does not load the page script")
	}
	if len(pageScriptRefs) != 1 {
		t.Error("settings shell must load the page script exactly once")
	}
	for _, module := range []string{
		"notifications_settings.js",
	} {
		refs := templateScriptRefOffsets(shell, "/static/js/"+module)
		if len(refs) == 0 || refs[0] > pageScriptRefs[0] {
			t.Errorf("module %s must load before the page script", module)
		}
	}

	// The save model's two scripts load before anything that reports through them.
	for _, module := range []string{"settings_cards.js", "settings_save.js"} {
		refs := templateScriptRefOffsets(shell, "/static/js/"+module)
		first := templateScriptRefOffsets(shell, "/static/js/notifications_settings.js")
		if len(refs) == 0 || len(first) == 0 || refs[0] > first[0] {
			t.Errorf("module %s must load before the notification controller", module)
		}
	}

	// The handlers the markup names must exist as globals in the page script.
	// saveSettings is gone on purpose: every card commits through its own control.
	pageScript := settingsPageScript(t)
	if strings.Contains(pageScript, "function saveSettings(") {
		t.Error("the page-level saveSettings handler must not return")
	}
	for _, handler := range []string{"handleRestore", "checkUpstreamStatus"} {
		if !strings.Contains(pageScript, "function "+handler+"(") {
			t.Errorf("page script does not define %s", handler)
		}
	}
}
