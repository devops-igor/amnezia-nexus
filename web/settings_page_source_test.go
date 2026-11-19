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

	// The page script runs after every module whose globals it calls.
	script := `src="` + "/" + settingsScriptPath
	scriptAt := strings.Index(shell, script)
	if scriptAt < 0 {
		t.Fatal("settings shell does not load the page script")
	}
	if strings.Count(shell, script) != 1 {
		t.Error("settings shell must load the page script exactly once")
	}
	for _, module := range []string{
		"notifications_settings.js", "gigahost_catalog_status.js", "gigahost_setup.js",
		"gigahost_setup_intents.js", "gigahost_order_status_model.js",
		"gigahost_order_status.js", "gigahost_placement.js",
	} {
		at := strings.Index(shell, `src="/static/js/`+module)
		if at < 0 || at > scriptAt {
			t.Errorf("module %s must load before the page script", module)
		}
	}

	// The save model's two scripts load before anything that reports through them.
	for _, module := range []string{"settings_cards.js", "settings_save.js"} {
		at := strings.Index(shell, `src="/static/js/`+module)
		first := strings.Index(shell, `src="/static/js/notifications_settings.js`)
		if at < 0 || at > first {
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
