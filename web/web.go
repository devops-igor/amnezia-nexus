package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var StaticFS embed.FS

//go:embed templates/*
var TemplatesFS embed.FS

//go:embed translations/*
var TranslationsFS embed.FS

// GetStaticSubFS returns the subtree of StaticFS rooted at "static".
func GetStaticSubFS() (fs.FS, error) {
	return fs.Sub(StaticFS, "static")
}

// GetTranslationsSubFS returns the subtree of TranslationsFS rooted at "translations".
func GetTranslationsSubFS() (fs.FS, error) {
	return fs.Sub(TranslationsFS, "translations")
}

// GetTemplatesSubFS returns the subtree of TemplatesFS rooted at "templates".
func GetTemplatesSubFS() (fs.FS, error) {
	return fs.Sub(TemplatesFS, "templates")
}

// LayoutPartials are the template files that only define sections included by a layout
// page: settings_policy.html is rendered by settings.html, settings/gigahost.html by the
// Settings group, servers_deployments.html by the Servers page, and so on.
//
// A Go template resolves its includes when it executes, not when it parses, so anything
// that renders a page has to parse these files beside base.html and the page itself. The
// application's engine is one such consumer and the tests that execute a page to inspect
// the document it produces are another; keeping the list here, beside the embedded
// templates, is what stops the two from disagreeing about which files make up a page. A
// page that includes a section this list omits cannot execute at all, in either consumer.
var LayoutPartials = []string{
	"servers_deployments.html",
	"settings_policy.html",
	"settings_policy_client.html",
	"settings_notifications.html",
	"settings_save_controls.html",
	"settings/appearance.html",
	"settings/captcha.html",
	"settings/telegram.html",
	"settings/ssl.html",
	"settings/limits.html",
	"settings/backup.html",
	"settings/upstream_components.html",
	"settings/gigahost.html",
}
