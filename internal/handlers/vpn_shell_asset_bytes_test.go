package handlers

// The layout stylesheet and the modal script changed in this delivery, so a returning
// browser must not keep the predecessor's bytes under the release-version query. Both
// are delivered assets: the shell requests each under the digest of its own bytes.
//
// The control is a stylesheet this delivery did not change: it keeps the release
// version, so a URL that moved for an untouched file would be reported here too.

import (
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/config"
)

func TestVPNShellRequestsLayoutAndModalScriptUnderTheirBytes(t *testing.T) {
	body := renderVPNPageFor(t, "vpn")
	links := collectShellLinks(t, body)

	delivered := map[string][]string{
		"stylesheet": links.stylesheets,
		"script":     links.scripts,
	}
	for _, want := range []struct {
		kind string
		path string
	}{
		{"stylesheet", "/static/css/layout.css"},
		{"script", "/static/js/ui.js"},
	} {
		wantURL := want.path + "?v=" + deliveredAssetDigest(t, want.path)
		found := false
		for _, ref := range delivered[want.kind] {
			if ref == wantURL {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s %s is not requested under its own bytes; want %s in %v",
				want.kind, want.path, wantURL, delivered[want.kind])
		}
		// The predecessor URL must not also be emitted: a browser that cached the old
		// bytes under it would keep them.
		stale := want.path + "?v=" + config.AppVersion
		for _, ref := range delivered[want.kind] {
			if ref == stale {
				t.Errorf("%s %s is still requested under the release version %s", want.kind, want.path, config.AppVersion)
			}
		}
		if strings.Contains(body, want.path+"\"") {
			t.Errorf("%s %s is also requested bare, which has no cache identity at all", want.kind, want.path)
		}
	}

	// Control: a stylesheet this delivery did not change keeps the release version, so
	// the identity above is the file's own content and not a blanket change.
	controlURL := "/static/css/tokens.css?v=" + config.AppVersion
	foundControl := false
	for _, ref := range links.stylesheets {
		if ref == controlURL {
			foundControl = true
		}
		if strings.HasPrefix(ref, "/static/css/tokens.css?v=") && ref != controlURL {
			t.Errorf("the untouched stylesheet's URL moved: %s", ref)
		}
	}
	if !foundControl {
		t.Errorf("the control stylesheet is not requested under the release version; got %v", links.stylesheets)
	}
}
