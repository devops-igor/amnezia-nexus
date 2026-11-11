package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestGigahostCatalogStaleBanner proves the ordering page states honestly when the
// catalog it is showing came from a retained snapshot whose refresh failed, and
// that it does not claim freshness when there is none.
//
// The helpers are extracted from the shipped template and run in JSDOM, so these
// assertions describe the real code rather than a copy of it. Three observable
// behaviors matter:
//
//   - a stale answer renders a visible banner carrying the snapshot age;
//   - a fresh answer clears the banner, so a recovered provider never still looks
//     stale;
//   - the age is rendered in coarse units, and an unparseable age degrades to an
//     empty value instead of printing "NaN".
func TestGigahostCatalogStaleBanner(t *testing.T) {
	node := requireNode(t)
	requireJSDOM(t)
	// The module is a static file, so the test asserts the shipped code directly
	// rather than a copy extracted from the template.
	module, err := StaticFS.ReadFile("static/js/gigahost_catalog_status.js")
	if err != nil {
		t.Fatal(err)
	}
	encodedModule, _ := json.Marshal(string(module))

	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="deployCatalogStale" style="display:none"></div>', {runScripts:'outside-only'});
const w = dom.window;
// The template resolves these from the page globals; the harness supplies them.
const translations = {deploy_vps_catalog_stale:'cached from {age}'};
w._ = key => translations[key] || key;
w.eval(%s);

const banner = w.document.getElementById('deployCatalogStale');

// A stale answer is visible and carries the rendered age.
w.renderDeployCatalogStale({stale:true, age_seconds:125});
assert.equal(banner.style.display, 'block');
assert.equal(banner.textContent, 'cached from 2m');

// A fresh answer clears it: a recovered provider must not still look stale.
w.renderDeployCatalogStale({stale:false, age_seconds:3});
assert.equal(banner.style.display, 'none');
assert.equal(banner.textContent, '');

// A stale answer with no usable age still states the stale fact, without NaN.
w.renderDeployCatalogStale({stale:true});
assert.equal(banner.style.display, 'block');
assert.ok(!banner.textContent.includes('NaN'), 'unparseable age must not render as NaN');
assert.equal(banner.textContent, 'cached from ');

// An error/absent answer clears the banner too: it is the refresh state, not an
// error state, that the banner describes.
w.renderDeployCatalogStale(null);
assert.equal(banner.style.display, 'none');

// Age units are coarse and monotonic.
assert.equal(w.formatDeployCatalogAge(0), '0s');
assert.equal(w.formatDeployCatalogAge(59), '59s');
assert.equal(w.formatDeployCatalogAge(60), '1m');
assert.equal(w.formatDeployCatalogAge(3599), '60m');
assert.equal(w.formatDeployCatalogAge(3600), '1h');
assert.equal(w.formatDeployCatalogAge(7200), '2h');

console.log('STALE_BANNER_OK');
dom.window.close();
`, string(encodedModule))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "STALE_BANNER_OK") {
		t.Fatalf("stale banner DOM check failed: %v\n%s", err, out)
	}
}
