package web

// Cache identity for the assets this build ships.
//
// /static is served with a one-day lifetime, so a browser keeps an asset whose
// URL does not change. The release version in the query is a cache identity only
// for the assets that release changed: an asset edited without a release bump is
// then served from the same ?v=<release> URL its predecessor used, and a
// returning browser runs the old bytes against the new markup. The identity
// below is derived from the asset's own bytes instead, so any edit to the
// delivered file moves the URL.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"strings"
)

// AssetVersion returns the cache identity of one asset: the hex SHA-256 of the
// bytes root holds at name. Two different contents cannot share it, and an
// unchanged file keeps its identity across builds.
func AssetVersion(root fs.FS, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("asset version: empty asset name")
	}
	body, err := fs.ReadFile(root, name)
	if err != nil {
		return "", fmt.Errorf("asset version for %q: %w", name, err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// DeliveredAssets are the /static paths this delivery replaced in place: the
// six VPN modules, the stylesheet every shell links and the table engine the
// VPN page's reveal depends on. The release version did not move with them, so
// ?v=<release> is exactly the URL their predecessor served and a returning
// browser keeps the old bytes. Each one therefore has to be requested through
// AssetURL, in every shell that loads it.
//
// This is the only place that set is spelled. A check that kept its own copy
// could answer "every asset is identified" while the copy was missing the asset
// whose bytes moved, which is how the table engine stayed bare behind a green
// VPN-only guard. A delivery that changes another shipped asset adds it here and
// the checks that consume this list cover it without further edits.
var DeliveredAssets = []string{
	"/static/css/settings.css",
	"/static/css/vpn.css",
	"/static/js/policy_panels.js",
	"/static/js/policy_routing.js",
	"/static/js/settings_nav.js",
	"/static/js/tables.js",
	"/static/js/vpn/backends.js",
	"/static/js/vpn/health_problems.js",
	"/static/js/vpn/health_summary.js",
	"/static/js/vpn/charts.js",
	"/static/js/vpn/sessions.js",
	"/static/js/vpn/page.js",
}

// AssetURL returns the URL a template emits for one asset of this build: the
// path with a query derived from the bytes embedded for it. A path this build
// does not ship is an error, so a missing asset fails the render instead of
// being served under a version that means nothing.
//
// This is the only place a content-derived query is spelled. A template names an
// asset by path and asks for its URL, so no asset can carry a hand-typed version
// that outlives its bytes.
func AssetURL(path string) (string, error) {
	return AssetURLFor(StaticFS, path)
}

// AssetURLFor is the same computation against another root. The build binds
// AssetURL; a test binds the same function to a copy of the assets so it can
// change one file's bytes and read the URL that results, rather than restating
// the derivation and proving a second implementation agrees with itself.
func AssetURLFor(root fs.FS, path string) (string, error) {
	name, ok := strings.CutPrefix(path, "/")
	if !ok || !strings.HasPrefix(name, "static/") {
		return "", fmt.Errorf("asset URL for %q: only /static assets carry a content identity", path)
	}
	version, err := AssetVersion(root, name)
	if err != nil {
		return "", err
	}
	return path + "?v=" + version, nil
}
