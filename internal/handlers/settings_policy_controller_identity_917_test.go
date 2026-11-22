package handlers

// The policy controller's cache identity.
//
// /static is served with a one-day lifetime, so a controller whose URL does not
// change keeps running in a browser that already holds it. This controller changed
// incompatibly in this change: the shipped markup now has one textarea
// (#policy_proxy_exceptions) where the predecessor had a local-entry editor plus a
// preset and custom-URL block, and the payload it builds carries proxy_exceptions
// where the predecessor sent local_entries/preset/custom_urls.
//
// The release version did not move, so ?v=<release> is exactly the URL the
// predecessor served. A return visit inside the cache window would therefore run the
// predecessor's bytes against this markup: the saved list would not be populated and
// a typed replacement would never be sent.
//
// The fix is the same mechanism the sibling diagnostics controller already uses —
// web.AssetURL, whose query is the digest of the delivered bytes — and these cases
// pin it at the two places it can silently regress: the emitted URL and the identity
// function's own behaviour.

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// TestPolicyControllerURLIsDerivedFromItsBytes is the F957-03 regression at the
// delivery boundary: the page must request this controller under the digest of the
// bytes this build ships, not under the release constant the predecessor also
// served.
//
// The assertion is on the production-rendered URL, so a template that reverts to the
// release version fails here even though every unit of the helper still works.
func TestPolicyControllerURLIsDerivedFromItsBytes(t *testing.T) {
	const controller = "/static/js/policy_routing.js"
	body := renderSettingsPage(t, models.RoleAdmin)

	emitted := ""
	for _, src := range collectShellLinks(t, body).scripts {
		if path, _, _ := strings.Cut(src, "?"); path == controller {
			emitted = src
		}
	}
	if emitted == "" {
		t.Fatalf("the settings page does not load %s at all", controller)
	}

	want := controller + "?v=" + deliveredAssetDigest(t, controller)
	if emitted != want {
		t.Fatalf("the page requests %s at %q, want %q; a browser that cached this controller under "+
			"another URL — the release-version URL the predecessor served — keeps running the "+
			"predecessor's bytes against the new markup", controller, emitted, want)
	}

	// The URL must not be the release version. This is the specific identity the
	// predecessor served, so asserting it directly states the defect that was fixed.
	if versioned := versionedAssetURL(controller); emitted == versioned {
		t.Fatalf("the page requests %s at the release URL %q, which the predecessor also served; "+
			"a returning browser keeps the incompatible controller", controller, versioned)
	}

	// And the digest must not accidentally coincide with the release constant, which
	// would make the two identities indistinguishable for this asset.
	if digest := deliveredAssetDigest(t, controller); digest == config.AppVersion {
		t.Fatalf("the controller's byte identity %q equals the release version, so it would follow "+
			"the build rather than the bytes", digest)
	}
}

// TestPolicyControllerIdentityMovesWithItsBytes states the property the URL rests
// on: changing this controller's bytes must change the rendered URL, so a future
// edit to it cannot stay behind a cached copy.
//
// It is asserted on the identity function with two different contents rather than by
// editing the shipped file, because the delivered asset is embedded in the binary:
// the two contents here are the only way to observe the function without a rebuild,
// and the digest comparison above pins the real file.
func TestPolicyControllerIdentityMovesWithItsBytes(t *testing.T) {
	const name = "js/policy_routing.js"
	predecessor := fstest.MapFS{name: &fstest.MapFile{Data: []byte(
		"// predecessor: reads policy_local_entries, sends local_entries\n")}}
	current := fstest.MapFS{name: &fstest.MapFile{Data: []byte(
		"// current: reads policy_proxy_exceptions, sends proxy_exceptions\n")}}

	before, err := web.AssetVersion(predecessor, name)
	if err != nil {
		t.Fatalf("AssetVersion(predecessor): %v", err)
	}
	after, err := web.AssetVersion(current, name)
	if err != nil {
		t.Fatalf("AssetVersion(current): %v", err)
	}
	if before == after {
		t.Fatalf("two different contents of %s produced one identity %q, so a cached copy of either "+
			"is served as the other", name, before)
	}
	if before == config.AppVersion || after == config.AppVersion {
		t.Fatalf("a byte identity equals the release version, so the URL would not move with the bytes")
	}
}

// TestEveryShellLinkingThePolicyControllerUsesItsBytes covers the instruction that
// the fix applies to every surface that loads this controller, not only the page this
// change edited. The list is derived from the shipped templates, so a shell added
// later is examined instead of silently exempt.
func TestEveryShellLinkingThePolicyControllerUsesItsBytes(t *testing.T) {
	const controller = "/static/js/policy_routing.js"

	templates, err := web.GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	var linking []string
	walkErr := fs.WalkDir(templates, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		body, readErr := fs.ReadFile(templates, path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(body), controller) {
			linking = append(linking, path)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk templates: %v", walkErr)
	}
	if len(linking) == 0 {
		t.Fatalf("no shipped template references %s; the scan proves nothing", controller)
	}
	if !slices.Contains(linking, "settings_policy.html") {
		t.Fatalf("the scan did not reach settings_policy.html (found %v)", linking)
	}

	for _, path := range linking {
		body, err := fs.ReadFile(templates, path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		source := string(body)
		if strings.Contains(source, controller+`?v={{ .app_version }}`) {
			t.Errorf("%s links %s at the release version, which the predecessor also served; a returning "+
				"browser keeps the incompatible controller", path, controller)
		}
		if !strings.Contains(source, `asset_url "`+controller+`"`) {
			t.Errorf("%s links %s without asking for its own-byte identity ({{ asset_url %q }})",
				path, controller, controller)
		}
	}
}
