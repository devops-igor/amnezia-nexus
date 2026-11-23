package web

import "html/template"

// withAssetURL registers the asset_url template helper on a fixture's FuncMap.
//
// Every shell that links an asset through asset_url needs the production
// resolver, so the registration lives here once. A fixture that stood in its
// own copy could drift from the resolver the shipped templates actually call,
// and a render check would then pass against a URL no release produces.
func withAssetURL(fm template.FuncMap) template.FuncMap {
	fm["asset_url"] = AssetURL
	return fm
}
