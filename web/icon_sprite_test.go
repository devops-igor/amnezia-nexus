package web

// Every icon reference in the shipped markup and the shipped scripts must resolve to
// a symbol the sprites actually declare.
//
// This is the check that was missing when `#icon-alert-triangle` shipped: the drops
// icon and every problem-severity icon referenced it, the sprite never declared it,
// and the pages rendered a blank box with nothing to fail. The reference set is read
// from the delivered files rather than from a list, so a new reference is covered the
// moment it is written.

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var iconReferencePattern = regexp.MustCompile(`#icon-([a-z0-9-]+)`)
var iconSymbolPattern = regexp.MustCompile(`<symbol id="icon-([a-z0-9-]+)"([^>]*)>`)

// iconReferences collects every `#icon-<name>` written in the shipped templates and
// scripts, keyed by the file that names it so a failure can say where to look.
func iconReferences(t *testing.T) map[string][]string {
	t.Helper()
	refs := map[string][]string{}
	collect := func(fsys fs.FS, dir string) {
		err := fs.WalkDir(fsys, dir, func(p string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			if !strings.HasSuffix(p, ".html") && !strings.HasSuffix(p, ".js") {
				return nil
			}
			body, readErr := fs.ReadFile(fsys, p)
			if readErr != nil {
				return readErr
			}
			for _, match := range iconReferencePattern.FindAllStringSubmatch(string(body), -1) {
				refs[match[1]] = append(refs[match[1]], p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	templates, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	collect(templates, ".")
	collect(StaticFS, "static/js")
	return refs
}

// iconSymbols returns the symbol names one sprite file declares, with the attributes
// of each symbol tag.
func iconSymbols(t *testing.T, path string) map[string]string {
	t.Helper()
	templates, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	body, err := fs.ReadFile(templates, path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	symbols := map[string]string{}
	for _, match := range iconSymbolPattern.FindAllStringSubmatch(string(body), -1) {
		symbols[match[1]] = match[2]
	}
	return symbols
}

func TestIconSpritesResolveEveryReferencedSymbol(t *testing.T) {
	refs := iconReferences(t)
	if len(refs) < 10 {
		t.Fatalf("only %d icon references found; the scan is not reading the delivered files", len(refs))
	}
	for _, sprite := range []string{"base.html", "icons.html"} {
		symbols := iconSymbols(t, sprite)
		if len(symbols) < 10 {
			t.Fatalf("%s declares only %d symbols; the scan is not reading the sprite", sprite, len(symbols))
		}
		var missing []string
		for name := range refs {
			if _, ok := symbols[name]; !ok {
				missing = append(missing, "#icon-"+name)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			var where []string
			for _, ref := range missing {
				where = append(where, ref+" ("+strings.Join(refs[strings.TrimPrefix(ref, "#icon-")], ", ")+")")
			}
			t.Errorf("%s does not declare every referenced symbol; unresolved: %s", sprite, strings.Join(where, "; "))
		}
	}
}

// TestAlertTriangleSymbolIsDrawn pins the symbol the drops and problem-severity icons
// use: declared in the shared stroke style at the neighbours' 24x24 viewBox, and
// actually drawn rather than left as an empty shell.
func TestAlertTriangleSymbolIsDrawn(t *testing.T) {
	for _, sprite := range []string{"base.html", "icons.html"} {
		symbols := iconSymbols(t, sprite)
		attrs, ok := symbols["alert-triangle"]
		if !ok {
			t.Fatalf("%s declares no icon-alert-triangle symbol", sprite)
		}
		for _, want := range []string{`viewBox="0 0 24 24"`, `stroke="currentColor"`, `fill="none"`, `stroke-width="2"`} {
			if !strings.Contains(attrs, want) {
				t.Errorf("%s icon-alert-triangle is not drawn in the neighbours' style: missing %s", sprite, want)
			}
		}
		// A symbol that declares no geometry renders blank, which is the state the
		// missing symbol produced.
		templates, err := GetTemplatesSubFS()
		if err != nil {
			t.Fatalf("GetTemplatesSubFS: %v", err)
		}
		body, err := fs.ReadFile(templates, sprite)
		if err != nil {
			t.Fatalf("read %s: %v", sprite, err)
		}
		text := string(body)
		start := strings.Index(text, `<symbol id="icon-alert-triangle"`)
		if start < 0 {
			t.Fatalf("%s: symbol start not found after the pattern matched", sprite)
		}
		end := strings.Index(text[start:], "</symbol>")
		if end < 0 {
			t.Fatalf("%s: icon-alert-triangle is not closed", sprite)
		}
		inner := text[start : start+end]
		if !strings.Contains(inner, "<path") || !strings.Contains(inner, "<line") {
			t.Fatalf("%s: icon-alert-triangle declares no geometry:\n%s", sprite, inner)
		}
	}
}
