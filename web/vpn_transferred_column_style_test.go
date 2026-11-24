package web

import (
	"io/fs"
	"strings"
	"testing"
)

// TestVPNSessionsTransferredColumnStyle covers the styling half of the
// Transferred column: the value is one unbreakable, explicitly isolated
// left-to-right run, the header and the not-measured label stop wrapping, and
// the not-measured state owns its own colour instead of borrowing the shared
// muted token (the shared .form-hint style belongs to issue 977).
//
// The sheet read here is the one the page links (vpn.css), not the concatenated
// artifact; TestStyleCSSConcatenationParity keeps the two identical.
func TestVPNSessionsTransferredColumnStyle(t *testing.T) {
	// Both are declarations bound to their own selectors, so a rule renamed or
	// moved elsewhere cannot pass the check that follows.
	t.Run("ValueAndLabelsDeclareTheirOwnWrapping", func(t *testing.T) {
		staticFS, err := GetStaticSubFS()
		if err != nil {
			t.Fatal(err)
		}
		vpnCSS, err := fs.ReadFile(staticFS, "css/vpn.css")
		if err != nil {
			t.Fatal(err)
		}
		cssStr := string(vpnCSS)
		expect := []struct{ selector, property, value string }{
			{".vpn-transferred-value", "white-space", "nowrap"},
			{".vpn-transferred-value", "unicode-bidi", "isolate"},
			{".vpn-transferred-value", "direction", "ltr"},
			{".vpn-transferred-missing", "white-space", "nowrap"},
			{".vpn-transferred-head", "white-space", "nowrap"},
		}
		for _, want := range expect {
			got, ok := cssDeclaration(cssStr, want.selector, want.property)
			if !ok || got != want.value {
				t.Errorf("%s %s = %q (found=%t), want %q", want.selector, want.property, got, ok, want.value)
			}
		}

		// Counterexample control: the mutation a substring oracle lets through.
		// Dropping the isolation and letting the value wrap again must be visible
		// through the same selector binding, not absorbed by a nearby rule.
		original := ".vpn-transferred-value {\n    white-space: nowrap;\n    unicode-bidi: isolate;\n    direction: ltr;\n}"
		mutated := ".vpn-transferred-value {\n    white-space: normal;\n    unicode-bidi: normal;\n    direction: ltr;\n}"
		if strings.Count(cssStr, original) != 1 {
			t.Fatalf("the .vpn-transferred-value rule is not present exactly once in the delivered stylesheet")
		}
		mutatedCSS := strings.Replace(cssStr, original, mutated, 1)
		if got, _ := cssDeclaration(mutatedCSS, ".vpn-transferred-value", "unicode-bidi"); got != "normal" {
			t.Errorf("mutation control: unicode-bidi = %q, want the mutated value", got)
		}
		if got, _ := cssDeclaration(mutatedCSS, ".vpn-transferred-value", "white-space"); got != "normal" {
			t.Errorf("mutation control: white-space = %q, want the mutated value", got)
		}
	})

	// The not-measured state owns its colour. The shared muted token and the
	// shared .form-hint style are issue 977's subject, so this delivery must not
	// reach for either: the state label declares --text-secondary itself.
	t.Run("NotMeasuredStateOwnsItsColour", func(t *testing.T) {
		staticFS, err := GetStaticSubFS()
		if err != nil {
			t.Fatal(err)
		}
		vpnCSS, err := fs.ReadFile(staticFS, "css/vpn.css")
		if err != nil {
			t.Fatal(err)
		}
		cssStr := string(vpnCSS)
		got, ok := cssDeclaration(cssStr, ".vpn-transferred-missing", "color")
		if !ok || got != "var(--text-secondary)" {
			t.Errorf(".vpn-transferred-missing color = %q (found=%t), want var(--text-secondary)", got, ok)
		}
		if got, _ := cssDeclaration(cssStr, ".vpn-transferred-missing", "color"); got == "var(--text-muted)" {
			t.Error("the not-measured state must not borrow the shared muted token")
		}

		componentsCSS, err := fs.ReadFile(staticFS, "css/components.css")
		if err != nil {
			t.Fatal(err)
		}
		// Issue 977 tracks the shared hint style; it stays exactly as it is.
		if got, ok := cssDeclaration(string(componentsCSS), ".form-hint", "color"); !ok || got != "var(--text-muted)" {
			t.Errorf(".form-hint color = %q (found=%t); the shared hint style belongs to issue 977 and must not move here", got, ok)
		}
	})
}
