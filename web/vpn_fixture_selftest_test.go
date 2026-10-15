package web

import (
	"os"
	"strings"
	"testing"
)

func TestVPNTestFixture(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	if fixture.TemplateHTML == "" {
		t.Fatal("expected non-empty TemplateHTML")
	}
	if fixture.StyleCSS == "" {
		t.Fatal("expected non-empty StyleCSS")
	}
	if fixture.ParsedDOM == nil {
		t.Fatal("expected non-nil ParsedDOM")
	}

	t.Run("DOMQueryHelpers", func(t *testing.T) {
		fx := fixture.WithT(t)
		topCard := fx.FindByID("vpn-forwarder-card")
		if topCard == nil {
			t.Fatal("expected to find #vpn-forwarder-card")
		}
		tables := fx.FindByTag("table")
		if len(tables) == 0 {
			t.Fatal("expected at least one table in vpn.html")
		}
		if err := fx.ValidateDashboardOrder(); err != nil {
			t.Fatalf("dashboard DOM order validation failed: %v", err)
		}
		if none := fx.FindByID(""); none != nil {
			t.Fatalf("expected FindByID(\"\") to return nil, got %v", none)
		}
	})

	t.Run("LocalizationInjection", func(t *testing.T) {
		fx := fixture.WithT(t)
		enDict := fx.Locale("en")
		if len(enDict) == 0 {
			t.Fatal("expected non-empty en locale dict")
		}
		rendered := fx.RenderedHTML("en")
		if len(rendered) == 0 {
			t.Fatal("expected non-empty rendered HTML")
		}
		if err := vpnDiagnosticsStaticOracle(rendered, enDict); err != nil {
			t.Fatalf("static oracle failed: %v", err)
		}
	})

	t.Run("JSDOMFakeClockAndMockFetch", func(t *testing.T) {
		fx := fixture.WithT(t)
		fx.MockEndpoint("/api/vpn/status", `{"forwarder_available": true, "status": "HEALTHY"}`)
		testScript := fx.BuildJSDOMHarness(JSDOMHarnessOptions{
			IncludeFakeClock: true,
			IncludeFetchMock: true,
			ExtraJS: `
(async () => {
    let timerFired = false;
    w.fakeClock.setTimeout(() => { timerFired = true; }, 500);
    assert.strictEqual(timerFired, false, 'timer should not fire before tick');
    w.fakeClock.tick(500);
    assert.strictEqual(timerFired, true, 'timer should fire after tick');
    const res = await w.fetch('/api/vpn/status');
    const data = await res.json();
    assert.strictEqual(data.forwarder_available, true, 'mock fetch must return payload');
    assert.strictEqual(data.status, 'HEALTHY', 'mock fetch payload match');
    console.log('FIXTURE_JSDOM_PASS');
})().catch(e => { console.error(e); process.exit(1); });
`,
		})
		out := fx.RunJSDOM(testScript)
		if !strings.Contains(out, "FIXTURE_JSDOM_PASS") {
			t.Fatalf("expected FIXTURE_JSDOM_PASS, got: %s", out)
		}
	})

	t.Run("BacktickPreservationInHarness", func(t *testing.T) {
		fx := fixture.WithT(t)
		harness := fx.BuildJSDOMHarness(JSDOMHarnessOptions{
			HTML: `<div id="backtick-test">` + "`literal_backtick`" + `</div>`,
		})
		if strings.Contains(harness, `\`+"`") {
			t.Fatalf("BuildJSDOMHarness must not escape backticks with backslashes; found backslash-escaped backtick")
		}
		if !strings.Contains(harness, "`literal_backtick`") {
			t.Fatalf("BuildJSDOMHarness must contain raw backtick literal")
		}
	})

	t.Run("WithTSubtestBinding", func(t *testing.T) {
		fx := fixture.WithT(t)
		if fx.t != t {
			t.Fatalf("expected fx.t to be subtest t, got %v", fx.t)
		}
	})

	t.Run("CombinedSourceAndExactBoundaryExtraction", func(t *testing.T) {
		fx := fixture.WithT(t)
		combined := fx.CombinedSource()
		if !strings.Contains(combined, fx.TemplateHTML) || !strings.Contains(combined, fx.SessionsJS) {
			t.Fatal("CombinedSource must contain both TemplateHTML and SessionsJS")
		}
		if fx.CombinedVPNSessionsSource() != combined {
			t.Fatal("CombinedVPNSessionsSource must match CombinedSource")
		}
		if _, err := extractJSFunction(combined, "function renderSessions"); err != nil {
			t.Fatalf("extractJSFunction renderSessions from combined source failed: %v", err)
		}
		if _, err := extractJSFunction(fx.TemplateHTML, "function renderSessions"); err == nil {
			t.Fatal("expected error extracting renderSessions from TemplateHTML without fallback")
		}
		dummySource := "function testFooBar() { return 1; }\nfunction testFoo() { return 2; }"
		fn, err := extractJSFunction(dummySource, "function testFoo")
		if err != nil {
			t.Fatalf("extractJSFunction testFoo failed: %v", err)
		}
		if !strings.Contains(fn, "return 2;") {
			t.Fatalf("extractJSFunction matched prefix instead of exact boundary: %s", fn)
		}
	})

	t.Run("FailClosedCIInvariant", func(t *testing.T) {
		origCI := os.Getenv("CI")
		defer os.Setenv("CI", origCI)
		os.Setenv("CI", "")
		if isCIEnvironment() {
			t.Fatal("expected isCIEnvironment() to be false when CI=''")
		}
		for _, v := range []string{"true", "1", "TRUE"} {
			os.Setenv("CI", v)
			if !isCIEnvironment() {
				t.Fatalf("expected isCIEnvironment() to be true when CI=%q", v)
			}
		}
	})
}
