package web

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"testing/fstest"
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
		if !strings.Contains(combined, fx.TemplateHTML) || !strings.Contains(combined, fx.SessionsJS) ||
			!strings.Contains(combined, fx.HealthProblemsJS) || !strings.Contains(combined, fx.HealthSummaryJS) ||
			!strings.Contains(combined, fx.ChartsJS) {
			t.Fatal("CombinedSource must contain TemplateHTML, SessionsJS, HealthProblemsJS, HealthSummaryJS, and ChartsJS")
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

	t.Run("TemplateOnlyLookupOfMovedFunctionsFails", func(t *testing.T) {
		fx := fixture.WithT(t)
		movedFunctions := []string{
			"renderSessions",
			"vpnFormatPeerKey",
			"vpnDiagText",
			"vpnLossReasonLabels",
			"createSeverityBadge",
			"deriveStableConditionCode",
			"parseConditionMessage",
			"extractConditionEntities",
			"vpnRenderActiveProblemsCards",
			"vpnRenderTechDiagnosticCards",
			"vpnResetHealthProblems",
			"vpnResetTechDiagnosticCards",
			"vpnRenderForwarderHealth",
			"vpnGenerateSparklineSVG",
			"vpnDisposeChartInteractions",
			"vpnRenderHistoryCharts",
			"vpnSetHistoryWindow",
		}
		for _, name := range movedFunctions {
			if _, err := extractJSFunction(fx.TemplateHTML, "function "+name); err == nil {
				t.Fatalf("expected extractJSFunction %s from TemplateHTML to fail, but succeeded", name)
			}
			if _, err := extractJSFunction(fx.CombinedSource(), "function "+name); err != nil {
				t.Fatalf("expected extractJSFunction %s from CombinedSource to succeed: %v", name, err)
			}
		}
		for _, name := range []string{
			"vpnGenerateSparklineSVG",
			"vpnDisposeChartInteractions",
			"vpnRenderHistoryCharts",
			"vpnSetHistoryWindow",
		} {
			if _, err := extractJSFunction(fx.ChartsJS, "function "+name); err != nil {
				t.Fatalf("expected extractJSFunction %s from ChartsJS to succeed: %v", name, err)
			}
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

func TestVPNFixtureAssetFailClosed(t *testing.T) {
	if os.Getenv("TEST_VPN_ASSET_FAIL_CLOSED") != "" {
		asset := os.Getenv("TEST_VPN_ASSET_FAIL_CLOSED")
		fx := NewVPNTestFixture(t)
		clone := *fx
		switch asset {
		case "empty_health_problems":
			clone.HealthProblemsJS = "   \n	  "
		case "empty_health_summary":
			clone.HealthSummaryJS = ""
		case "empty_sessions":
			clone.SessionsJS = " "
		case "empty_charts":
			clone.ChartsJS = "   \n	  "
		}
		clone.BuildJSDOMHarness(JSDOMHarnessOptions{})
		return
	}

	for _, assetCase := range []struct {
		envVal    string
		errSubstr string
	}{
		{"empty_health_problems", "failed to read static health problems asset"},
		{"empty_health_summary", "failed to read static health summary asset"},
		{"empty_sessions", "failed to read static sessions asset"},
		{"empty_charts", "failed to read static charts asset"},
	} {
		t.Run(assetCase.envVal, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestVPNFixtureAssetFailClosed$")
			cmd.Env = append(os.Environ(), "TEST_VPN_ASSET_FAIL_CLOSED="+assetCase.envVal)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("expected failure for %s, but process exited cleanly", assetCase.envVal)
			}
			if !strings.Contains(string(out), assetCase.errSubstr) {
				t.Fatalf("expected output to contain %q, got:\n%s", assetCase.errSubstr, string(out))
			}
		})
	}
}

func TestHealthSummaryFailsClosedWithoutHealthProblems(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireNode()

	// 1. Available forwarder with CRITICAL status throws ReferenceError when health_problems.js is missing
	availableScript := vpnDOMMock(t, fixture.TemplateHTML) + "\n" + fixture.TranslationsJS("en") + "\n" + fixture.HealthSummaryJS + `
try {
    vpnRenderForwarderHealth({
        forwarder_available: true,
        health_assessment: { status: 'CRITICAL', conditions: [{ severity: 'CRITICAL', message: 'Failure' }] }
    });
    console.log('FAIL_OPEN_AVAILABLE');
} catch (e) {
    if (e instanceof ReferenceError) {
        console.log('FAIL_CLOSED_REFERENCE_ERROR_AVAILABLE');
    } else {
        throw e;
    }
}
`
	out, err := execNodeScript(nodePath, availableScript)
	if err != nil {
		t.Fatalf("unexpected execution failure: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "FAIL_CLOSED_REFERENCE_ERROR_AVAILABLE") {
		t.Fatalf("expected ReferenceError on available render without health_problems.js, got:\n%s", string(out))
	}

	// 2. Unavailable forwarder (null status) throws ReferenceError when resetting without health_problems.js
	unavailableScript := vpnDOMMock(t, fixture.TemplateHTML) + "\n" + fixture.TranslationsJS("en") + "\n" + fixture.HealthSummaryJS + `
try {
    vpnRenderForwarderHealth(null);
    console.log('FAIL_OPEN_UNAVAILABLE');
} catch (e) {
    if (e instanceof ReferenceError) {
        console.log('FAIL_CLOSED_REFERENCE_ERROR_UNAVAILABLE');
    } else {
        throw e;
    }
}
`
	out2, err := execNodeScript(nodePath, unavailableScript)
	if err != nil {
		t.Fatalf("unexpected execution failure: %v\n%s", err, string(out2))
	}
	if !strings.Contains(string(out2), "FAIL_CLOSED_REFERENCE_ERROR_UNAVAILABLE") {
		t.Fatalf("expected ReferenceError on unavailable reset without health_problems.js, got:\n%s", string(out2))
	}
}

func TestSuppliedSourceIsolationInHealthScriptLocale(t *testing.T) {
	fixture := NewVPNTestFixture(t)

	// Supplying TemplateHTML (which lacks function vpnRenderForwarderHealth declaration) must return error
	_, err := vpnDiagnosticsHealthScriptLocale(t, fixture.TemplateHTML, "en", `vpnRenderForwarderHealth(null);`)
	if err == nil {
		t.Fatal("expected error when supplying template-only source lacking vpnRenderForwarderHealth, got nil")
	}
	if !strings.Contains(err.Error(), "vpnRenderForwarderHealth") {
		t.Fatalf("expected error mentioning vpnRenderForwarderHealth, got: %v", err)
	}
}

func TestBrokenCompanionModuleExecutionFailsInHarness(t *testing.T) {
	t.Run("HealthProblemsModuleExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixture(t)
		nodePath := fixture.RequireNode()
		fixture.HealthProblemsJS = "throw new Error('AUDIT_MODULE_EXECUTION_FAILURE');\n" + fixture.HealthProblemsJS

		script, err := vpnDiagnosticsHealthScriptLocale(t, fixture.CombinedSource(), "en", `vpnRenderForwarderHealth({forwarder_available:true});`)
		if err != nil {
			t.Fatalf("vpnDiagnosticsHealthScriptLocale failed: %v", err)
		}

		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "AUDIT_MODULE_EXECUTION_FAILURE") {
			t.Fatalf("expected output to mention AUDIT_MODULE_EXECUTION_FAILURE, got:\n%s", string(out))
		}
	})

	t.Run("HealthSummaryModuleExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixture(t)
		nodePath := fixture.RequireNode()
		fixture.HealthSummaryJS = "throw new Error('SUMMARY_MODULE_INIT_FAILURE');\n" + fixture.HealthSummaryJS

		script, err := vpnDiagnosticsHealthScriptLocale(t, fixture.CombinedSource(), "en", `vpnRenderForwarderHealth({forwarder_available:true});`)
		if err != nil {
			t.Fatalf("vpnDiagnosticsHealthScriptLocale failed: %v", err)
		}

		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "SUMMARY_MODULE_INIT_FAILURE") {
			t.Fatalf("expected output to mention SUMMARY_MODULE_INIT_FAILURE, got:\n%s", string(out))
		}
	})

	t.Run("TroubleshootingHarnessHealthProblemsExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixture(t)
		nodePath := fixture.RequireNode()
		fixture.HealthProblemsJS = "throw new Error('TROUBLESHOOTING_MODULE_FAILURE');\n" + fixture.HealthProblemsJS

		script := vpnConnectionTroubleshootingScriptLocale(t, fixture.CombinedSource(), "en", `assert(true);`)
		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error in troubleshooting harness, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "TROUBLESHOOTING_MODULE_FAILURE") {
			t.Fatalf("expected output to mention TROUBLESHOOTING_MODULE_FAILURE, got:\n%s", string(out))
		}
	})

	t.Run("ChartsModuleExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixture(t)
		nodePath := fixture.RequireNode()
		fixture.ChartsJS = "throw new Error('CHARTS_MODULE_FAILURE');\n" + fixture.ChartsJS

		script, err := vpnDiagnosticsHealthScriptLocale(t, fixture.CombinedSource(), "en", `assert(true);`)
		if err != nil {
			t.Fatalf("vpnDiagnosticsHealthScriptLocale failed: %v", err)
		}

		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "CHARTS_MODULE_FAILURE") {
			t.Fatalf("expected output to mention CHARTS_MODULE_FAILURE, got:\n%s", string(out))
		}
	})

	t.Run("ChartsModuleJSDOMExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixture(t)
		nodePath := fixture.RequireJSDOM()
		fixture.ChartsJS = "throw new Error('CHARTS_JSDOM_FAILURE');\n" + fixture.ChartsJS

		script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
			ExtraJS: `console.log('UNREACHABLE_AFTER_CHARTS_ERROR');`,
		})

		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error in JSDOM harness, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "CHARTS_JSDOM_FAILURE") {
			t.Fatalf("expected output to mention CHARTS_JSDOM_FAILURE, got:\n%s", string(out))
		}
	})
}

func TestVPNFixtureLoaderSeamAssetFailClosed(t *testing.T) {
	if mode := os.Getenv("TEST_VPN_LOADER_SEAM_CASE"); mode != "" {
		baseFS := fstest.MapFS{
			"static/css/style.css":             &fstest.MapFile{Data: []byte("body { margin: 0; }")},
			"static/js/vpn/sessions.js":        &fstest.MapFile{Data: []byte("function vpnRenderSessions() {}")},
			"static/js/vpn/health_problems.js": &fstest.MapFile{Data: []byte("function vpnEvaluateHealth() {}")},
			"static/js/vpn/health_summary.js":  &fstest.MapFile{Data: []byte("function vpnRenderForwarderHealth() {}")},
		}
		switch mode {
		case "missing_charts":
			// static/js/vpn/charts.js omitted
		case "empty_charts":
			baseFS["static/js/vpn/charts.js"] = &fstest.MapFile{Data: []byte("")}
		case "whitespace_charts":
			baseFS["static/js/vpn/charts.js"] = &fstest.MapFile{Data: []byte("   \n	  \r\n")}
		default:
			t.Fatalf("unknown test mode: %s", mode)
		}
		newVPNTestFixtureWithFS(t, baseFS)
		return
	}

	for _, tc := range []struct {
		mode      string
		errSubstr string
	}{
		{"missing_charts", "failed to read static charts asset static/js/vpn/charts.js"},
		{"empty_charts", "failed to read static charts asset static/js/vpn/charts.js: empty content"},
		{"whitespace_charts", "failed to read static charts asset static/js/vpn/charts.js: empty content"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestVPNFixtureLoaderSeamAssetFailClosed$")
			cmd.Env = append(os.Environ(), "TEST_VPN_LOADER_SEAM_CASE="+tc.mode)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("expected failure for %s, but process exited cleanly", tc.mode)
			}
			if !strings.Contains(string(out), tc.errSubstr) {
				t.Fatalf("expected output to contain %q, got:\n%s", tc.errSubstr, string(out))
			}
		})
	}

	t.Run("ValidMapFS", func(t *testing.T) {
		validFS := fstest.MapFS{
			"static/css/style.css":             &fstest.MapFile{Data: []byte("body { margin: 0; }")},
			"static/js/vpn/sessions.js":        &fstest.MapFile{Data: []byte("function vpnRenderSessions() {}")},
			"static/js/vpn/health_problems.js": &fstest.MapFile{Data: []byte("function vpnEvaluateHealth() {}")},
			"static/js/vpn/health_summary.js":  &fstest.MapFile{Data: []byte("function vpnRenderForwarderHealth() {}")},
			"static/js/vpn/charts.js":          &fstest.MapFile{Data: []byte("function vpnRenderHistoryCharts() {}")},
		}
		fx := newVPNTestFixtureWithFS(t, validFS)
		if fx == nil {
			t.Fatal("expected non-nil fixture from valid MapFS")
		}
		if fx.ChartsJS != "function vpnRenderHistoryCharts() {}" {
			t.Fatalf("unexpected ChartsJS content: %s", fx.ChartsJS)
		}
	})
}

func TestTemplateMarkerNotFoundFailsClosed(t *testing.T) {
	_, err := vpnDiagnosticsHealthScriptLocale(t, "function vpnRenderForwarderHealth() { return 1; }", "en", "vpnRenderForwarderHealth();")
	if err == nil {
		t.Fatal("expected error when template marker is missing, got nil")
	}
	if !strings.Contains(err.Error(), "template marker not found in source") {
		t.Fatalf("expected error mentioning 'template marker not found in source', got: %v", err)
	}
}
