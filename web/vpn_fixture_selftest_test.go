package web

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"testing/fstest"
)

func TestVPNTestFixture(t *testing.T) {
	// The diagnostics document owns the health card, the sessions table and every
	// controller this self-test exercises.
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
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
		// The order contract this fixture validates is the diagnostics document's.
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
		// CombinedSource is the owner document plus exactly the modules it ships.
		for _, module := range []string{fx.SessionsJS, fx.HealthProblemsJS, fx.HealthSummaryJS, fx.ChartsJS, fx.CommonJS, fx.DiagnosticsPageJS} {
			if !strings.Contains(combined, module) {
				t.Fatal("CombinedSource must contain every module the owner document loads")
			}
		}
		if strings.Contains(combined, fx.BackendsJS) {
			t.Fatal("CombinedSource must not carry another document's backend controller")
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
			"vpnFormatApiError",
			"vpnServerHasAwg",
			"vpnStatusBadgeClass",
			"vpnStatusLabel",
			"vpnSetListenerBadge",
			"vpnRenderBackendRow",
			"vpnToggleBackend",
			"vpnDeleteBackend",
			"vpnResetAddModal",
			"vpnOpenAddBackendModal",
			"vpnOnServerSelected",
			"vpnTriggerQuickCheck",
			"vpnSubmitAddBackend",
			"vpnLoadData",
			"vpnToggleShowAllRoutes",
		}
		for _, name := range movedFunctions {
			if _, err := extractJSFunction(fx.TemplateHTML, "function "+name); err == nil {
				t.Fatalf("expected extractJSFunction %s from TemplateHTML to fail, but succeeded", name)
			}
		}
		// Each moved function lives in the module that now owns it, and in no
		// document's markup. Naming the owner is what keeps this check honest: a
		// single "combined source contains it" assertion would pass for a function
		// that stayed behind in another page's controller.
		owners := map[string]string{
			"vpnStatusBadgeClass":    fx.CommonJS,
			"vpnStatusLabel":         fx.CommonJS,
			"vpnSetListenerBadge":    fx.CommonJS,
			"vpnRenderBackendRow":    fx.BackendsJS,
			"vpnToggleBackend":       fx.BackendsJS,
			"vpnDeleteBackend":       fx.BackendsJS,
			"vpnResetAddModal":       fx.BackendsJS,
			"vpnOpenAddBackendModal": fx.BackendsJS,
			"vpnOnServerSelected":    fx.BackendsJS,
			"vpnTriggerQuickCheck":   fx.BackendsJS,
			"vpnSubmitAddBackend":    fx.BackendsJS,
			"vpnToggleShowAllRoutes": fx.PageJS,
		}
		for name, owner := range owners {
			if _, err := extractJSFunction(fx.TemplateHTML, "function "+name); err == nil {
				t.Fatalf("expected extractJSFunction %s from TemplateHTML to fail, but succeeded", name)
			}
			if _, err := extractJSFunction(owner, "function "+name); err != nil {
				t.Fatalf("expected extractJSFunction %s from its owning module to succeed: %v", name, err)
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
		for name, module := range map[string]string{
			// Shared helpers any VPN document may use.
			"vpnFormatApiError":   fx.CommonJS,
			"vpnStatusBadgeClass": fx.CommonJS,
			"vpnStatusLabel":      fx.CommonJS,
			"vpnSetListenerBadge": fx.CommonJS,
			// Backend management.
			"vpnServerHasAwg":        fx.BackendsJS,
			"vpnRenderBackendRow":    fx.BackendsJS,
			"vpnToggleBackend":       fx.BackendsJS,
			"vpnDeleteBackend":       fx.BackendsJS,
			"vpnResetAddModal":       fx.BackendsJS,
			"vpnOpenAddBackendModal": fx.BackendsJS,
			"vpnOnServerSelected":    fx.BackendsJS,
			"vpnTriggerQuickCheck":   fx.BackendsJS,
			"vpnSubmitAddBackend":    fx.BackendsJS,
			// The endpoint dialog belongs to the overview.
			"vpnOpenEditEndpointModal": fx.OverviewJS,
			"vpnSubmitEditEndpoint":    fx.OverviewJS,
		} {
			if _, err := extractJSFunction(module, "function "+name); err != nil {
				t.Fatalf("expected extractJSFunction %s from its owning module to succeed: %v", name, err)
			}
		}
		for _, name := range []string{
			"vpnToggleShowAllRoutes",
		} {
			if _, err := extractJSFunction(fx.PageJS, "function "+name); err != nil {
				t.Fatalf("expected extractJSFunction %s from PageJS to succeed: %v", name, err)
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
		case "empty_backends":
			clone.BackendsJS = "   \n	  "
		case "empty_page":
			clone.PageJS = "   \n	  "
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
		{"empty_backends", "failed to read static backends asset"},
		{"empty_page", "failed to read static page asset"},
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
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
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
		fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
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
		fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
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
		fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
		nodePath := fixture.RequireNode()
		fixture.HealthProblemsJS = "throw new Error('TROUBLESHOOTING_MODULE_FAILURE');\n" + fixture.HealthProblemsJS

		script := vpnConnectionTroubleshootingScriptLocale(t, fixture.TemplateHTML, fixture.CompanionScripts(), "en", `assert(true);`)
		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error in troubleshooting harness, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "TROUBLESHOOTING_MODULE_FAILURE") {
			t.Fatalf("expected output to mention TROUBLESHOOTING_MODULE_FAILURE, got:\n%s", string(out))
		}
	})

	t.Run("ChartsModuleExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
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
		fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
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

	t.Run("BackendsModuleJSDOMExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixtureForPage(t, "vpn_backends")
		nodePath := fixture.RequireJSDOM()
		fixture.BackendsJS = "throw new Error('BACKENDS_MODULE_FAILURE');\n" + fixture.BackendsJS

		script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
			ExtraJS: `console.log('UNREACHABLE_AFTER_BACKENDS_ERROR');`,
		})

		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error in JSDOM harness, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "BACKENDS_MODULE_FAILURE") {
			t.Fatalf("expected output to mention BACKENDS_MODULE_FAILURE, got:\n%s", string(out))
		}
		if strings.Contains(string(out), "UNREACHABLE_AFTER_BACKENDS_ERROR") {
			t.Fatalf("downstream marker UNREACHABLE_AFTER_BACKENDS_ERROR must be absent, got:\n%s", string(out))
		}
	})

	// The three subtests below used to prove that a broken backend module also broke
	// the health, troubleshooting and localization scripts, because all four modules
	// shipped in one page. They are separate documents now, and the stronger property
	// is the separation itself: a backend module that throws cannot affect any
	// diagnostics script, because no diagnostics document loads it.
	t.Run("BrokenBackendsModuleCannotAffectDiagnostics", func(t *testing.T) {
		diagnostics := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
		nodePath := diagnostics.RequireNode()
		if strings.Contains(diagnostics.CompanionScripts(), diagnostics.BackendsJS) {
			t.Fatal("the diagnostics chain must not contain the backend controller")
		}

		broken := NewVPNTestFixtureForPage(t, "vpn_backends")
		broken.BackendsJS = "throw new Error('BACKENDS_MODULE_FAILURE');\n" + broken.BackendsJS
		for _, harness := range []string{
			func() string {
				script, err := vpnDiagnosticsHealthScriptLocale(t, diagnostics.CombinedSource(), "en", `console.log('DIAGNOSTICS_HEALTH_OK');`)
				if err != nil {
					t.Fatalf("vpnDiagnosticsHealthScriptLocale failed: %v", err)
				}
				return script
			}(),
			vpnConnectionTroubleshootingScriptLocale(t, diagnostics.TemplateHTML, diagnostics.CompanionScripts(), "en", `console.log('DIAGNOSTICS_TROUBLESHOOTING_OK');`),
			vpnDiagnosticsLocalizationScript(t, diagnostics.TemplateHTML, diagnostics.CompanionScripts(), "en"),
		} {
			out, err := execNodeScript(nodePath, harness)
			if err != nil {
				t.Fatalf("a diagnostics script failed while only the backends module was broken: %v\nOutput:\n%s", err, string(out))
			}
			if strings.Contains(string(out), "BACKENDS_MODULE_FAILURE") {
				t.Fatalf("the diagnostics script executed the backend controller:\n%s", string(out))
			}
		}
	})

	t.Run("PageModuleJSDOMExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
		nodePath := fixture.RequireJSDOM()
		fixture.PageJS = "throw new Error('PAGE_MODULE_FAILURE');\n" + fixture.PageJS

		script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
			ExtraJS: `console.log('UNREACHABLE_AFTER_PAGE_ERROR');`,
		})

		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error in JSDOM harness, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "PAGE_MODULE_FAILURE") {
			t.Fatalf("expected output to mention PAGE_MODULE_FAILURE, got:\n%s", string(out))
		}
		if strings.Contains(string(out), "UNREACHABLE_AFTER_PAGE_ERROR") {
			t.Fatalf("downstream marker UNREACHABLE_AFTER_PAGE_ERROR must be absent, got:\n%s", string(out))
		}
	})

	t.Run("PageModuleHealthScriptExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
		nodePath := fixture.RequireNode()
		fixture.PageJS = "throw new Error('PAGE_MODULE_FAILURE');\n" + fixture.PageJS

		script, err := vpnDiagnosticsHealthScriptLocale(t, fixture.CombinedSource(), "en", `console.log('UNREACHABLE_AFTER_PAGE_ERROR');`)
		if err != nil {
			t.Fatalf("vpnDiagnosticsHealthScriptLocale failed: %v", err)
		}

		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error in health script, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "PAGE_MODULE_FAILURE") {
			t.Fatalf("expected output to mention PAGE_MODULE_FAILURE, got:\n%s", string(out))
		}
		if strings.Contains(string(out), "UNREACHABLE_AFTER_PAGE_ERROR") {
			t.Fatalf("downstream marker UNREACHABLE_AFTER_PAGE_ERROR must be absent, got:\n%s", string(out))
		}
	})

	t.Run("PageModuleTroubleshootingHarnessExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
		nodePath := fixture.RequireNode()
		fixture.PageJS = "throw new Error('PAGE_MODULE_FAILURE');\n" + fixture.PageJS

		script := vpnConnectionTroubleshootingScriptLocale(t, fixture.TemplateHTML, fixture.CompanionScripts(), "en", `console.log('UNREACHABLE_AFTER_PAGE_ERROR');`)
		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error in troubleshooting harness, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "PAGE_MODULE_FAILURE") {
			t.Fatalf("expected output to mention PAGE_MODULE_FAILURE, got:\n%s", string(out))
		}
		if strings.Contains(string(out), "UNREACHABLE_AFTER_PAGE_ERROR") {
			t.Fatalf("downstream marker UNREACHABLE_AFTER_PAGE_ERROR must be absent, got:\n%s", string(out))
		}
	})

	t.Run("PageModuleLocalizationScriptExecutionError", func(t *testing.T) {
		fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
		nodePath := fixture.RequireNode()
		fixture.PageJS = "throw new Error('PAGE_MODULE_FAILURE');\n" + fixture.PageJS

		script := vpnDiagnosticsLocalizationScript(t, fixture.TemplateHTML, fixture.CompanionScripts(), "en") + "\nconsole.log('UNREACHABLE_AFTER_PAGE_ERROR');\n"
		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure on injected companion module error in localization script, got nil error\nOutput:\n%s", string(out))
		}
		if !strings.Contains(string(out), "PAGE_MODULE_FAILURE") {
			t.Fatalf("expected output to mention PAGE_MODULE_FAILURE, got:\n%s", string(out))
		}
		if strings.Contains(string(out), "UNREACHABLE_AFTER_PAGE_ERROR") {
			t.Fatalf("downstream marker UNREACHABLE_AFTER_PAGE_ERROR must be absent, got:\n%s", string(out))
		}
	})
}

func TestVPNBackendsExportAuthorityFailsClosed(t *testing.T) {
	// The inventory document loads both the row renderer and the shared labels.
	fixture := NewVPNTestFixtureForPage(t, "vpn_backends")
	nodePath := fixture.RequireJSDOM()

	fnCode, err := extractJSFunction(fixture.CommonJS, "function vpnStatusLabel")
	if err != nil {
		t.Fatalf("extractJSFunction vpnStatusLabel from CommonJS failed: %v", err)
	}
	strippedCommon := strings.Replace(fixture.CommonJS, fnCode, "", 1)

	// 1. Static extraction of missing export function must fail closed
	if _, err := extractJSFunction(strippedCommon, "function vpnStatusLabel"); err == nil {
		t.Fatal("expected extractJSFunction for vpnStatusLabel to fail when stripped, got nil")
	}

	// 2. Harness execution with stripped export must fail closed
	t.Run("JSDOMHarnessExecutionFails", func(t *testing.T) {
		fx := fixture.WithT(t)
		fx.CommonJS = strippedCommon
		script := fx.BuildJSDOMHarness(JSDOMHarnessOptions{
			ExtraJS: `
assert.strictEqual(typeof w.vpnStatusLabel, 'function', 'vpnStatusLabel must be exported');
w.vpnStatusLabel('active');
console.log('UNREACHABLE_AFTER_EXPORT_STRIP');
`,
		})
		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected execution failure when vpnStatusLabel is stripped, got nil error\nOutput:\n%s", string(out))
		}
		if strings.Contains(string(out), "UNREACHABLE_AFTER_EXPORT_STRIP") {
			t.Fatalf("downstream marker UNREACHABLE_AFTER_EXPORT_STRIP must be absent, got:\n%s", string(out))
		}
	})

	// 3. Sessions and routes runner depending on vpnStatusLabel must fail closed
	t.Run("SessionsRoutesRunnerFails", func(t *testing.T) {
		fx := fixture.WithT(t)
		fx.CommonJS = strippedCommon
		script := fx.BuildJSDOMHarness(JSDOMHarnessOptions{
			ExtraJS: `
const row = w.vpnRenderBackendRow({ server_id: 1, endpoint: '203.0.113.1:51820', enabled: true, status: 'active', latency_ms: 10 });
assert(row, 'row rendered');
console.log('UNREACHABLE_AFTER_ROW_RENDER_WITHOUT_STATUS_LABEL');
`,
		})
		out, err := execNodeScript(nodePath, script)
		if err == nil {
			t.Fatalf("expected runner depending on vpnStatusLabel to fail, got nil error\nOutput:\n%s", string(out))
		}
		if strings.Contains(string(out), "UNREACHABLE_AFTER_ROW_RENDER_WITHOUT_STATUS_LABEL") {
			t.Fatalf("downstream marker must be absent, got:\n%s", string(out))
		}
	})
}

func TestVPNFixtureLoaderSeamAssetFailClosed(t *testing.T) {
	if mode := os.Getenv("TEST_VPN_LOADER_SEAM_CASE"); mode != "" {
		baseFS := fstest.MapFS{
			"static/css/style.css":              &fstest.MapFile{Data: []byte("body { margin: 0; }")},
			"static/js/vpn/sessions.js":         &fstest.MapFile{Data: []byte("function vpnRenderSessions() {}")},
			"static/js/vpn/health_problems.js":  &fstest.MapFile{Data: []byte("function vpnEvaluateHealth() {}")},
			"static/js/vpn/health_summary.js":   &fstest.MapFile{Data: []byte("function vpnRenderForwarderHealth() {}")},
			"static/js/vpn/charts.js":           &fstest.MapFile{Data: []byte("function vpnRenderHistoryCharts() {}")},
			"static/js/vpn/backends.js":         &fstest.MapFile{Data: []byte("function vpnRenderBackendRow() {}")},
			"static/js/vpn/common.js":           &fstest.MapFile{Data: []byte("function vpnAssignText() {}")},
			"static/js/vpn/overview.js":         &fstest.MapFile{Data: []byte("function vpnLoadOverview() {}")},
			"static/js/vpn/backends_page.js":    &fstest.MapFile{Data: []byte("function vpnLoadBackends() {}")},
			"static/js/vpn/diagnostics_page.js": &fstest.MapFile{Data: []byte("function vpnLoadDiagnostics() {}")},
			"static/js/vpn/anchor_handoff.js":   &fstest.MapFile{Data: []byte("function vpnAnchorOwner() {}")},
			"static/js/vpn/page.js":             &fstest.MapFile{Data: []byte("function vpnBoot() {}")},
			"static/js/tables.js":               &fstest.MapFile{Data: []byte("function NexusTable() {}")},
		}
		switch mode {
		case "missing_charts":
			delete(baseFS, "static/js/vpn/charts.js")
		case "decoy_alternate_root_charts":
			delete(baseFS, "static/js/vpn/charts.js")
			baseFS["js/vpn/charts.js"] = &fstest.MapFile{Data: []byte("function vpnRenderHistoryCharts() { /* decoy */ }")}
		case "empty_charts":
			baseFS["static/js/vpn/charts.js"] = &fstest.MapFile{Data: []byte("")}
		case "whitespace_charts":
			baseFS["static/js/vpn/charts.js"] = &fstest.MapFile{Data: []byte("   \n	  \r\n")}
		case "missing_backends":
			delete(baseFS, "static/js/vpn/backends.js")
		case "decoy_alternate_root_backends":
			delete(baseFS, "static/js/vpn/backends.js")
			baseFS["js/vpn/backends.js"] = &fstest.MapFile{Data: []byte("function vpnRenderBackendRow() { /* decoy */ }")}
		case "empty_backends":
			baseFS["static/js/vpn/backends.js"] = &fstest.MapFile{Data: []byte("")}
		case "whitespace_backends":
			baseFS["static/js/vpn/backends.js"] = &fstest.MapFile{Data: []byte("   \n	  \r\n")}
		case "missing_common":
			delete(baseFS, "static/js/vpn/common.js")
		case "decoy_alternate_root_common":
			delete(baseFS, "static/js/vpn/common.js")
			baseFS["js/vpn/common.js"] = &fstest.MapFile{Data: []byte("function vpnAssignText() { /* decoy */ }")}
		case "empty_common":
			baseFS["static/js/vpn/common.js"] = &fstest.MapFile{Data: []byte("")}
		case "whitespace_common":
			baseFS["static/js/vpn/common.js"] = &fstest.MapFile{Data: []byte("   \n\t  \r\n")}
		case "missing_overview":
			delete(baseFS, "static/js/vpn/overview.js")
		case "decoy_alternate_root_overview":
			delete(baseFS, "static/js/vpn/overview.js")
			baseFS["js/vpn/overview.js"] = &fstest.MapFile{Data: []byte("function vpnLoadOverview() { /* decoy */ }")}
		case "empty_overview":
			baseFS["static/js/vpn/overview.js"] = &fstest.MapFile{Data: []byte("")}
		case "whitespace_overview":
			baseFS["static/js/vpn/overview.js"] = &fstest.MapFile{Data: []byte("   \n\t  \r\n")}
		case "missing_page":
			delete(baseFS, "static/js/vpn/overview.js")
		case "decoy_alternate_root_page":
			delete(baseFS, "static/js/vpn/overview.js")
			baseFS["js/vpn/overview.js"] = &fstest.MapFile{Data: []byte("function vpnLoadOverview() { /* decoy */ }")}
		case "empty_page":
			baseFS["static/js/vpn/overview.js"] = &fstest.MapFile{Data: []byte("")}
		case "whitespace_page":
			baseFS["static/js/vpn/overview.js"] = &fstest.MapFile{Data: []byte("   \n\t  \r\n")}
		default:
			t.Fatalf("unknown test mode: %s", mode)
		}
		newVPNTestFixtureWithFS(t, baseFS, "vpn")
		return
	}

	for _, tc := range []struct {
		mode      string
		errSubstr string
	}{
		{"missing_charts", "failed to read static charts asset static/js/vpn/charts.js"},
		{"decoy_alternate_root_charts", "failed to read static charts asset static/js/vpn/charts.js"},
		{"empty_charts", "failed to read static charts asset static/js/vpn/charts.js: empty content"},
		{"whitespace_charts", "failed to read static charts asset static/js/vpn/charts.js: empty content"},
		{"missing_backends", "failed to read static backends asset static/js/vpn/backends.js"},
		{"decoy_alternate_root_backends", "failed to read static backends asset static/js/vpn/backends.js"},
		{"empty_backends", "failed to read static backends asset static/js/vpn/backends.js: empty content"},
		{"whitespace_backends", "failed to read static backends asset static/js/vpn/backends.js: empty content"},
		{"missing_common", "failed to read static page asset static/js/vpn/common.js"},
		{"decoy_alternate_root_common", "failed to read static page asset static/js/vpn/common.js"},
		{"empty_common", "failed to read static page asset static/js/vpn/common.js: empty content"},
		{"whitespace_common", "failed to read static page asset static/js/vpn/common.js: empty content"},
		{"missing_overview", "failed to read static page asset static/js/vpn/overview.js"},
		{"decoy_alternate_root_overview", "failed to read static page asset static/js/vpn/overview.js"},
		{"empty_overview", "failed to read static page asset static/js/vpn/overview.js: empty content"},
		{"whitespace_overview", "failed to read static page asset static/js/vpn/overview.js: empty content"},
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
			"static/css/style.css":              &fstest.MapFile{Data: []byte("body { margin: 0; }")},
			"static/js/vpn/sessions.js":         &fstest.MapFile{Data: []byte("function vpnRenderSessions() {}")},
			"static/js/vpn/health_problems.js":  &fstest.MapFile{Data: []byte("function vpnEvaluateHealth() {}")},
			"static/js/vpn/health_summary.js":   &fstest.MapFile{Data: []byte("function vpnRenderForwarderHealth() {}")},
			"static/js/vpn/charts.js":           &fstest.MapFile{Data: []byte("function vpnRenderHistoryCharts() {}")},
			"static/js/vpn/backends.js":         &fstest.MapFile{Data: []byte("function vpnRenderBackendRow() {}")},
			"static/js/vpn/common.js":           &fstest.MapFile{Data: []byte("function vpnAssignText() {}")},
			"static/js/vpn/overview.js":         &fstest.MapFile{Data: []byte("function vpnLoadOverview() {}")},
			"static/js/vpn/backends_page.js":    &fstest.MapFile{Data: []byte("function vpnLoadBackends() {}")},
			"static/js/vpn/diagnostics_page.js": &fstest.MapFile{Data: []byte("function vpnLoadDiagnostics() {}")},
			"static/js/vpn/anchor_handoff.js":   &fstest.MapFile{Data: []byte("function vpnAnchorOwner() {}")},
			"static/js/vpn/page.js":             &fstest.MapFile{Data: []byte("function vpnBoot() {}")},
			"static/js/tables.js":               &fstest.MapFile{Data: []byte("function NexusTable() {}")},
		}
		fx := newVPNTestFixtureWithFS(t, validFS, "vpn")
		if fx == nil {
			t.Fatal("expected non-nil fixture from valid MapFS")
		}
		if fx.ChartsJS != "function vpnRenderHistoryCharts() {}" {
			t.Fatalf("unexpected ChartsJS content: %s", fx.ChartsJS)
		}
		if fx.BackendsJS != "function vpnRenderBackendRow() {}" {
			t.Fatalf("unexpected BackendsJS content: %s", fx.BackendsJS)
		}
		if fx.PageJS != "function vpnLoadOverview() {}" {
			t.Fatalf("unexpected PageJS content: %s", fx.PageJS)
		}
		if fx.DiagnosticsPageJS != "function vpnLoadDiagnostics() {}" {
			t.Fatalf("unexpected DiagnosticsPageJS content: %s", fx.DiagnosticsPageJS)
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

func TestVPNPageBootDOMContentLoadedMutationFailsClosed(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	fixture.RequireJSDOM()

	// The boot is what starts the page's streams, so the mutation targets the boot's
	// own readiness hook. Mutating a section module would only prove that a section
	// has a listener; the page's first paint depends on this one.
	if !strings.Contains(fixture.PageBootJS, "DOMContentLoaded") {
		t.Fatal("expected fixture.PageBootJS to contain DOMContentLoaded")
	}

	mutatedFx := *fixture
	// Replace EVERY occurrence: the boot names the event once in its readiness hook
	// and discusses it in a comment, so a first-occurrence replace would land in the
	// comment and leave the hook intact - a mutant that proves nothing.
	mutatedFx.PageBootJS = strings.ReplaceAll(fixture.PageBootJS, "DOMContentLoaded", "never-fired-mutant")
	if mutatedFx.PageBootJS == fixture.PageBootJS {
		t.Fatal("the mutation did not apply")
	}

	testScript := mutatedFx.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
// Install real NexusTelemetry
const candidatePaths = ['static/js/telemetry.js', 'web/static/js/telemetry.js'];
let telemetryCode = '';
for (const cp of candidatePaths) {
    if (fs.existsSync(cp)) { telemetryCode = fs.readFileSync(cp, 'utf8'); break; }
}
if (!telemetryCode) { throw new Error('telemetry.js not found in candidate paths'); }
const sTel = w.document.createElement('script');
sTel.textContent = telemetryCode;
w.document.body.appendChild(sTel);

w.API = {
    get: async () => ({})
};

(async () => {
    // Await natural readiness. The mutant never starts a stream, so nothing else in
    // this document is waiting on the page: the assertion below is the whole test.
    await new Promise(resolve => w.document.addEventListener('DOMContentLoaded', resolve, { once: true }));
    for (let i = 0; i < 20; i++) await Promise.resolve();

    const activeStreams = w.NexusTelemetry.getActiveStreams();
    assert.ok(activeStreams.includes('vpn-overview'), 'vpn-overview must be registered in active streams');
    console.log('MUTATION_UNEXPECTEDLY_PASSED');
    if (dom && dom.window) dom.window.close();
})().catch(e => {
    console.error('MUTATION_FAILED_CLOSED: ' + e.message);
    if (dom && dom.window) dom.window.close();
    process.exit(1);
});
`,
	})

	out, err := execNodeScript(fixture.RequireNode(), testScript)
	if err == nil {
		t.Fatalf("expected mutant script to fail, but process succeeded with output:\n%s", string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "MUTATION_FAILED_CLOSED") || !strings.Contains(outStr, "vpn-overview must be registered") {
		t.Fatalf("expected failure output mentioning 'MUTATION_FAILED_CLOSED' and 'vpn-overview must be registered', got:\n%s", outStr)
	}
}
