package vpn

import (
	"errors"
	"math"
	"sort"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Issue #424 review round 9, BLOCKER 3 and BLOCKER 4.
//
// BLOCKER 3: critical loss reasons were reduced to generic aggregate drop-rate
// thresholds. TotalDropRatePps sums EVERY reason, so reason identity was never
// consulted: an ownership mismatch — which #424 treats as critical — was
// classified exactly like routine queue-full churn, and the CLIENT-direction
// ownership-mismatch counter was not wired into routing health at all, so a
// small number of them produced a HEALTHY headline.
//
// BLOCKER 4: a partial enabled-backend failure was emitted at WARNING, and
// summarizeHealthConditions maps WARNING-only to HEALTHY, so two enabled
// backends with one healthy reported HEALTHY.
//
// The disjointness requirement is load-bearing: round 5 of this review was
// entirely about double-counted losses. Every test below therefore also
// asserts that a loss already claimed by a reason-specific condition is
// EXCLUDED from the generic aggregate condition, so one physical loss yields
// exactly one condition.

// conditionsIn returns every condition in the given category.
func conditionsIn(conds []HealthCondition, category string) []HealthCondition {
	var out []HealthCondition
	for _, c := range conds {
		if c.Category == category {
			out = append(out, c)
		}
	}
	return out
}

// assertSingleCondition fails unless exactly one condition exists in category,
// and returns it.
func assertSingleCondition(t *testing.T, conds []HealthCondition, category string) HealthCondition {
	t.Helper()
	got := conditionsIn(conds, category)
	if len(got) != 1 {
		t.Fatalf("expected exactly ONE %q condition (one loss, one condition), got %d: %+v",
			category, len(got), got)
	}
	return got[0]
}

// B3 regression: a SPARSE number of CLIENT-direction ownership mismatches must
// classify at the reason's own severity. Before the fix the client-direction
// counter was never evaluated, so routing stayed consistent and the headline
// stayed HEALTHY.
func TestB3SparseClientOwnershipMismatchClassifiesAtReasonSeverity(t *testing.T) {
	th := DefaultHealthThresholds
	svc := &Service{}

	// Prime the window: the delta tracker's first sample only establishes the
	// baseline, so a counter that was already non-zero is not a fresh incident.
	checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, 0)
	time.Sleep(250 * time.Millisecond)

	// A handful of client-direction ownership mismatches. Sparse on purpose:
	// the aggregate rate this produces is far below DropRateDegradedPPS.
	const sparseClient = 2
	diag := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, sparseClient)

	if diag.ClientOwnershipMismatchDrops != sparseClient {
		t.Fatalf("client cumulative mismatch not wired into routing: %d, want %d",
			diag.ClientOwnershipMismatchDrops, sparseClient)
	}
	if diag.ClientOwnershipMismatchDropsRecent != sparseClient {
		t.Fatalf("client recent mismatch=%d, want %d", diag.ClientOwnershipMismatchDropsRecent, sparseClient)
	}
	if diag.IsConsistent {
		t.Fatal("routing reported consistent despite current-window ownership mismatches")
	}

	conds := evaluateRoutingConditions(diag)
	cond := assertSingleCondition(t, conds, "routing")
	if cond.Severity != "CRITICAL" {
		t.Fatalf("sparse client ownership mismatch severity=%q, want CRITICAL: %q", cond.Severity, cond.Message)
	}
	if diag.ClientOwnershipMismatchDropsRecent < th.OwnershipMismatchCriticalDrops {
		t.Fatalf("test does not exercise the critical threshold: recent=%d threshold=%d",
			diag.ClientOwnershipMismatchDropsRecent, th.OwnershipMismatchCriticalDrops)
	}

	// The headline must not be HEALTHY, and it must be CRITICAL rather than
	// merely DEGRADED.
	health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		DropCategoryBreakdown{}, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})
	if health.Status == HealthHealthy || health.Status == HealthDegraded {
		t.Fatalf("headline=%s: a current-window ownership mismatch must not read below CRITICAL (%s)",
			health.Status, health.Summary)
	}
	if health.Status != HealthCritical {
		t.Fatalf("headline=%s, want CRITICAL", health.Status)
	}
}

// B3 regression: escalating RETURN-direction ownership mismatches reach CRITICAL.
// Before the fix the aggregate drop-rate threshold downgraded them to DEGRADED.
func TestB3EscalatingReturnOwnershipMismatchReachesCritical(t *testing.T) {
	svc := &Service{}
	checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, 0)
	time.Sleep(250 * time.Millisecond)

	const escalating = 500
	diag := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: escalating}, 0)
	if diag.OwnershipMismatchDropsRecent != escalating {
		t.Fatalf("return recent mismatch=%d, want %d", diag.OwnershipMismatchDropsRecent, escalating)
	}
	cond := assertSingleCondition(t, evaluateRoutingConditions(diag), "routing")
	if cond.Severity != "CRITICAL" {
		t.Fatalf("escalating return ownership mismatch severity=%q, want CRITICAL: %q",
			cond.Severity, cond.Message)
	}
}

// B3 regression: injection failures classify CRITICAL. Before the fix they were
// only ever visible through the aggregate drop rate, i.e. DEGRADED at best.
func TestB3InjectionFailuresClassifyCritical(t *testing.T) {
	th := DefaultHealthThresholds
	drops := DropCategoryBreakdown{
		TotalDropRatePps: 1.0, // far below DropRateDegradedPPS
		RatesAvailable:   true,
		ReasonRates:      map[string]float64{reasonReturnInjectionErrors: 1.0},
	}
	quiet := RoutingConsistencyDiagnostics{IsConsistent: true}

	conds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), drops, quiet, 0)
	cond := assertSingleCondition(t, conds, "drops")
	if cond.Severity != "CRITICAL" {
		t.Fatalf("injection failure severity=%q, want CRITICAL: %q", cond.Severity, cond.Message)
	}
	if !strings.Contains(cond.Message, "injection") {
		t.Errorf("injection condition must name its reason: %q", cond.Message)
	}
	if 1.0 <= th.InjectionFailureCriticalRatePPS {
		t.Fatalf("test does not exercise the critical threshold: %v <= %v",
			1.0, th.InjectionFailureCriticalRatePPS)
	}

	// Boundary: the comparison is STRICT >. A zero measured rate must not fire
	// and an arbitrarily small positive one must, which pins the operator; the
	// threshold's own value of 0 is pinned by
	// TestDefaultHealthThresholdsPreservePreviousLiterals.
	for _, tc := range []struct {
		name string
		rate float64
		want string
	}{
		{"a zero measured rate does not fire", 0, ""},
		{"an arbitrarily small positive rate does fire", math.SmallestNonzeroFloat64, "CRITICAL"},
		{"an ordinary failure rate fires", 12.5, "CRITICAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := DropCategoryBreakdown{
				TotalDropRatePps: 0.5,
				RatesAvailable:   true,
				ReasonRates:      map[string]float64{reasonReturnInjectionErrors: tc.rate},
			}
			got := conditionsIn(evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), d, quiet, 0), "drops")
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected no drops condition, got %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Severity != tc.want {
				t.Fatalf("rate=%v: got %+v, want one %s", tc.rate, got, tc.want)
			}
		})
	}

	// An UNMEASURED window is unknown, not bad: no critical injection condition
	// may be fabricated before a rate has been sampled.
	unmeasured := DropCategoryBreakdown{
		TotalDropRatePps: 0,
		RatesAvailable:   false,
		ReasonRates:      map[string]float64{reasonReturnInjectionErrors: 99.0},
	}
	if got := conditionsIn(evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), unmeasured, quiet, 0), "drops"); len(got) != 0 {
		t.Fatalf("unmeasured reason rates must not produce a condition: %+v", got)
	}
}

// B3 regression, over-correction guard: high-volume ROUTINE queue-full loss is
// DEGRADED and never CRITICAL. This is what rules out "lower the generic
// thresholds" as the fix: queue-full is a capacity reason, not a critical one.
func TestB3HighVolumeRoutineQueueFullIsNotCritical(t *testing.T) {
	drops := DropCategoryBreakdown{
		TotalDropRatePps: 100000,
		RatesAvailable:   true,
		ReasonRates: map[string]float64{
			reasonReturnQueueFull: 100000,
		},
	}
	conds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), drops,
		RoutingConsistencyDiagnostics{IsConsistent: true}, 0)
	cond := assertSingleCondition(t, conds, "drops")
	if cond.Severity != "DEGRADED" {
		t.Fatalf("high-volume routine queue-full loss severity=%q, want DEGRADED (never CRITICAL): %q",
			cond.Severity, cond.Message)
	}
	if !strings.Contains(cond.Message, "routine") {
		t.Errorf("aggregate condition must describe the routine population it covers: %q", cond.Message)
	}
}

// B3 regression, disjointness: a loss claimed by a reason-specific condition
// must NOT also raise the generic aggregate condition. Both directions of
// ownership mismatch plus injection failures together still yield exactly one
// routing condition and one drops condition, and no routine-population
// condition over the same losses.
func TestB3OneLossNeverYieldsTwoConditions(t *testing.T) {
	svc := &Service{}
	checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, 0)
	time.Sleep(250 * time.Millisecond)

	diag := checkRoutingInvariants(svc, nil,
		ReturnStatsSnapshot{OwnershipMismatchDrops: 40}, 60)
	if diag.ClientOwnershipMismatchDropsRecent == 0 || diag.OwnershipMismatchDropsRecent == 0 {
		t.Fatalf("both directions must contribute: %+v", diag)
	}

	// The aggregate carries exactly the losses the reason-specific conditions
	// already claim, and nothing else.
	mismatchRate := diag.OwnershipMismatchRatePPS()
	injectionRate := 25.0
	drops := DropCategoryBreakdown{
		TotalDropRatePps: mismatchRate + injectionRate,
		RatesAvailable:   true,
		ReasonRates:      map[string]float64{reasonReturnInjectionErrors: injectionRate},
	}

	// The FULL condition set, so the disjointness claim is made about what an
	// operator actually sees rather than about one evaluator in isolation.
	conds := append(evaluateRoutingConditions(diag),
		evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), drops, diag, 0)...)

	routingConds := conditionsIn(conds, "routing")
	if len(routingConds) != 1 {
		t.Fatalf("both mismatch directions must collapse into ONE routing condition, got %d: %+v",
			len(routingConds), routingConds)
	}
	if routingConds[0].Severity != "CRITICAL" {
		t.Fatalf("routing severity=%q, want CRITICAL", routingConds[0].Severity)
	}
	// The single routing condition must account for BOTH directions.
	for _, want := range []string{"client", "return"} {
		if !strings.Contains(routingConds[0].Message, want) {
			t.Errorf("routing condition must name the %s direction: %q", want, routingConds[0].Message)
		}
	}

	dropsConds := conditionsIn(conds, "drops")
	if len(dropsConds) != 1 {
		t.Fatalf("expected exactly ONE drops condition (injection failures), got %d: %+v",
			len(dropsConds), dropsConds)
	}
	if dropsConds[0].Severity != "CRITICAL" {
		t.Fatalf("drops severity=%q, want CRITICAL", dropsConds[0].Severity)
	}

	// Nothing anywhere may describe the routine population: the aggregate rate
	// consisted only of losses already reported.
	for _, c := range conds {
		if strings.Contains(c.Message, "routine") {
			t.Fatalf("a routine-population condition double-counts reason-specific losses: %+v", c)
		}
	}

	// Add genuine routine loss on top: now, and only now, the routine
	// condition appears — as DEGRADED, alongside the two criticals, not
	// replacing them.
	withRoutine := drops
	withRoutine.TotalDropRatePps += 1000
	withRoutine.ReasonRates[reasonReturnQueueFull] = 1000
	mixed := append(evaluateRoutingConditions(diag),
		evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), withRoutine, diag, 0)...)

	mixedDrops := conditionsIn(mixed, "drops")
	if len(mixedDrops) != 2 {
		t.Fatalf("expected injection CRITICAL plus one routine DEGRADED, got %d: %+v",
			len(mixedDrops), mixedDrops)
	}
	// The routine condition must be DEGRADED even alongside a CRITICAL sibling:
	// queue-full is a capacity reason, not a critical one, and 1000 drops/sec
	// of it must never escalate on volume alone.
	var routineSev string
	for _, c := range mixedDrops {
		if strings.Contains(c.Message, "routine drop rate") {
			routineSev = c.Severity
		}
	}
	if routineSev != "DEGRADED" {
		t.Fatalf("routine drop condition severity=%q, want DEGRADED: %+v", routineSev, mixedDrops)
	}
}

// B3 regression: reason-specific conditions are gated on CURRENT-window data,
// so a historical counter cannot pin CRITICAL after recovery (the round 2
// property, preserved for the reason-keyed path).
func TestB3RecoveredCriticalReasonDoesNotPinCritical(t *testing.T) {
	svc := &Service{}
	checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, 0)
	time.Sleep(250 * time.Millisecond)
	checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: 300}, 5)
	time.Sleep(250 * time.Millisecond)
	diag := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: 300}, 5)

	if !diag.IsConsistent {
		t.Fatalf("routing must recover once the mismatch window is quiet: %+v", diag.InconsistencyDetails)
	}
	if got := evaluateRoutingConditions(diag); len(got) != 0 {
		t.Fatalf("recovered routing must produce no condition, got %+v", got)
	}
	if len(diag.HistoricalDetails) != 1 {
		t.Fatalf("the recovered incident must stay visible as exactly one historical note, got %v",
			diag.HistoricalDetails)
	}
}

// B3: the reason keys the evaluator gates on must be keys the drop-reason
// tracker actually publishes, or the conditions would silently never fire. It
// also pins the disjointness invariant structurally: every critical reason has
// exactly ONE owning evaluator, because an ownership owned twice is a
// double-counted condition.
func TestB3CriticalReasonKeysArePublishedReasons(t *testing.T) {
	published := dropReasonTotals(DropCategoryBreakdown{})
	owners := map[string][]string{}
	for key, claim := range criticalLossReasons {
		if _, ok := published[key]; !ok {
			t.Errorf("critical reason key %q is not published by dropReasonTotals: its gate would never fire", key)
		}
		switch claim {
		case claimRouting:
			owners["routing"] = append(owners["routing"], key)
		case claimDrops:
			owners["drops"] = append(owners["drops"], key)
		default:
			t.Errorf("critical reason %q has unknown owner %d", key, claim)
		}
	}
	// The map's key domain already guarantees one owner per reason; assert the
	// expected ownership explicitly so re-pointing a reason at the wrong
	// evaluator (which would double-count it) fails here.
	wantOwners := map[string][]string{
		"routing": {reasonClientOwnershipMismatch, reasonReturnOwnershipMismatch},
		"drops":   {reasonReturnInjectionErrors},
	}
	for evaluator, want := range wantOwners {
		got := append([]string(nil), owners[evaluator]...)
		sort.Strings(got)
		if len(got) != len(want) {
			t.Errorf("%s evaluator owns %v, want %v", evaluator, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s evaluator owns %v, want %v", evaluator, got, want)
				break
			}
		}
	}
	if len(criticalLossReasons) != len(wantOwners["routing"])+len(wantOwners["drops"]) {
		t.Errorf("a critical reason is owned by no evaluator or an unknown one: %v", criticalLossReasons)
	}
}

// B4: the reviewer's exact scenario. Two enabled backends, one healthy: the
// headline must be DEGRADED. Before the fix this was a WARNING condition, and
// summarizeHealthConditions maps WARNING-only to HEALTHY.
func TestB4PartialEnabledBackendFailureIsDegraded(t *testing.T) {
	conds := evaluatePeerSyncAndBackendConditions(nil,
		BackendsDiagnostics{
			EligibilityKnown: true,
			EnabledCount:     2,
			HealthyCount:     1,
			TotalCount:       2,
		}, HandshakeFreshnessDiagnostics{})

	cond := assertSingleCondition(t, conds, "backend")
	if cond.Severity != "DEGRADED" {
		t.Fatalf("partial enabled-backend failure severity=%q, want DEGRADED: %q", cond.Severity, cond.Message)
	}
	if !strings.Contains(cond.Message, "enabled") {
		t.Errorf("the message must scope the population to ENABLED backends: %q", cond.Message)
	}

	status, summary := summarizeHealthConditions(conds)
	if status != HealthDegraded {
		t.Fatalf("headline=%s (%s), want DEGRADED", status, summary)
	}
}

// B4: the full scenario matrix, including the failed-versus-disabled
// distinction and the unchanged all-disabled CRITICAL case.
func TestB4BackendFailureClassificationMatrix(t *testing.T) {
	for _, tc := range []struct {
		name     string
		backends BackendsDiagnostics
		wantSev  string
		wantHas  string
		absent   string
	}{
		{
			name:     "two enabled one healthy is DEGRADED",
			backends: BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 2, HealthyCount: 1, TotalCount: 2},
			wantSev:  "DEGRADED", wantHas: "1 of 2 enabled",
		},
		{
			name:     "one enabled backend failing entirely is CRITICAL",
			backends: BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 1, HealthyCount: 0, TotalCount: 1},
			wantSev:  "CRITICAL", wantHas: "No healthy backends",
		},
		{
			name:     "all backends administratively disabled stays CRITICAL",
			backends: BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 0, DisabledCount: 2, HealthyCount: 0, TotalCount: 2},
			wantSev:  "CRITICAL", wantHas: "administratively disabled",
		},
		{
			name:     "disabled-but-healthy is never counted as a failure",
			backends: BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 2, DisabledCount: 1, HealthyCount: 1, TotalCount: 3},
			wantSev:  "DEGRADED", wantHas: "1 of 2 enabled", absent: "3 of 3",
		},
		{
			name:     "every enabled backend healthy while others are disabled is HEALTHY",
			backends: BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 2, DisabledCount: 1, HealthyCount: 2, TotalCount: 3},
			wantSev:  "", wantHas: "",
		},
		{
			name:     "legacy caller without eligibility knowledge degrades on the enabled-equivalent count",
			backends: BackendsDiagnostics{EligibilityKnown: false, TotalCount: 2, HealthyCount: 1},
			wantSev:  "DEGRADED", wantHas: "1 of 2 enabled",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conds := evaluatePeerSyncAndBackendConditions(nil, tc.backends, HandshakeFreshnessDiagnostics{})
			got := conditionsIn(conds, "backend")
			if tc.wantSev == "" {
				if len(got) != 0 {
					t.Fatalf("expected no backend condition, got %+v", got)
				}
				if status, _ := summarizeHealthConditions(conds); status != HealthHealthy {
					t.Fatalf("expected HEALTHY, got %s", status)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected exactly one backend condition, got %d: %+v", len(got), got)
			}
			if got[0].Severity != tc.wantSev {
				t.Fatalf("severity=%q, want %q: %s", got[0].Severity, tc.wantSev, got[0].Message)
			}
			if !strings.Contains(got[0].Message, tc.wantHas) {
				t.Errorf("message %q does not contain %q", got[0].Message, tc.wantHas)
			}
			if tc.absent != "" && strings.Contains(got[0].Message, tc.absent) {
				t.Errorf("message %q must not contain %q", got[0].Message, tc.absent)
			}
		})
	}
}

// B4 guard on the OTHER summarizer branch: genuinely advisory WARNING-only
// conditions must still read HEALTHY. The fix is B4's condition severity, not
// a blanket change to summarizeHealthConditions.
func TestB4WarningOnlyConditionsStillMapToHealthy(t *testing.T) {
	conds := evaluatePeerSyncAndBackendConditions(nil,
		BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 2, HealthyCount: 2, TotalCount: 2},
		HandshakeFreshnessDiagnostics{TotalPeers: 3, StaleLiveSessions: []string{"peer-a"}})

	backend := conditionsIn(conds, "backend")
	if len(backend) != 0 {
		t.Fatalf("a fully healthy fleet must emit no backend condition: %+v", backend)
	}
	if !hasCondition(conds, "sessions", "WARNING") {
		t.Fatalf("expected the stale-handshake WARNING: %+v", conds)
	}
	status, summary := summarizeHealthConditions(conds)
	if status != HealthHealthy {
		t.Fatalf("WARNING-only must still summarize to HEALTHY, got %s (%s)", status, summary)
	}

	// Direct check of the summarizer branch itself, independent of any producer.
	if st, _ := summarizeHealthConditions([]HealthCondition{
		{Category: "queue_pressure", Severity: "WARNING", Message: "advisory"},
		{Category: "sessions", Severity: "WARNING", Message: "advisory too"},
	}); st != HealthHealthy {
		t.Fatalf("summarizer WARNING branch changed: %s", st)
	}

	// And a WARNING alongside a DEGRADED backend failure must not mask it.
	mixed := append(conds, evaluatePeerSyncAndBackendConditions(nil,
		BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 2, HealthyCount: 1, TotalCount: 2},
		HandshakeFreshnessDiagnostics{})...)
	if st, _ := summarizeHealthConditions(mixed); st != HealthDegraded {
		t.Fatalf("a backend failure alongside warnings must read DEGRADED, got %s", st)
	}
}

// B4: the production collector must feed the classification correctly, so the
// reviewer's scenario is exercised end to end and not only as a struct literal.
func TestB4ProductionFleetCollectorDistinguishesDisabledFromFailed(t *testing.T) {
	svc := &Service{}
	diags := collectBackendDiagnostics(svc)
	if diags.EligibilityKnown != true || diags.TotalCount != 0 {
		t.Fatalf("empty fleet baseline changed: %+v", diags)
	}
	conds := evaluatePeerSyncAndBackendConditions(nil, diags, HandshakeFreshnessDiagnostics{})
	if got := conditionsIn(conds, "backend"); len(got) != 1 || got[0].Severity != "CRITICAL" {
		t.Fatalf("an empty fleet must stay CRITICAL: %+v", got)
	}
	if !strings.Contains(conds[0].Message, "configured") {
		t.Errorf("empty fleet message must say nothing is configured: %q", conds[0].Message)
	}
}

// B3+B4 together: the two fixes must compose into one headline decision.
func TestB3B4HeadlineComposition(t *testing.T) {
	th := DefaultHealthThresholds
	svc := &Service{}
	checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, 0)
	time.Sleep(250 * time.Millisecond)
	diag := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: 12}, 3)

	if th.OwnershipMismatchCriticalDrops != 1 {
		t.Fatalf("threshold moved from the value this test pins: %v", th.OwnershipMismatchCriticalDrops)
	}

	drops := DropCategoryBreakdown{
		TotalDropRatePps: 0.25,
		RatesAvailable:   true,
		ReasonRates:      map[string]float64{reasonClientOwnershipMismatch: 0.25},
	}
	health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		drops, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 2, HealthyCount: 1, TotalCount: 2})

	if health.Status != HealthCritical {
		t.Fatalf("headline=%s, want CRITICAL (ownership mismatch outranks the backend degradation): %s",
			health.Status, health.Summary)
	}
	if !strings.Contains(health.Summary, "mismatch") {
		t.Errorf("headline must describe the winning CRITICAL condition: %q", health.Summary)
	}
	if !hasCondition(health.Conditions, "backend", "DEGRADED") {
		t.Errorf("the backend degradation must still be reported: %+v", health.Conditions)
	}

	// Removing the mismatch leaves exactly the B4 scenario: DEGRADED, not
	// HEALTHY. This is the before/after of the reported defect in one place.
	recovered := diag
	recovered.IsConsistent = true
	recovered.InconsistencyDetails = nil
	after := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		DropCategoryBreakdown{}, quietVirtualTUN(), nil, recovered, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 2, HealthyCount: 1, TotalCount: 2})
	if after.Status != HealthDegraded {
		t.Fatalf("after mismatch recovery the headline must be DEGRADED (B4), got %s: %s",
			after.Status, after.Summary)
	}
	// The recovered case must carry exactly the backend degradation and
	// nothing else: no residual critical, and no leftover routing condition.
	if n := len(after.Conditions); n != 1 {
		t.Fatalf("expected exactly one condition after recovery, got %d: %+v", n, after.Conditions)
	}
	if c := conditionsIn(after.Conditions, "backend"); len(c) != 1 || c[0].Severity != "DEGRADED" {
		t.Fatalf("expected one DEGRADED backend condition, got %+v", after.Conditions)
	}
	if r := conditionsIn(after.Conditions, "routing"); len(r) != 0 {
		t.Fatalf("a recovered routing invariant must emit no routing condition, got %+v", r)
	}
}

// B3 regression (Finding B3): low-rate (1 packet/sec) real client-side backend queue loss
// must report DEGRADED with a condition identifying client backend queue full.
// Prior to the fix, 1 pkt/sec produced generic WARNING which summarized to HEALTHY.
func TestB3ClientBackendQueueLossRefusalDegradesHealth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := forwarder.NewForwarder(nil, "192.0.2.0/24", 1)
		path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
		f.RegisterSessionWithReturnPath("s", "c", "peer", "192.0.2.1", 1, path)
		packet := returnPacket("192.0.2.1")
		packet[12], packet[13], packet[14], packet[15] = 192, 0, 2, 1
		for range forwarder.DefaultBackendQueueSize {
			if err := f.RouteClientToBackend("peer", packet); err != nil {
				t.Fatal(err)
			}
		}
		svc := &Service{forwarder: f}
		var baseline Status
		svc.populateOperationalDiagnostics(&baseline)
		time.Sleep(time.Second)
		if err := f.RouteClientToBackend("peer", packet); !errors.Is(err, forwarder.ErrQueueFull) {
			t.Fatalf("expected actual refusal, got %v", err)
		}
		var status Status
		svc.populateOperationalDiagnostics(&status)
		if status.DropCategories.ReasonRates["client_backend_queue_full"] != 1 {
			t.Fatalf("probe did not establish the loss rate: %+v", status.DropCategories.ReasonRates)
		}
		health := EvaluateForwarderHealth(true, true, status.QueuePressure, status.ForwardLatency, status.DropCategories, status.VirtualTUN, nil,
			RoutingConsistencyDiagnostics{IsConsistent: true}, HandshakeFreshnessDiagnostics{},
			BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 1, HealthyCount: 1, TotalCount: 1})
		t.Logf("actual client queue refusal: reason_rate=%v return_queue_rate=%v total_rate=%v health=%s conditions=%+v",
			status.DropCategories.ReasonRates["client_backend_queue_full"], status.QueuePressure.QueueDropRatePps,
			status.DropCategories.TotalDropRatePps, health.Status, health.Conditions)
		if health.Status != HealthDegraded {
			t.Fatalf("actual backend queue loss must degrade health; got %s (conditions: %+v)", health.Status, health.Conditions)
		}
		cond := assertSingleCondition(t, health.Conditions, "drops")
		if cond.Severity != "DEGRADED" {
			t.Fatalf("condition severity=%q, want DEGRADED", cond.Severity)
		}
		if !strings.Contains(cond.Message, "client") || !strings.Contains(cond.Message, "backend") {
			t.Fatalf("condition message must identify client backend queue: %q", cond.Message)
		}
	})
}

// B3 regression: boundary rates, zero idle, and rate availability for client_backend_queue_full.
func TestB3ClientBackendQueueLossSeverityBoundaries(t *testing.T) {
	quiet := RoutingConsistencyDiagnostics{IsConsistent: true}

	for _, tc := range []struct {
		name    string
		rate    float64
		wantSev string
	}{
		{"a zero measured rate does not fire", 0, ""},
		{"an arbitrarily small positive rate does fire", math.SmallestNonzeroFloat64, "DEGRADED"},
		{"a low positive rate (0.5 pps) fires DEGRADED", 0.5, "DEGRADED"},
		{"1 pkt/sec rate fires DEGRADED", 1.0, "DEGRADED"},
		{"a 10 pkt/sec rate fires DEGRADED", 10.0, "DEGRADED"},
		{"high-volume client queue loss stays DEGRADED (never CRITICAL)", 100000.0, "DEGRADED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := DropCategoryBreakdown{
				TotalDropRatePps: tc.rate,
				RatesAvailable:   true,
				ReasonRates:      map[string]float64{reasonClientBackendQueueFull: tc.rate},
			}
			got := conditionsIn(evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), d, quiet, 0), "drops")
			if tc.wantSev == "" {
				if len(got) != 0 {
					t.Fatalf("expected no drops condition, got %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Severity != tc.wantSev {
				t.Fatalf("rate=%v: got %+v, want one %s", tc.rate, got, tc.wantSev)
			}
			if !strings.Contains(got[0].Message, "client") || !strings.Contains(got[0].Message, "backend") {
				t.Errorf("condition message must identify client backend queue: %q", got[0].Message)
			}
		})
	}

	// An UNMEASURED window is unknown, not bad: no client queue condition
	// may be fabricated before a rate has been sampled.
	unmeasured := DropCategoryBreakdown{
		TotalDropRatePps: 0,
		RatesAvailable:   false,
		ReasonRates:      map[string]float64{reasonClientBackendQueueFull: 99.0},
	}
	if got := conditionsIn(evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), unmeasured, quiet, 0), "drops"); len(got) != 0 {
		t.Fatalf("unmeasured reason rates must not produce a condition: %+v", got)
	}
}

// B3 regression: mixtures of reason-owned client queue loss and generic routine loss
// must remain disjoint, reporting both populations at DEGRADED without double-counting.
func TestB3ClientQueueAndRoutineQueueMixture(t *testing.T) {
	drops := DropCategoryBreakdown{
		TotalDropRatePps: 100000,
		RatesAvailable:   true,
		ReasonRates: map[string]float64{
			reasonClientBackendQueueFull: 40000,
			reasonReturnQueueFull:        60000,
		},
	}
	conds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), drops,
		RoutingConsistencyDiagnostics{IsConsistent: true}, 0)

	dropsConds := conditionsIn(conds, "drops")
	if len(dropsConds) != 2 {
		t.Fatalf("expected exactly 2 drops conditions (1 client queue, 1 routine), got %d: %+v",
			len(dropsConds), dropsConds)
	}

	var foundClient, foundRoutine bool
	for _, c := range dropsConds {
		if c.Severity != "DEGRADED" {
			t.Errorf("condition severity=%q, want DEGRADED: %s", c.Severity, c.Message)
		}
		if strings.Contains(c.Message, "client") && strings.Contains(c.Message, "backend") {
			foundClient = true
			if !strings.Contains(c.Message, "40000.0") {
				t.Errorf("client queue condition must report its own 40000.0 rate: %s", c.Message)
			}
		}
		if strings.Contains(c.Message, "routine") {
			foundRoutine = true
			if !strings.Contains(c.Message, "60000.0") {
				t.Errorf("routine condition must subtract client queue loss and report 60000.0: %s", c.Message)
			}
		}
	}
	if !foundClient {
		t.Errorf("client queue condition missing: %+v", dropsConds)
	}
	if !foundRoutine {
		t.Errorf("routine drop condition missing: %+v", dropsConds)
	}

	// Overall headline summary must be DEGRADED (never CRITICAL).
	status, summary := summarizeHealthConditions(conds)
	if status != HealthDegraded {
		t.Fatalf("headline=%s (%s), want DEGRADED", status, summary)
	}
}

// B3 regression: when current loss stops, health recovers cleanly;
// monotonic lifetime counters must not latch degradation.
func TestB3ClientQueueLossRecoveryDoesNotLatch(t *testing.T) {
	// Active incident: 10 pps current loss, 500 lifetime drops.
	active := DropCategoryBreakdown{
		ClientBackendQueueFull: 500,
		TotalDropRatePps:       10.0,
		RatesAvailable:         true,
		ReasonRates:            map[string]float64{reasonClientBackendQueueFull: 10.0},
	}
	activeHealth := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		active, quietVirtualTUN(), nil, RoutingConsistencyDiagnostics{IsConsistent: true}, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 1, HealthyCount: 1, TotalCount: 1})
	if activeHealth.Status != HealthDegraded {
		t.Fatalf("active loss must degrade health, got %s", activeHealth.Status)
	}

	// Recovery: current rate is zero, but cumulative monotonic counter remains 500.
	recovered := DropCategoryBreakdown{
		ClientBackendQueueFull: 500,
		TotalDropRatePps:       0.0,
		RatesAvailable:         true,
		ReasonRates:            map[string]float64{reasonClientBackendQueueFull: 0.0},
	}
	recoveredHealth := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		recovered, quietVirtualTUN(), nil, RoutingConsistencyDiagnostics{IsConsistent: true}, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 1, HealthyCount: 1, TotalCount: 1})
	if recoveredHealth.Status != HealthHealthy {
		t.Fatalf("recovered health must be HEALTHY, got %s (summary: %s, conditions: %+v)",
			recoveredHealth.Status, recoveredHealth.Summary, recoveredHealth.Conditions)
	}
	if len(recoveredHealth.Conditions) != 0 {
		t.Fatalf("expected no conditions after recovery, got %+v", recoveredHealth.Conditions)
	}
}

// B3 regression: truly critical reasons (ownership mismatch, injection failures)
// take precedence over client backend queue DEGRADED, keeping headline CRITICAL.
func TestB3CriticalPrecedenceOverClientQueueDegradation(t *testing.T) {
	// Injection CRITICAL + Client Queue DEGRADED
	drops := DropCategoryBreakdown{
		TotalDropRatePps: 15.0,
		RatesAvailable:   true,
		ReasonRates: map[string]float64{
			reasonReturnInjectionErrors:  5.0,
			reasonClientBackendQueueFull: 10.0,
		},
	}
	health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		drops, quietVirtualTUN(), nil, RoutingConsistencyDiagnostics{IsConsistent: true}, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{EligibilityKnown: true, EnabledCount: 1, HealthyCount: 1, TotalCount: 1})

	if health.Status != HealthCritical {
		t.Fatalf("status=%s, want CRITICAL: summary=%s", health.Status, health.Summary)
	}
	if !strings.Contains(health.Summary, "injection") {
		t.Errorf("summary must identify critical injection failure: %s", health.Summary)
	}

	// Both conditions must still be observable
	if !hasCondition(health.Conditions, "drops", "CRITICAL") {
		t.Errorf("missing CRITICAL drops condition: %+v", health.Conditions)
	}
	if !hasCondition(health.Conditions, "drops", "DEGRADED") {
		t.Errorf("missing DEGRADED client queue drops condition: %+v", health.Conditions)
	}
}

// B3: every degraded reason key gated on must be published by dropReasonTotals,
// and exactly one evaluator must own each degraded reason.
func TestB3DegradedReasonKeysArePublishedReasons(t *testing.T) {
	published := dropReasonTotals(DropCategoryBreakdown{})
	owners := map[string][]string{}
	for key, claim := range degradedLossReasons {
		if _, ok := published[key]; !ok {
			t.Errorf("degraded reason key %q is not published by dropReasonTotals", key)
		}
		switch claim {
		case claimDrops:
			owners["drops"] = append(owners["drops"], key)
		default:
			t.Errorf("degraded reason %q has unexpected owner %d", key, claim)
		}
	}
	// client_backend_device_unattributed joined this evaluator with the
	// R5-refinement and is published under the direction-neutral
	// backend_device_unattributed key as of review round 3, blocker 3: it has
	// its own DEGRADED condition (reported by reason), and living in this pin
	// is what keeps one-loss-one-condition enforced — the same loss may never
	// also surface in the routine aggregate.
	wantOwners := map[string][]string{
		"drops": {reasonBackendDeviceUnattributed, reasonClientBackendQueueFull},
	}
	for evaluator, want := range wantOwners {
		got := append([]string(nil), owners[evaluator]...)
		sort.Strings(got)
		if len(got) != len(want) {
			t.Errorf("%s evaluator owns %v, want %v", evaluator, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s evaluator owns %v, want %v", evaluator, got, want)
				break
			}
		}
	}
}
