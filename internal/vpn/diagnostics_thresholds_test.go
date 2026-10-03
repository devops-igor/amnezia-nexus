package vpn

import (
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Issue #424 round 3, finding 4: the health thresholds must be centralized and
// documented. Centralizing them is only safe if the numbers did not move, so
// this file pins BOTH halves of that claim:
//
//  1. TestDefaultHealthThresholdsPreservePreviousLiterals — every field equals
//     the literal it replaced, at the value that literal had before the move.
//     This is the numeric-identity proof: if someone later "calibrates" a
//     threshold in DefaultHealthThresholds, this test fails and the change has
//     to be argued as a behaviour change rather than slipping in as a
//     refactor.
//
//  2. The boundary tables below — for each severity threshold, the
//     classification just below, exactly at, and just above it. These pin the
//     comparison OPERATORS as well as the values: the rework preserved them
//     exactly (>= stayed >=, > stayed >), and an operator flip would move a
//     boundary without changing a single number in the struct.

// TestDefaultHealthThresholdsPreservePreviousLiterals is the numeric-identity
// mapping, executable.
//
// Each entry is written as: the literal that stood in the evaluation path
// before finding 4, and the struct field that now owns it. The left-hand value
// is transcribed from the pre-rework source at this head; the right-hand value
// is asserted against DefaultHealthThresholds. They are deliberately not
// written as "field == field", which would pass for any value.
func TestDefaultHealthThresholdsPreservePreviousLiterals(t *testing.T) {
	th := DefaultHealthThresholds

	t.Run("forwarder return queue", func(t *testing.T) {
		// diagnostics.go:1021  queue.UtilizationPct >= 95.0
		if th.QueueCriticalPct != 95.0 {
			t.Errorf("QueueCriticalPct=%v, want 95.0 (was the literal 95.0)", th.QueueCriticalPct)
		}
		// diagnostics.go:1034  queue.UtilizationPct >= 80.0
		if th.QueueWarningPct != 80.0 {
			t.Errorf("QueueWarningPct=%v, want 80.0 (was the literal 80.0)", th.QueueWarningPct)
		}
		// diagnostics.go:1027  queue.ConsecutiveAbove80Sec >= 30
		if th.QueueDegradedSustainedSeconds != 30 {
			t.Errorf("QueueDegradedSustainedSeconds=%d, want 30 (was the literal 30)", th.QueueDegradedSustainedSeconds)
		}
		// diagnostics.go:1034  queue.ConsecutiveAbove50Sec >= 60
		if th.QueueWarningSustainedSeconds != 60 {
			t.Errorf("QueueWarningSustainedSeconds=%d, want 60 (was the literal 60)", th.QueueWarningSustainedSeconds)
		}
		// diagnostics.go:1034 message text "at or above 80%%"
		if th.QueueDegradedAbovePct != 80.0 {
			t.Errorf("QueueDegradedAbovePct=%v, want 80.0 (was the literal 80 in the message)", th.QueueDegradedAbovePct)
		}
		// diagnostics.go:1034 message text; the observer's own "above 50" level.
		if th.QueueWarningSustainedAbovePct != 50.0 {
			t.Errorf("QueueWarningSustainedAbovePct=%v, want 50.0 (was the literal 50 in the message)", th.QueueWarningSustainedAbovePct)
		}
		// diagnostics.go  queue.QueueDropRatePps > 0
		if th.QueueActiveDropRatePPS != 0 {
			t.Errorf("QueueActiveDropRatePPS=%v, want 0 (was the literal 0)", th.QueueActiveDropRatePPS)
		}
	})

	t.Run("forwarder device write latency", func(t *testing.T) {
		// diagnostics.go  latency.OldestInFlightMS >= 1000
		if th.WriteStallCriticalMS != 1000 {
			t.Errorf("WriteStallCriticalMS=%d, want 1000 (was the literal 1000)", th.WriteStallCriticalMS)
		}
		// diagnostics.go  latency.OldestInFlightMS >= 100
		if th.WriteStallWarningMS != 100 {
			t.Errorf("WriteStallWarningMS=%d, want 100 (was the literal 100)", th.WriteStallWarningMS)
		}
		// diagnostics.go:1075  latency.P95HealthMS >= 100.0
		if th.WriteLatencyDegradedMS != 100.0 {
			t.Errorf("WriteLatencyDegradedMS=%v, want 100.0 (was the literal 100.0)", th.WriteLatencyDegradedMS)
		}
		// diagnostics.go:1081  latency.P95HealthMS >= 50.0
		if th.WriteLatencyWarningMS != 50.0 {
			t.Errorf("WriteLatencyWarningMS=%v, want 50.0 (was the literal 50.0)", th.WriteLatencyWarningMS)
		}
	})

	t.Run("upstream VirtualTUN queues", func(t *testing.T) {
		// diagnostics.go  upstreamToNexusUtil >= 90.0 || nexusToUpstreamUtil >= 90.0
		if th.VirtualTUNDegradedPct != 90.0 {
			t.Errorf("VirtualTUNDegradedPct=%v, want 90.0 (was the literal 90.0)", th.VirtualTUNDegradedPct)
		}
		// diagnostics.go  upstreamToNexusUtil >= 75.0 || nexusToUpstreamUtil >= 75.0
		if th.VirtualTUNWarningPct != 75.0 {
			t.Errorf("VirtualTUNWarningPct=%v, want 75.0 (was the literal 75.0)", th.VirtualTUNWarningPct)
		}
	})

	t.Run("dataplane drop rate", func(t *testing.T) {
		// diagnostics.go  drops.TotalDropRatePps >= 10.0
		//
		// The compared POPULATION moved in review round 9 (routine loss only,
		// with reason-claimed losses subtracted), but the VALUE and the operator
		// did not. The boundary tests below pin the operator.
		if th.DropRateDegradedPPS != 10.0 {
			t.Errorf("DropRateDegradedPPS=%v, want 10.0 (was the literal 10.0)", th.DropRateDegradedPPS)
		}
		// diagnostics.go  drops.TotalDropRatePps >= 1.0
		if th.DropRateWarningPPS != 1.0 {
			t.Errorf("DropRateWarningPPS=%v, want 1.0 (was the literal 1.0)", th.DropRateWarningPPS)
		}
	})

	// Round 9 added two severity thresholds rather than moving any. They have
	// no literal they replaced, so their numeric identity is stated as the
	// comparison they restate: each is the boundary of an EXISTING gate applied
	// to a different loss population, not a newly chosen number.
	t.Run("reason-specific critical loss (round 9 additions)", func(t *testing.T) {
		// Pre-round-9, auditRoutingConsistencyDetails gated the routing
		// inconsistency on `OwnershipMismatchDropsRecent > 0`. Round 9 keeps that
		// exact boundary and changes only the severity it produces, so 1 with
		// >= is numerically identical to the old literal 0 with >.
		if th.OwnershipMismatchCriticalDrops != 1 {
			t.Errorf("OwnershipMismatchCriticalDrops=%d, want 1 (the `recent > 0` gate it restates, as >= 1)",
				th.OwnershipMismatchCriticalDrops)
		}
		// Pre-round-9, evaluateLatencyConditions gated device write errors on
		// `latency.WriteErrorRatePps > 0` against the same literal 0, and
		// QueueActiveDropRatePPS is already 0 compared with >. The injection
		// gate is that same rule applied to a third failure population.
		if th.InjectionFailureCriticalRatePPS != 0 {
			t.Errorf("InjectionFailureCriticalRatePPS=%v, want 0 (was the literal 0 of the `> 0` rate gates it mirrors)",
				th.InjectionFailureCriticalRatePPS)
		}
	})

	t.Run("peer synchronisation durations", func(t *testing.T) {
		// diagnostics.go  const peerSyncDivergenceWarningAge = 30 * time.Second
		if th.PeerSyncDivergenceWarningAge != 30*time.Second {
			t.Errorf("PeerSyncDivergenceWarningAge=%v, want 30s (was the const 30 * time.Second)", th.PeerSyncDivergenceWarningAge)
		}
		// diagnostics.go  const peerSyncDivergenceDegradedAge = 60 * time.Second
		if th.PeerSyncDivergenceDegradedAge != 60*time.Second {
			t.Errorf("PeerSyncDivergenceDegradedAge=%v, want 60s (was the const 60 * time.Second)", th.PeerSyncDivergenceDegradedAge)
		}
	})

	t.Run("session handshake freshness", func(t *testing.T) {
		// diagnostics.go:971  now.Sub(hs) > 3*time.Minute
		if th.HandshakeStaleAge != 3*time.Minute {
			t.Errorf("HandshakeStaleAge=%v, want 3m (was the literal 3*time.Minute)", th.HandshakeStaleAge)
		}
	})

	t.Run("problem-route pressure ratio", func(t *testing.T) {
		// diagnostics.go  float64(Occupancy)/float64(Capacity) >= 0.8
		if th.ProblemRoutePressureRatio != 0.8 {
			t.Errorf("ProblemRoutePressureRatio=%v, want 0.8 (was the literal 0.8)", th.ProblemRoutePressureRatio)
		}
	})
}

// severityIn returns the worst severity among the conditions in a given
// category, or "" when that category produced nothing. Comparing "worst" rather
// than "first" keeps the boundary tables robust to the order in which
// independent conditions are appended.
func severityIn(conds []HealthCondition, category string) string {
	worst := ""
	for _, c := range conds {
		if c.Category != category {
			continue
		}
		if c.Severity == "CRITICAL" || worst == "" {
			worst = c.Severity
		}
	}
	return worst
}

// quietQueue is a queue reading that trips no threshold, so a boundary case
// only ever exercises the one threshold under test.
func quietQueue() QueuePressureDiagnostics {
	return QueuePressureDiagnostics{Capacity: 1000, Occupancy: 1, UtilizationPct: 0.1}
}

// quietLatency is a latency reading that trips no threshold.
func quietLatency() ForwardLatencyDiagnostics {
	return ForwardLatencyDiagnostics{P95HealthWindowSec: 60}
}

// quietVirtualTUN is a VirtualTUN reading that trips no threshold.
func quietVirtualTUN() VirtualTUNDiagnostics {
	return VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 1},
		NexusToUpstream: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 1},
	}
}

// TestQueueConditionSeverityBoundaries pins the classification on each side of
// every queue threshold, using the centralized values as the pivot.
func TestQueueConditionSeverityBoundaries(t *testing.T) {
	th := DefaultHealthThresholds

	t.Run("critical occupancy", func(t *testing.T) {
		cases := []struct {
			name string
			pct  float64
			want string
		}{
			{"just below critical", th.QueueCriticalPct - 0.01, "WARNING"},
			{"exactly at critical", th.QueueCriticalPct, "CRITICAL"},
			{"just above critical", th.QueueCriticalPct + 0.01, "CRITICAL"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				q := quietQueue()
				q.UtilizationPct = tc.pct
				if got := severityIn(evaluateQueueConditions(q), "queue_pressure"); got != tc.want {
					t.Errorf("utilization %.2f%%: severity %q, want %q (the boundary is >=, so AT the threshold must already fire)",
						tc.pct, got, tc.want)
				}
			})
		}
	})

	t.Run("sustained degraded dwell", func(t *testing.T) {
		// Utilization is held BELOW the warning level so the sustained-dwell
		// branch is the only one that can fire: a rising dwell is measured while
		// instantaneous occupancy has already recovered.
		cases := []struct {
			name string
			secs int64
			want string
		}{
			{"just below sustained dwell", th.QueueDegradedSustainedSeconds - 1, ""},
			{"exactly at sustained dwell", th.QueueDegradedSustainedSeconds, "DEGRADED"},
			{"just above sustained dwell", th.QueueDegradedSustainedSeconds + 1, "DEGRADED"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				q := quietQueue()
				q.ConsecutiveAbove80Sec = tc.secs
				if got := severityIn(evaluateQueueConditions(q), "queue_pressure"); got != tc.want {
					t.Errorf("dwell %ds: severity %q, want %q (the boundary is >=, so AT the threshold must already fire)",
						tc.secs, got, tc.want)
				}
			})
		}
	})

	t.Run("warning occupancy", func(t *testing.T) {
		cases := []struct {
			name string
			pct  float64
			want string
		}{
			{"just below warning", th.QueueWarningPct - 0.01, ""},
			{"exactly at warning", th.QueueWarningPct, "WARNING"},
			{"just above warning", th.QueueWarningPct + 0.01, "WARNING"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				q := quietQueue()
				q.UtilizationPct = tc.pct
				if got := severityIn(evaluateQueueConditions(q), "queue_pressure"); got != tc.want {
					t.Errorf("utilization %.2f%%: severity %q, want %q", tc.pct, got, tc.want)
				}
			})
		}
	})

	t.Run("sustained warning dwell after recovery", func(t *testing.T) {
		cases := []struct {
			name string
			secs int64
			want string
		}{
			{"just below sustained warning dwell", th.QueueWarningSustainedSeconds - 1, ""},
			{"exactly at sustained warning dwell", th.QueueWarningSustainedSeconds, "WARNING"},
			{"just above sustained warning dwell", th.QueueWarningSustainedSeconds + 1, "WARNING"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				q := quietQueue()
				q.ConsecutiveAbove50Sec = tc.secs
				if got := severityIn(evaluateQueueConditions(q), "queue_pressure"); got != tc.want {
					t.Errorf("dwell %ds: severity %q, want %q", tc.secs, got, tc.want)
				}
			})
		}
	})

	t.Run("active queue drop rate", func(t *testing.T) {
		// This boundary is a STRICT >, not >=: at exactly zero rate nothing may
		// fire, and the smallest representable positive rate must. A test that
		// only probed a large rate would pass either way.
		if got := severityIn(evaluateQueueConditions(quietQueue()), "drops"); got != "" {
			t.Errorf("zero drop rate must not fire the active-drop condition, got %q", got)
		}
		q := quietQueue()
		q.QueueDropRatePps = 0.1
		if got := severityIn(evaluateQueueConditions(q), "drops"); got != "DEGRADED" {
			t.Errorf("0.1 drops/sec: severity %q, want DEGRADED (the boundary is strict >, so the smallest positive rate must fire)", got)
		}
	})
}

// TestLatencyConditionSeverityBoundaries pins the classification on each side
// of every latency threshold.
func TestLatencyConditionSeverityBoundaries(t *testing.T) {
	th := DefaultHealthThresholds

	t.Run("in-flight write stall critical", func(t *testing.T) {
		cases := []struct {
			name string
			ms   int64
			want string
		}{
			{"just below critical stall", th.WriteStallCriticalMS - 1, "WARNING"},
			{"exactly at critical stall", th.WriteStallCriticalMS, "CRITICAL"},
			{"just above critical stall", th.WriteStallCriticalMS + 1, "CRITICAL"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				l := quietLatency()
				l.OldestInFlightMS = tc.ms
				if got := severityIn(evaluateLatencyConditions(l), "latency"); got != tc.want {
					t.Errorf("in-flight %dms: severity %q, want %q", tc.ms, got, tc.want)
				}
			})
		}
	})

	t.Run("in-flight write stall warning", func(t *testing.T) {
		cases := []struct {
			name string
			ms   int64
			want string
		}{
			{"just below warning stall", th.WriteStallWarningMS - 1, ""},
			{"exactly at warning stall", th.WriteStallWarningMS, "WARNING"},
			{"just above warning stall", th.WriteStallWarningMS + 1, "WARNING"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				l := quietLatency()
				l.OldestInFlightMS = tc.ms
				if got := severityIn(evaluateLatencyConditions(l), "latency"); got != tc.want {
					t.Errorf("in-flight %dms: severity %q, want %q", tc.ms, got, tc.want)
				}
			})
		}
	})

	t.Run("recent-window p95 degraded", func(t *testing.T) {
		// P95HealthSamples must be non-zero: an empty window is UNKNOWN latency
		// and is deliberately not evaluated at all, which would make every
		// case in this table report "" and pass for the wrong reason.
		cases := []struct {
			name string
			ms   float64
			want string
		}{
			{"just below degraded p95", th.WriteLatencyDegradedMS - 0.01, "WARNING"},
			{"exactly at degraded p95", th.WriteLatencyDegradedMS, "DEGRADED"},
			{"just above degraded p95", th.WriteLatencyDegradedMS + 0.01, "DEGRADED"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				l := quietLatency()
				l.P95HealthMS = tc.ms
				l.P95HealthSamples = 40
				if got := severityIn(evaluateLatencyConditions(l), "latency"); got != tc.want {
					t.Errorf("p95 %.2fms over a populated window: severity %q, want %q", tc.ms, got, tc.want)
				}
			})
		}
	})

	t.Run("recent-window p95 warning", func(t *testing.T) {
		cases := []struct {
			name string
			ms   float64
			want string
		}{
			{"just below warning p95", th.WriteLatencyWarningMS - 0.01, ""},
			{"exactly at warning p95", th.WriteLatencyWarningMS, "WARNING"},
			{"just above warning p95", th.WriteLatencyWarningMS + 0.01, "WARNING"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				l := quietLatency()
				l.P95HealthMS = tc.ms
				l.P95HealthSamples = 40
				if got := severityIn(evaluateLatencyConditions(l), "latency"); got != tc.want {
					t.Errorf("p95 %.2fms over a populated window: severity %q, want %q", tc.ms, got, tc.want)
				}
			})
		}
	})

	t.Run("empty health window is not bad latency", func(t *testing.T) {
		// The counterweight to the two tables above: a window with no samples
		// must produce NO p95 condition even when the descriptive percentile is
		// far past the degraded bound. Without this, "severity == \"\"" in the
		// below-boundary rows could be satisfied by the evaluation being
		// skipped rather than by the threshold not being crossed.
		l := quietLatency()
		l.P95MS = th.WriteLatencyDegradedMS * 10
		l.P95HealthMS = th.WriteLatencyDegradedMS * 10
		l.P95HealthSamples = 0
		for _, c := range evaluateLatencyConditions(l) {
			if c.Category == "latency" {
				t.Errorf("an empty health window must not produce a latency condition, got %q", c.Message)
			}
		}
	})
}

// TestVirtualTUNConditionSeverityBoundaries pins the classification on each
// side of both VirtualTUN utilization thresholds, in BOTH directions: the
// evaluator ORs the two directions together, so a threshold that only ever got
// exercised through upstream->nexus could pass while nexus->upstream was
// broken.
func TestVirtualTUNConditionSeverityBoundaries(t *testing.T) {
	th := DefaultHealthThresholds

	// occupied builds VirtualTUNDiagnostics with the given utilization percent
	// in the named direction and a quiet reading in the other.
	occupied := func(pct float64, direction string) VirtualTUNDiagnostics {
		v := quietVirtualTUN()
		// Capacity 1000, so pct% is expressible exactly at whole percents.
		occupancy := int(pct * 10)
		switch direction {
		case "upstream_to_nexus":
			v.UpstreamToNexus.Occupancy = occupancy
		case "nexus_to_upstream":
			v.NexusToUpstream.Occupancy = occupancy
		}
		return v
	}

	t.Run("degraded occupancy", func(t *testing.T) {
		cases := []struct {
			name string
			pct  float64
			want string
		}{
			{"just below degraded", th.VirtualTUNDegradedPct - 1, "WARNING"},
			{"exactly at degraded", th.VirtualTUNDegradedPct, "DEGRADED"},
			{"just above degraded", th.VirtualTUNDegradedPct + 1, "DEGRADED"},
		}
		for _, tc := range cases {
			for _, direction := range []string{"upstream_to_nexus", "nexus_to_upstream"} {
				t.Run(tc.name+"/"+direction, func(t *testing.T) {
					conds := evaluateVirtualTUNAndDropConditions(occupied(tc.pct, direction), DropCategoryBreakdown{}, RoutingConsistencyDiagnostics{IsConsistent: true})
					if got := severityIn(conds, "virtual_tun"); got != tc.want {
						t.Errorf("%s at %.0f%%: severity %q, want %q", direction, tc.pct, got, tc.want)
					}
				})
			}
		}
	})

	t.Run("warning occupancy", func(t *testing.T) {
		cases := []struct {
			name string
			pct  float64
			want string
		}{
			{"just below warning", th.VirtualTUNWarningPct - 1, ""},
			{"exactly at warning", th.VirtualTUNWarningPct, "WARNING"},
			{"just above warning", th.VirtualTUNWarningPct + 1, "WARNING"},
		}
		for _, tc := range cases {
			for _, direction := range []string{"upstream_to_nexus", "nexus_to_upstream"} {
				t.Run(tc.name+"/"+direction, func(t *testing.T) {
					conds := evaluateVirtualTUNAndDropConditions(occupied(tc.pct, direction), DropCategoryBreakdown{}, RoutingConsistencyDiagnostics{IsConsistent: true})
					if got := severityIn(conds, "virtual_tun"); got != tc.want {
						t.Errorf("%s at %.0f%%: severity %q, want %q", direction, tc.pct, got, tc.want)
					}
				})
			}
		}
	})
}

// TestDropRateConditionSeverityBoundaries pins the classification on each side
// of both dataplane drop-rate thresholds.
func TestDropRateConditionSeverityBoundaries(t *testing.T) {
	th := DefaultHealthThresholds

	cases := []struct {
		name string
		pps  float64
		want string
	}{
		{"just below warning rate", th.DropRateWarningPPS - 0.01, ""},
		{"exactly at warning rate", th.DropRateWarningPPS, "WARNING"},
		{"just above warning rate", th.DropRateWarningPPS + 0.01, "WARNING"},
		{"just below degraded rate", th.DropRateDegradedPPS - 0.01, "WARNING"},
		{"exactly at degraded rate", th.DropRateDegradedPPS, "DEGRADED"},
		{"just above degraded rate", th.DropRateDegradedPPS + 0.01, "DEGRADED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), DropCategoryBreakdown{TotalDropRatePps: tc.pps}, RoutingConsistencyDiagnostics{IsConsistent: true})
			if got := severityIn(conds, "drops"); got != tc.want {
				t.Errorf("drop rate %.2f/sec: severity %q, want %q", tc.pps, got, tc.want)
			}
		})
	}
}

// TestProblemRoutePressureRatioBoundary pins the problem-route 0.8 note
// threshold. It is a classification bound for a NOTE rather than a severity:
// the route's severity is decided by the dataplane-wide conditions above, so
// this asserts the note appearing and not appearing either side of the ratio.
//
// The route must carry HasPressure, because collectProblemRoutes only
// classifies routes the forwarder already flagged as under pressure; leaving it
// false would make every case report "" and pass without exercising the ratio.
func TestProblemRoutePressureRatioBoundary(t *testing.T) {
	th := DefaultHealthThresholds

	// pressureNoteFor builds a route whose queue holds occupancy out of
	// capacity and returns the pressure note production attached, if any.
	pressureNoteFor := func(occupancy, capacity int) string {
		t.Helper()
		routes := []forwarder.RouteInfo{{
			PeerKey:     "peer-pressure",
			AssignedIP:  "10.100.0.30",
			SessionID:   "sess-pressure",
			HasPressure: true,
			Stats: forwarder.RouteQueueStats{
				Capacity:  capacity,
				Occupancy: occupancy,
			},
		}}
		items := collectProblemRoutes(routes)
		if len(items) != 1 {
			t.Fatalf("collectProblemRoutes returned %d items, want 1", len(items))
		}
		return items[0].PressureNote
	}

	// Capacity 1000 makes a 0.1% occupancy step exactly 1 packet, so the
	// "just below" and "just above" cases sit either side of the ratio on
	// opposite sides of the >= comparison.
	const capacity = 1000
	below := int(th.ProblemRoutePressureRatio*capacity) - 1
	on := int(th.ProblemRoutePressureRatio * capacity)
	above := on + 1

	cases := []struct {
		name      string
		occupancy int
		wantNote  bool
	}{
		{"just below the pressure ratio", below, false},
		{"exactly at the pressure ratio", on, true},
		{"just above the pressure ratio", above, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			note := pressureNoteFor(tc.occupancy, capacity)
			if got := note != ""; got != tc.wantNote {
				t.Errorf("occupancy %d/%d = %.4f (ratio %.2f): note=%q, wantNote=%v",
					tc.occupancy, capacity,
					float64(tc.occupancy)/float64(capacity), th.ProblemRoutePressureRatio, note, tc.wantNote)
			}
			if tc.wantNote && note == "" {
				t.Errorf("occupancy %d/%d crossed the ratio but produced no note", tc.occupancy, capacity)
			}
		})
	}

	// A zero-capacity route must never divide by zero into a bogus note.
	if note := pressureNoteFor(50, 0); note != "" {
		t.Errorf("a route with no queue capacity must produce no pressure note, got %q", note)
	}
}
