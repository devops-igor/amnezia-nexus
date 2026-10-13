package vpn

import (
	"fmt"
	"strings"
	"time"
)

// EvaluateForwarderHealth applies deterministic rules to derive the overall dataplane health status.
func EvaluateForwarderHealth(
	fwdAvailable bool,
	engineRunning bool,
	queue QueuePressureDiagnostics,
	latency ForwardLatencyDiagnostics,
	drops DropCategoryBreakdown,
	vtun VirtualTUNDiagnostics,
	peerSync *PeerSyncStatus,
	routing RoutingConsistencyDiagnostics,
	handshake HandshakeFreshnessDiagnostics,
	backends BackendsDiagnostics,
	actionable ...ActionableProblem,
) ForwarderHealthAssessment {
	if !fwdAvailable || !engineRunning {
		return ForwarderHealthAssessment{
			Status:  HealthUnavailable,
			Summary: "Forwarder engine is stopped or unavailable",
			Conditions: []HealthCondition{
				{
					Category: "engine",
					Severity: "CRITICAL",
					Message:  "Forwarder dataplane is not active",
				},
			},
			ActionableProblems: actionable,
		}
	}

	conditions := make([]HealthCondition, 0)
	conditions = append(conditions, evaluateRoutingConditions(routing)...)
	conditions = append(conditions, evaluateQueueConditions(queue)...)
	conditions = append(conditions, evaluateLatencyConditions(latency)...)
	conditions = append(conditions, evaluateVirtualTUNAndDropConditions(vtun, drops, routing, queue.QueueDropRatePps)...)
	conditions = append(conditions, evaluatePeerSyncAndBackendConditions(peerSync, backends, handshake)...)

	status, summary := summarizeHealthConditions(conditions)

	hasCriticalActionable := false
	hasDegradedActionable := false
	for _, p := range actionable {
		switch strings.ToUpper(p.Severity) {
		case HealthCritical:
			hasCriticalActionable = true
		case HealthDegraded:
			hasDegradedActionable = true
		}
	}

	initialStatus := status
	if hasCriticalActionable && status != "DOWN" {
		status = HealthCritical
	} else if hasDegradedActionable && (status == HealthHealthy || status == "WARNING") {
		status = HealthDegraded
	}

	var summaryKey string
	if (initialStatus == HealthHealthy || initialStatus == "WARNING") && status != initialStatus {
		summary = "Active VPN session routing or dataplane issues detected"
		summaryKey = "vpn_diag_summary_actionable_issues"
	}

	return ForwarderHealthAssessment{
		Status:             status,
		Summary:            summary,
		SummaryKey:         summaryKey,
		Conditions:         conditions,
		ActionableProblems: actionable,
	}
}

// evaluateRoutingConditions turns routing invariants into health conditions.
//
// In issue #457, severity is evaluated per condition detail:
//   - Duplicate IPs and unroutable sessions remain CRITICAL.
//   - Client-direction ownership mismatches remain CRITICAL.
//   - Return-direction ownership mismatches classify as CRITICAL if client mismatch
//     is also present, DEGRADED if return drop rate reaches the degraded threshold,
//     and WARNING for routine sparse drops.
//   - Structural routing discrepancies remain DEGRADED.
func evaluateRoutingConditions(routing RoutingConsistencyDiagnostics) []HealthCondition {
	if routing.IsConsistent {
		return nil
	}
	th := defaultHealthThresholds()
	conds := make([]HealthCondition, 0, len(routing.InconsistencyDetails))
	for _, detail := range routing.InconsistencyDetails {
		condSev := "DEGRADED"
		if strings.Contains(detail, "duplicate IP") || strings.Contains(detail, "lack a forwarder route") {
			condSev = "CRITICAL"
		} else if strings.Contains(detail, "client-direction") {
			if routing.ClientOwnershipMismatchDropsRecent >= th.ClientOwnershipMismatchCriticalDrops {
				condSev = "CRITICAL"
			}
		} else if strings.Contains(detail, "return-direction") {
			minConsecutive := th.ReturnOwnershipMismatchDegradedConsecutiveWindows
			if minConsecutive <= 0 {
				minConsecutive = 1
			}
			if routing.ClientOwnershipMismatchDropsRecent >= th.ClientOwnershipMismatchCriticalDrops {
				condSev = "CRITICAL"
			} else if routing.ReturnOwnershipMismatchRatePPS() >= th.ReturnOwnershipMismatchDegradedRatePPS &&
				routing.ReturnOwnershipMismatchConsecutiveHighRateWindows >= minConsecutive {
				condSev = "DEGRADED"
			} else if routing.OwnershipMismatchDropsRecent >= th.ReturnOwnershipMismatchWarningDrops {
				condSev = "WARNING"
			}
		}
		conds = append(conds, HealthCondition{
			Category: "routing",
			Severity: condSev,
			Message:  detail,
		})
	}
	return conds
}

func evaluateQueueConditions(queue QueuePressureDiagnostics) []HealthCondition {
	// Read the DERIVED set live, not the package snapshot: the queue-pressure
	// levels are canonical in internal/vpn/forwarder/thresholds and this is
	// their reporting half, so a change there must move this evaluation
	// (issue #424 round 5, finding 4).
	th := defaultHealthThresholds()
	var conds []HealthCondition
	if queue.UtilizationPct >= th.QueueCriticalPct {
		conds = append(conds, HealthCondition{
			Category: "queue_pressure",
			Severity: "CRITICAL",
			Message:  fmt.Sprintf("Queue saturation: Return queue utilization is at %.1f%%", queue.UtilizationPct),
		})
	} else if queue.ConsecutiveAbove80Sec >= th.QueueDegradedSustainedSeconds {
		conds = append(conds, HealthCondition{
			Category: "queue_pressure",
			Severity: "DEGRADED",
			// Consecutive duration is measured from managed queue transitions.
			Message: fmt.Sprintf("Queue pressure: Return queue utilization has been at or above %d%% for %ds",
				int(th.QueueDegradedAbovePct), queue.ConsecutiveAbove80Sec),
		})
	} else if queue.UtilizationPct >= th.QueueWarningPct || queue.ConsecutiveAbove50Sec >= th.QueueWarningSustainedSeconds {
		conds = append(conds, HealthCondition{
			Category: "queue_pressure",
			Severity: "WARNING",
			Message:  fmt.Sprintf("Elevated queue utilization at %.1f%%", queue.UtilizationPct),
		})
	}
	if queue.QueueDropRatePps > th.QueueActiveDropRatePPS {
		conds = append(conds, HealthCondition{
			Category: "drops",
			Severity: "DEGRADED",
			Message:  fmt.Sprintf("Active queue drops: %.1f drops/sec due to full return queues", queue.QueueDropRatePps),
		})
	}
	return conds
}

func evaluateLatencyConditions(latency ForwardLatencyDiagnostics) []HealthCondition {
	th := defaultHealthThresholds()
	var conds []HealthCondition
	if latency.OldestInFlightMS >= th.WriteStallCriticalMS {
		conds = append(conds, HealthCondition{
			Category: "latency",
			Severity: "CRITICAL",
			Message:  fmt.Sprintf("Device write stall: in-flight write blocked for %dms", latency.OldestInFlightMS),
		})
	} else if latency.OldestInFlightMS >= th.WriteStallWarningMS {
		conds = append(conds, HealthCondition{
			Category: "latency",
			Severity: "WARNING",
			Message:  fmt.Sprintf("Slow in-flight write: in progress for %dms", latency.OldestInFlightMS),
		})
	}

	// Latency health uses the RECENT window, not the descriptive percentile.
	// P95MS describes the last 1024 completed writes and never expires, so on a
	// low-volume or idle server one burst of slow writes held DEGRADED until
	// 1024 new writes displaced it. P95HealthSamples == 0 means nothing was
	// written inside the window, which is UNKNOWN latency, not bad latency: the
	// live signals above (an in-flight write blocked right now) still apply
	// (issue #424 round 8, finding 4).
	if latency.P95HealthSamples > 0 {
		if latency.P95HealthMS >= th.WriteLatencyDegradedMS {
			conds = append(conds, HealthCondition{
				Category: "latency",
				Severity: "DEGRADED",
				Message:  fmt.Sprintf("High forward write latency: p95 is %.1fms over the last %ds", latency.P95HealthMS, latency.P95HealthWindowSec),
			})
		} else if latency.P95HealthMS >= th.WriteLatencyWarningMS {
			conds = append(conds, HealthCondition{
				Category: "latency",
				Severity: "WARNING",
				Message:  fmt.Sprintf("Elevated forward write latency: p95 is %.1fms over the last %ds", latency.P95HealthMS, latency.P95HealthWindowSec),
			})
		}
	}

	if latency.WriteErrorRatePps > 0 {
		conds = append(conds, HealthCondition{
			Category: "latency",
			Severity: "DEGRADED",
			Message:  fmt.Sprintf("Active device write errors: %.1f errors/sec detected", latency.WriteErrorRatePps),
		})
	}
	return conds
}

// evaluateVirtualTUNAndDropConditions classifies upstream queue occupancy and
// dataplane loss.
//
// Loss is classified in TWO disjoint populations rather than one aggregate
// (issue #424 review round 9, blocker 3):
//
//  1. CRITICAL reasons, identified by name. A packet refused because ownership
//     could not be verified, or refused at the injection hop after decryption,
//     is a correctness failure at any volume. Deciding that by REASON rather
//     than by aggregate rate is the whole point: previously these losses were
//     summed into TotalDropRatePps and compared against a generic threshold, so
//     a sparse critical reason read as HEALTHY and a large one read as DEGRADED.
//
//  2. The ROUTINE population: everything else. Its rate is the aggregate MINUS
//     the reason-claimed losses, so a loss can never be reported twice — once by
//     reason and once by the aggregate. This is what keeps the two populations
//     disjoint, and it is why lowering the generic thresholds would NOT have
//     been a fix: it would have turned high-volume queue-full churn critical
//     while still misreading a single ownership mismatch.
//
// routing is taken so the ownership-mismatch subtraction reads the same
// windowed measurement the routing condition was decided on, rather than a
// second, independently-sampled view of the same counters.
func evaluateVirtualTUNAndDropConditions(vtun VirtualTUNDiagnostics, drops DropCategoryBreakdown, routing RoutingConsistencyDiagnostics, returnQueueRate float64) []HealthCondition {
	th := defaultHealthThresholds()
	var conds []HealthCondition
	upstreamToNexusUtil := float64(0)
	if vtun.UpstreamToNexus.Capacity > 0 {
		upstreamToNexusUtil = float64(vtun.UpstreamToNexus.Occupancy) / float64(vtun.UpstreamToNexus.Capacity) * 100.0
	}
	nexusToUpstreamUtil := float64(0)
	if vtun.NexusToUpstream.Capacity > 0 {
		nexusToUpstreamUtil = float64(vtun.NexusToUpstream.Occupancy) / float64(vtun.NexusToUpstream.Capacity) * 100.0
	}
	if upstreamToNexusUtil >= th.VirtualTUNDegradedPct || nexusToUpstreamUtil >= th.VirtualTUNDegradedPct {
		conds = append(conds, HealthCondition{
			Category: "virtual_tun",
			Severity: "DEGRADED",
			Message: fmt.Sprintf("VirtualTUN queue saturation: upstream->nexus %.1f%%, nexus->upstream %.1f%%",
				upstreamToNexusUtil, nexusToUpstreamUtil),
		})
	} else if upstreamToNexusUtil >= th.VirtualTUNWarningPct || nexusToUpstreamUtil >= th.VirtualTUNWarningPct {
		conds = append(conds, HealthCondition{
			Category: "virtual_tun",
			Severity: "WARNING",
			Message: fmt.Sprintf("Elevated VirtualTUN queue utilization: upstream->nexus %.1f%%, nexus->upstream %.1f%%",
				upstreamToNexusUtil, nexusToUpstreamUtil),
		})
	}

	// Ownership mismatch in either direction is claimed by the ROUTING
	// condition, not here. Emitting it in both places is precisely the
	// double-counted loss round 5 of this review was about, so the routing
	// contribution is subtracted from the routine population below rather than
	// reported a second time.

	// Injection failures are claimed here. They have no routing invariant, and
	// before this change they were visible only through the aggregate rate, so
	// they could never exceed DEGRADED.
	//
	// The rate comes from criticalLossReasons, the same declaration that names
	// every other critical reason and its owner, so a reason cannot be reported
	// by reason here without also being subtracted from the routine population
	// below.
	//
	// RatesAvailable gates this deliberately: the first sample of the tracker
	// publishes zeros because the interval is not yet known, so treating an
	// unmeasured window as a real rate would fabricate an incident. That is the
	// same rule the write-latency p95 gate uses (P95HealthSamples > 0).
	if drops.RatesAvailable {
		if rate := criticalReasonRatePps(drops, claimDrops); rate > th.InjectionFailureCriticalRatePPS {
			conds = append(conds, HealthCondition{
				Category: "drops",
				Severity: "CRITICAL",
				Message: fmt.Sprintf("Return-path injection failures: %.1f errors/sec; "+
					"decrypted replies are being refused at the client ingress hop", rate),
			})
		}
		// The queue-full gate reads its OWN reason's rate, not the degraded
		// reason sum: backend_device_unattributed now shares the
		// degradedLossReasons map (and the routine-population subtraction) but
		// has its own condition below, so summing here would report one loss
		// twice under two different messages.
		if rate := drops.ReasonRates[reasonClientBackendQueueFull]; rate > th.ClientQueueActiveDropRatePPS {
			conds = append(conds, HealthCondition{
				Category: "drops",
				Severity: "DEGRADED",
				Message:  fmt.Sprintf("Active client queue drops: %.1f drops/sec due to full backend queues", rate),
			})
		}
		// Unattributed backend-device loss is active: drops ARE happening on a
		// device, but that device cannot report the direction x reason
		// breakdown, so nothing can say which traffic or why. Reported by
		// reason (DEGRADED, review item 2) instead of folding into the generic
		// routine aggregate, which the review called not actionable. The same
		// RatesAvailable gate as above applies: an unmeasured window is not an
		// incident. The reason is the direction-NEUTRAL backend_device_unattributed
		// key (issue #429 review round 3, blocker 3): the loss counts toward the
		// total but toward neither directional total. A device WITH detailed
		// attribution publishes a measured zero for this reason and a non-zero
		// rate under a device-specific key, so this condition stays off in both
		// of its firing-exclusion cases (attribution available; drops quiet).
		if rate := drops.ReasonRates[reasonBackendDeviceUnattributed]; rate > th.BackendDeviceUnattributedActiveDropRatePPS {
			conds = append(conds, HealthCondition{
				Category:   "drops",
				Severity:   "DEGRADED",
				MessageKey: vpnDiagConditionBackendDeviceUnattributed,
				Message: fmt.Sprintf("Backend device drops are active but detailed per-direction attribution is unavailable: "+
					"%.1f drops/sec", rate),
			})
		}
	}

	// The ROUTINE population: the aggregate minus every loss already claimed by
	// a reason-specific condition, whichever evaluator owns it. When drops.RatesAvailable
	// is true and ownership reason rates are present, ownership mismatch losses are
	// subtracted using the reason rates from the same loss observation window
	// (drops.ReasonRates, issue #457 Rework Round 6) to eliminate cross-window sampling
	// skew under concurrent collection. When unavailable or unpopulated in ReasonRates,
	// fall back to routing.DirectionalOwnershipMismatchRatePPS().
	var ownershipLossRate float64
	_, hasReturn := drops.ReasonRates[reasonReturnOwnershipMismatch]
	_, hasClient := drops.ReasonRates[reasonClientOwnershipMismatch]
	if drops.RatesAvailable && (hasReturn || hasClient) {
		ownershipLossRate = drops.ReasonRates[reasonReturnOwnershipMismatch] + drops.ReasonRates[reasonClientOwnershipMismatch]
	} else {
		ownershipLossRate = routing.DirectionalOwnershipMismatchRatePPS()
	}

	routineRate := drops.TotalDropRatePps -
		ownershipLossRate -
		criticalReasonRatePps(drops, claimDrops) -
		degradedReasonRatePps(drops, claimDrops)
	// evaluateQueueConditions owns return-queue refusals. Its rate uses the
	// same reason window as this aggregate in operational status.
	if returnQueueRate > th.QueueActiveDropRatePPS {
		routineRate -= returnQueueRate
	}
	if routineRate < 0 {
		routineRate = 0
	}

	if routineRate >= th.DropRateDegradedPPS {
		conds = append(conds, HealthCondition{
			Category: "drops",
			Severity: "DEGRADED",
			Message: fmt.Sprintf("Elevated routine drop rate: %.1f drops/sec across dataplane "+
				"(excluding ownership-mismatch, injection-failure, and queue losses, reported by reason)",
				routineRate),
		})
	} else if routineRate >= th.DropRateWarningPPS {
		conds = append(conds, HealthCondition{
			Category: "drops",
			Severity: "WARNING",
			Message: fmt.Sprintf("Active routine packet drops: %.1f drops/sec across dataplane "+
				"(excluding ownership-mismatch, injection-failure, and queue losses, reported by reason)",
				routineRate),
		})
	}
	return conds
}

// Peer-sync divergence timing thresholds (issue #424 round 4, item F; round 5,
// item B; centralized in HealthThresholds by round 3, finding 4). A
// desired/actual mismatch that resolves inside the next reconcile
// is normal convergence, not an incident; only a PERSISTED mismatch is. The
// age is measured from PeerSync.DivergenceSince, the moment the CURRENT
// mismatch was first observed, which the peerSynchronizer records during
// reconcile. It is deliberately NOT measured from LastSuccessfulReconcile:
// that is when reconciliation last succeeded, which on a long-healthy system
// can be hours before a single new peer fails to be added, and using it made
// a seconds-old divergence report DEGRADED with a multi-hour claim.
//
// The durations themselves live on DefaultHealthThresholds
// (PeerSyncDivergenceWarningAge / PeerSyncDivergenceDegradedAge).

// peerSyncDivergenceCondition returns the health condition for a persisted
// desired/actual mismatch, or nil when there is nothing to report. now is
// injected so the thresholds are exactly observable; the production caller
// passes the wall clock (issue #424 round 4).
//
// known is false when no divergence is being timed, i.e. DivergenceSince is
// zero, which means no reconcile has ever reached the point where both counts
// are known. Two cases produce that, and they are handled differently rather
// than inherited from the previous behavior:
//
//   - The system has never reconciled, so there is genuinely no evidence of
//     when anything happened. The age is stated as unknown and the severity
//     stays WARNING; inventing a large age here would report DEGRADED on a
//     system that has never synchronized at all.
//   - A fresh divergence on a system that has never had a SUCCESSFUL
//     reconcile. Here the synchronizer DID stamp a start on first
//     observation, so DivergenceSince is set and the age is known: the
//     mismatch began when it was first seen, regardless of whether any
//     earlier reconcile succeeded. It is therefore held to the same
//     thresholds as any other divergence, and is NOT reported as "age
//     unknown". This is the explicit decision required for the case where
//     LastSuccessfulReconcile is zero but the counts disagree: a brand new
//     system whose first reconcile installs 3 of 4 peers is a real,
//     just-begun divergence, not an unmeasurable one.
//
// A negative age (DivergenceSince stamped in the future, which a clock step
// backwards can produce) is clamped to zero and treated as younger than the
// warning threshold, so a clock adjustment cannot fabricate an escalation.
func peerSyncDivergenceCondition(peerSync *PeerSyncStatus, now time.Time) *HealthCondition {
	if peerSync.DesiredPeers == peerSync.ActualPeers {
		return nil
	}
	if peerSync.DivergenceSince.IsZero() {
		return &HealthCondition{
			Category: "peer_sync",
			Severity: "WARNING",
			Message: fmt.Sprintf("Peer sync divergence: %d desired vs %d actual peers "+
				"(divergence age unknown: no reconciliation has ever succeeded)",
				peerSync.DesiredPeers, peerSync.ActualPeers),
		}
	}
	age := now.Sub(peerSync.DivergenceSince)
	if age < 0 {
		age = 0
	}
	switch {
	case age > DefaultHealthThresholds.PeerSyncDivergenceDegradedAge:
		return &HealthCondition{
			Category: "peer_sync",
			Severity: "DEGRADED",
			Message: fmt.Sprintf("Peer sync divergence for %s: %d desired vs %d actual peers",
				age.Round(time.Second), peerSync.DesiredPeers, peerSync.ActualPeers),
		}
	case age > DefaultHealthThresholds.PeerSyncDivergenceWarningAge:
		return &HealthCondition{
			Category: "peer_sync",
			Severity: "WARNING",
			Message: fmt.Sprintf("Peer sync divergence for %s: %d desired vs %d actual peers",
				age.Round(time.Second), peerSync.DesiredPeers, peerSync.ActualPeers),
		}
	default:
		// Converging, or younger than the warning threshold: not a condition.
		return nil
	}
}

func evaluatePeerSyncAndBackendConditions(peerSync *PeerSyncStatus, backends BackendsDiagnostics, handshake HandshakeFreshnessDiagnostics) []HealthCondition {
	var conds []HealthCondition
	now := time.Now()
	if peerSync != nil {
		if peerSync.PortalConfigRestartRequired {
			conds = append(conds, HealthCondition{
				Category: "peer_sync",
				Severity: "DEGRADED",
				Message:  "Portal configuration changed; engine restart is required to apply updates",
			})
		}
		// InvalidRows is STICKY (issue #424 round 4, item G), for the same
		// reason LastError is: it is durable STATE, not a rate. Every
		// reconcile re-derives it from the durable rows (peer_sync.go:671), so
		// it goes to 0 the moment the rows are repaired, and a failed durable
		// read returns BEFORE that assignment, so a transient read glitch
		// cannot clear it either. That is what keeps it clear of the round-3
		// trap: the lifetime counters (SyncFailures and friends) only ever
		// grow, so they are exposed as history and gated on their windowed
		// deltas. InvalidRows is not such a counter; it is a level recomputed
		// from durable state on every pass, so gating on it cannot pin health
		// forever and cannot be missed by a delta that has gone quiet.
		//
		// DEGRADED rather than CRITICAL: an invalid row is excluded from the
		// desired set, so its peer is simply not enforced upstream and its
		// traffic is unauthorized and dropped. That is a real, unrecoverable-
		// by-retry service gap for the affected peer, but every other peer
		// still reconciles normally, so the dataplane as a whole keeps serving
		// and CRITICAL would overstate the blast radius.
		if peerSync.InvalidRows > 0 {
			conds = append(conds, HealthCondition{
				Category: "peer_sync",
				Severity: "DEGRADED",
				Message: fmt.Sprintf("%d invalid durable peer row(s) excluded from the desired set; "+
					"those peers are not enforced upstream and their traffic is unauthorized until the rows are repaired",
					peerSync.InvalidRows),
			})
		}
		// An UNRESOLVED reconciliation failure is sticky and is gated on
		// LastError, not on the windowed deltas (issue #424 round 3,
		// finding 2). The deltas are a rate: the tracker reports 0 on its
		// first observation (baseline establishment) and falls back to 0
		// once the cumulative counter stops rising, so a delta-only gate
		// reports HEALTHY while the last reconcile is still failing.
		// LastError is set by peerSynchronizer.fail and cleared ONLY by a
		// successful reconcile (peer_sync.go), which makes it exactly the
		// "degraded until recovery" signal the health surface needs.
		//
		// LastEnqueueError deliberately does NOT gate here: nothing in the
		// peer synchronizer ever clears it, so treating it as sticky would
		// pin DEGRADED permanently after a single transient enqueue
		// failure. Enqueue failures stay gated on their windowed delta.
		if peerSync.LastError != "" {
			conds = append(conds, HealthCondition{
				Category: "peer_sync",
				Severity: "DEGRADED",
				Message: fmt.Sprintf("Unresolved peer sync failure: %s (last successful reconcile %s; "+
					"recent activity: %d sync, %d enqueue failures in the last %.1fs; %d sync, %d enqueue cumulative)",
					clampDiagnosticText(peerSync.LastError, maxDiagnosticErrorTextLen),
					describeLastSuccessfulReconcile(peerSync.LastSuccessfulReconcile),
					peerSync.SyncFailuresRecent, peerSync.EnqueueFailuresRecent, peerSync.FailuresWindowSec,
					peerSync.SyncFailures, peerSync.EnqueueFailures),
			})
		} else if peerSync.SyncFailuresRecent > 0 || peerSync.EnqueueFailuresRecent > 0 {
			conds = append(conds, HealthCondition{
				Category: "peer_sync",
				Severity: "DEGRADED",
				Message: fmt.Sprintf("Active peer sync failures: %d sync, %d enqueue in the last %.1fs "+
					"(%d sync, %d enqueue cumulative)",
					peerSync.SyncFailuresRecent, peerSync.EnqueueFailuresRecent, peerSync.FailuresWindowSec,
					peerSync.SyncFailures, peerSync.EnqueueFailures),
			})
		}
		if divergence := peerSyncDivergenceCondition(peerSync, now); divergence != nil {
			conds = append(conds, *divergence)
		}
	}

	// enabled is the population a FAILURE can be counted against. When eligibility
	// is known, that is the ENABLED count: a backend an operator disabled is an
	// operator decision, not a failure, so it must never contribute to a
	// degradation (issue #424 review round 9, blocker 4).
	//
	// HealthyCount already counts only ELIGIBLE backends (enabled AND active),
	// so HealthyCount < enabled is precisely "enabled backends that are not
	// carrying traffic". The disabled ones are absent from both sides of that
	// comparison, which is what keeps failed and disabled distinguishable
	// without any extra bookkeeping here.
	enabled := backends.TotalCount
	if backends.EligibilityKnown {
		enabled = backends.EnabledCount
	}
	if backends.HealthyCount == 0 && (backends.TotalCount > 0 || backends.EligibilityKnown) {
		message := "No healthy backends available to route traffic"
		if backends.TotalCount == 0 {
			message = "No backends configured to route traffic"
		} else if enabled == 0 {
			message = "All backends are administratively disabled; no traffic can be routed"
		}
		conds = append(conds, HealthCondition{
			Category: "backend",
			Severity: "CRITICAL",
			Message:  message,
		})
	} else if enabled > 0 && backends.HealthyCount < enabled {
		// DEGRADED, not WARNING. #424 specifies DEGRADED for a degraded
		// backend, and summarizeHealthConditions maps WARNING-only to
		// HEALTHY, so a WARNING here reported two enabled backends with one
		// healthy as HEALTHY (issue #424 review round 9, blocker 4).
		//
		// CRITICAL is deliberately reserved for the branch above: with no
		// healthy backend at all there is nowhere to route traffic, which is a
		// categorically different condition from losing part of a fleet that
		// still has somewhere to send packets.
		//
		// The message names the enabled population so the count cannot be
		// misread against TotalCount: a disabled backend is neither healthy nor
		// failed, and an operator seeing "1 of 2" must be able to tell which two.
		conds = append(conds, HealthCondition{
			Category: "backend",
			Severity: "DEGRADED",
			Message: fmt.Sprintf("%d of %d enabled backends are degraded or unavailable "+
				"(%d administratively disabled, not counted as failures)",
				enabled-backends.HealthyCount, enabled, backends.DisabledCount),
		})
	}

	if len(handshake.StaleLiveSessions) > 0 {
		conds = append(conds, HealthCondition{
			Category:   "sessions",
			Severity:   "WARNING",
			MessageKey: "vpn_problem_stale_handshake",
			Message: fmt.Sprintf("%d active live session(s) have stale upstream handshakes (> %s)",
				len(handshake.StaleLiveSessions), DefaultHealthThresholds.HandshakeStaleAge),
		})
	}
	return conds
}

func summarizeHealthConditions(conditions []HealthCondition) (string, string) {
	var criticalCount, degradedCount, warningCount int
	for _, c := range conditions {
		switch c.Severity {
		case "CRITICAL":
			criticalCount++
		case "DEGRADED":
			degradedCount++
		case "WARNING":
			warningCount++
		}
	}

	// firstMessageAtSeverity returns the message of the first condition at the
	// winning severity, so the headline describes the condition that actually
	// set the headline (issue #424 round 2, finding 7).
	firstMessageAtSeverity := func(severity string) string {
		for _, c := range conditions {
			if c.Severity == severity {
				return c.Message
			}
		}
		return ""
	}

	if criticalCount > 0 {
		return HealthCritical, fmt.Sprintf("%d critical issue(s) affecting forwarder health: %s",
			criticalCount, firstMessageAtSeverity("CRITICAL"))
	}
	if degradedCount > 0 {
		return HealthDegraded, fmt.Sprintf("%d degradation condition(s) detected: %s",
			degradedCount, firstMessageAtSeverity("DEGRADED"))
	}
	if warningCount > 0 {
		return HealthHealthy, fmt.Sprintf("Operational with %d warning condition(s): %s",
			warningCount, firstMessageAtSeverity("WARNING"))
	}
	return HealthHealthy, "All forwarder and dataplane components are operating normally"
}
