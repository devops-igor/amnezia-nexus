package tunnel

import (
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TransitionGate names the condition that currently decides whether a backend is
// eligible for traffic. It is a closed vocabulary so an operator surface can
// distinguish the reasons an automated transition is withheld or applied instead
// of showing one opaque label.
type TransitionGate string

const (
	// GateNone means no gate is withheld: the backend's status is the health
	// prober's ordinary verdict.
	GateNone TransitionGate = "none"
	// GateAdministrative means an operator disabled the backend. Automated
	// health decisions do not apply to it.
	GateAdministrative TransitionGate = "administrative"
	// GateEnrollmentQuarantine means initial enrollment has not been qualified.
	// A successful outer handshake is not admission evidence, so the backend
	// stays out of rotation regardless of its probe result.
	GateEnrollmentQuarantine TransitionGate = "enrollment_quarantine"
	// GateHealthDisable means the consecutive-failure threshold withdrew the
	// backend. Established sessions are handed to failover.
	GateHealthDisable TransitionGate = "health_disable"
	// GateOuterUnproven means the backend is not active because its outer
	// handshake (or protocol-appropriate probe) has not succeeded.
	GateOuterUnproven TransitionGate = "outer_unproven"
)

// AttemptOutcome is the sanitized result of one probe attempt.
type AttemptOutcome string

const (
	// OutcomeUnknown means no attempt has been observed for this generation.
	OutcomeUnknown AttemptOutcome = "unknown"
	// OutcomeSuccess means the attempt's evidence was affirmative.
	OutcomeSuccess AttemptOutcome = "success"
	// OutcomeFailure means the attempt's evidence was negative.
	OutcomeFailure AttemptOutcome = "failure"
	// OutcomeNotRun means the attempt did not produce evidence at all (for
	// example, an administratively disabled backend is not probed).
	OutcomeNotRun AttemptOutcome = "not_run"
)

// FailureCategory distinguishes the failure streaks that never combine. Sharing
// one counter let an attachment failure complete a streak built from outer
// handshake failures and withdraw a backend whose data path was never shown to
// be broken.
type FailureCategory string

const (
	// FailureOuter is a failed outer handshake / protocol probe.
	FailureOuter FailureCategory = "outer"
	// FailureAttachment is a failed data-plane attach attempt.
	FailureAttachment FailureCategory = "attachment"
	// FailureInner is a failed in-tunnel canary exchange on an attached device.
	FailureInner FailureCategory = "inner"
	// FailureNone means the last observation was not a failure.
	FailureNone FailureCategory = ""
)

// EvidenceFreshness reports whether recorded inner evidence is usable right now
// and, if not, why not. It is derived from the existing recording cadence; it is
// not an independent timer.
type EvidenceFreshness string

const (
	// FreshnessFresh means the evidence is within the bound derived from the
	// probe cadence and belongs to the current tunnel generation and device.
	FreshnessFresh EvidenceFreshness = "fresh"
	// FreshnessStale means recorded evidence exists but is too old to authorize
	// anything.
	FreshnessStale EvidenceFreshness = "stale"
	// FreshnessNone means no inner evidence has ever been recorded.
	FreshnessNone EvidenceFreshness = "none"
	// FreshnessPreviousDevice means the recorded evidence came from a backend
	// device that is no longer attached, so it cannot speak for the current one.
	FreshnessPreviousDevice EvidenceFreshness = "previous_device"
	// FreshnessPreviousGeneration means the recorded evidence belongs to a
	// replaced tunnel row.
	FreshnessPreviousGeneration EvidenceFreshness = "previous_generation"
)

// TransitionEvidence is the sanitized record of what the health decision used.
//
// It exists because a status label and a status-write timestamp are not evidence:
// `last_health_check` advances on every status write, including unsuccessful
// states, so it can never be presented as proof that a probe succeeded. This
// record separates the LAST ATTEMPT (what was observed, and how it ended) from
// the last CONFIRMED SUCCESSFUL health evidence (which may be much older, or
// absent entirely).
//
// It carries identity and classification only: tunnel/server IDs, a state
// version, a device creation stamp, counters, closed-vocabulary categories and
// timestamps. It never carries endpoints, keys, client configuration, raw probe
// payloads or error chains, so it is safe on a public operator surface.
type TransitionEvidence struct {
	// Gate is the condition currently deciding eligibility.
	Gate TransitionGate `json:"gate"`
	// TunnelID and StateVersion are the generation this record describes. A
	// reader must ignore the record when either no longer matches the backend.
	TunnelID     int64 `json:"tunnel_id"`
	StateVersion int64 `json:"state_version"`
	// Enabled is the administrative intent, independent of runtime health.
	Enabled bool `json:"enabled"`

	// LastAttempt is the most recent probe attempt for this generation.
	LastAttemptOutcome AttemptOutcome `json:"last_attempt_outcome"`
	// LastAttemptAt is when that attempt was made. nil means none was observed.
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	// LastAttemptOuter and LastAttemptInner are that attempt's two independent
	// observations. An outer handshake success says nothing about whether the
	// attached data device forwards payload, so they are reported separately.
	LastAttemptOuter AttemptOutcome `json:"last_attempt_outer"`
	LastAttemptInner AttemptOutcome `json:"last_attempt_inner"`

	// FailureCategory and FailureCount are the streak that the last negative
	// observation belongs to. Categories never accumulate into one another.
	FailureCategory FailureCategory `json:"failure_category,omitempty"`
	FailureCount    int             `json:"failure_count,omitempty"`
	// FailureThreshold is the configured threshold for that category, so a
	// count can be read without guessing the policy.
	FailureThreshold int `json:"failure_threshold,omitempty"`

	// LastSuccessAt is the timestamp of the last CONFIRMED successful inner
	// evidence for this generation and device. nil means none was recorded; it is
	// never inferred from a status write.
	LastSuccessAt *time.Time `json:"last_successful_health_at,omitempty"`
	// SuccessFreshness classifies LastSuccessAt against the cadence-derived
	// bound and the current device/generation identity.
	SuccessFreshness EvidenceFreshness `json:"success_freshness"`
	// DeviceCreatedAt identifies the backend device the evidence is bound to.
	DeviceCreatedAt *time.Time `json:"device_created_at,omitempty"`
}

// gateRecord is the mutable per-server record behind TransitionEvidence. It is
// guarded by HealthProber.mu and fenced by tunnel generation, so a record
// belonging to a replaced backend can never be read as the current verdict.
type gateRecord struct {
	tunnelID     int64
	stateVersion int64
	enabled      bool

	lastAttemptAt     time.Time
	lastAttemptOuter  AttemptOutcome
	lastAttemptInner  AttemptOutcome
	failureCategory   FailureCategory
	failureCount      int
	failureThreshold  int
	lastSuccessAt     time.Time
	lastSuccessDevice time.Time
	deviceCreatedAt   time.Time
	gate              TransitionGate
}

// lastInnerOutcome reports the inner observation belonging to the attempt just
// made. A protocol without an in-tunnel canary cannot produce one, and reporting
// that as "not run" keeps an outer handshake from being presented as data-path
// proof.
func (hp *HealthProber) lastInnerOutcome(t *models.BackendTunnel) AttemptOutcome {
	if hp == nil || t == nil || !hp.hasCanaryProber(t) {
		return OutcomeNotRun
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	if rec, ok := hp.gateRecords[t.ServerID]; ok && rec != nil && rec.tunnelID == t.ID {
		if rec.lastAttemptInner == OutcomeSuccess || rec.lastAttemptInner == OutcomeFailure {
			return rec.lastAttemptInner
		}
	}
	return OutcomeUnknown
}

// attachedDeviceCreatedAt reports the creation stamp of the backend device
// currently attached to t, or the zero time when none is attached. It is the
// identity the recorded inner evidence is bound to.
func (hp *HealthProber) attachedDeviceCreatedAt(t *models.BackendTunnel) time.Time {
	if hp == nil || t == nil {
		return time.Time{}
	}
	return canaryDeviceGeneration(hp.GetDevice(t.ID))
}

// recordProbeAttempt records one probe attempt's sanitized outcome. outer is the
// protocol-level result; inner is the attached-device result, which is
// OutcomeNotRun when the attempt never reached the data plane.
//
// It is a pure in-memory write: no I/O, no callbacks, so it is safe on the probe
// hot path.
func (hp *HealthProber) recordProbeAttempt(t *models.BackendTunnel, outer, inner AttemptOutcome) {
	if hp == nil || t == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	rec := hp.gateRecordLocked(t)
	rec.lastAttemptAt = hp.now()
	rec.lastAttemptOuter = outer
	rec.lastAttemptInner = inner
}

// gateRecordLocked returns the record for t, resetting it when t belongs to a
// different tunnel generation than the one on file. Callers hold hp.mu.
func (hp *HealthProber) gateRecordLocked(t *models.BackendTunnel) *gateRecord {
	if hp.gateRecords == nil {
		hp.gateRecords = make(map[int64]*gateRecord)
	}
	rec := hp.gateRecords[t.ServerID]
	if rec == nil || rec.tunnelID != t.ID {
		rec = &gateRecord{tunnelID: t.ID}
		hp.gateRecords[t.ServerID] = rec
	}
	rec.stateVersion = t.StateVersion
	rec.enabled = t.Enabled
	return rec
}

// recordFailureStreak records the category and count that produced a negative
// decision, together with the threshold in force, so the surface can show "2 of
// 3 outer failures" instead of a bare status.
func (hp *HealthProber) recordFailureStreak(t *models.BackendTunnel, category FailureCategory, count, threshold int) {
	if hp == nil || t == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	rec := hp.gateRecordLocked(t)
	rec.failureCategory = category
	rec.failureCount = count
	rec.failureThreshold = threshold
}

// recordGate records the condition currently deciding eligibility for t.
func (hp *HealthProber) recordGate(t *models.BackendTunnel, gate TransitionGate, deviceCreated time.Time) {
	if hp == nil || t == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	rec := hp.gateRecordLocked(t)
	rec.gate = gate
	if !deviceCreated.IsZero() {
		rec.deviceCreatedAt = deviceCreated
	}
}

// TransitionEvidenceFor returns the sanitized transition evidence for a backend.
//
// ok is false when no observation has been recorded for the CURRENT tunnel
// generation; a caller must then report the gate as unknown rather than reuse a
// previous backend's record. The device identity in the snapshotted tunnel is
// used to classify the recorded success, so evidence from a detached or replaced
// device is reported as such instead of being presented as current health.
func (hp *HealthProber) TransitionEvidenceFor(t *models.BackendTunnel) (TransitionEvidence, bool) {
	if hp == nil || t == nil {
		return TransitionEvidence{}, false
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	rec, ok := hp.gateRecords[t.ServerID]
	if !ok || rec == nil || rec.tunnelID != t.ID {
		return TransitionEvidence{}, false
	}

	ev := TransitionEvidence{
		Gate:             rec.gate,
		TunnelID:         rec.tunnelID,
		StateVersion:     t.StateVersion,
		Enabled:          t.Enabled,
		LastAttemptOuter: rec.lastAttemptOuter,
		LastAttemptInner: rec.lastAttemptInner,
		FailureCategory:  rec.failureCategory,
		FailureCount:     rec.failureCount,
		FailureThreshold: rec.failureThreshold,
		SuccessFreshness: FreshnessNone,
	}
	if ev.Gate == "" {
		ev.Gate = GateNone
	}
	ev.LastAttemptOutcome = attemptOutcome(rec.lastAttemptOuter, rec.lastAttemptInner)
	ev.LastAttemptAt = timePtr(rec.lastAttemptAt)
	ev.LastSuccessAt = timePtr(rec.lastSuccessAt)
	ev.DeviceCreatedAt = timePtr(rec.deviceCreatedAt)

	if !rec.lastSuccessAt.IsZero() {
		ev.SuccessFreshness = hp.classifyEvidenceLocked(rec, t)
	}

	// A record observed for an administratively disabled backend still describes
	// the last attempt; the gate is reported from the recorded decision.
	return ev, true
}

// timePtr returns a pointer to a copy of at, or nil for the zero time, so an
// absent observation serializes as absent instead of as a zero timestamp.
func timePtr(at time.Time) *time.Time {
	if at.IsZero() {
		return nil
	}
	cp := at
	return &cp
}

// attemptOutcome reduces the two independent observations of one attempt to the
// single headline outcome a surface can show, without hiding which half failed.
//
// The reduction is a table rather than a comparison chain because the four
// outcomes combine into a small closed set: an attempt succeeds only when its
// affirmative observation was taken and nothing contradicted it, fails when
// either half failed, and is otherwise "not established" - which is deliberately
// distinct from both success and failure.
func attemptOutcome(outer, inner AttemptOutcome) AttemptOutcome {
	switch outer {
	case OutcomeSuccess:
		if inner == OutcomeSuccess || inner == OutcomeNotRun {
			return OutcomeSuccess
		}
		if inner == OutcomeFailure {
			return OutcomeFailure
		}
		return OutcomeUnknown
	case OutcomeFailure:
		return OutcomeFailure
	case OutcomeNotRun:
		if inner == OutcomeFailure {
			return OutcomeFailure
		}
		return OutcomeNotRun
	default:
		if inner == OutcomeFailure {
			return OutcomeFailure
		}
		return OutcomeUnknown
	}
}

// classifyEvidenceLocked reports whether the recorded inner success may still be
// used, and if not, which fence rejected it. Callers hold hp.mu.
func (hp *HealthProber) classifyEvidenceLocked(rec *gateRecord, t *models.BackendTunnel) EvidenceFreshness {
	if rec.lastSuccessDevice.IsZero() {
		// Without a device stamp the evidence cannot be bound to a data path.
		return FreshnessNone
	}
	if !rec.lastSuccessDevice.Equal(rec.deviceCreatedAt) && !rec.deviceCreatedAt.IsZero() {
		return FreshnessPreviousDevice
	}
	// A recorded failure since that success withdraws the evidence regardless of
	// how recent it is: the timestamp only says when the canary last SUCCEEDED,
	// not whether it has failed since. hp.canaryFailCounts is guarded by this same
	// lock, so it is read directly rather than through the locking accessor.
	if hp.canaryFailCounts[t.ServerID] > 0 {
		return FreshnessStale
	}
	age := hp.now().Sub(rec.lastSuccessAt)
	if age < 0 || age > hp.maxCanaryEvidenceAgeLocked() {
		return FreshnessStale
	}
	if !t.Enabled {
		return FreshnessStale
	}
	return FreshnessFresh
}
