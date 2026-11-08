package handlers

// Bounded per-admin admission control for Gigahost deploy attempts.
//
// Two distinct mechanisms are needed and were previously conflated:
//
//  1. IN-FLIGHT RESERVATION (atomicity). An attempt claims the admin's single
//     slot BEFORE any provider I/O, in the same critical section as the check.
//     A check -> I/O -> record sequence lets every concurrent request pass the
//     check while the first is still blocked on the network; that is precisely
//     the retry storm this exists to stop. The reservation is released on every
//     terminal path, and no mutex is ever held across a provider call.
//
//  2. COOLDOWN (after a failure). When an attempt ends badly - a persistent
//     rejection OR a provider timeout/error - the admin is suppressed for a
//     short window so an immediate repeat does not re-run an expensive sequence
//     that just failed. Provider timeouts qualify: repeated stalled account
//     reads were previously unlimited.
//
// This is deliberately NOT a cache of decisions: no eligibility, credit or price
// verdict is stored or reused, so no purchase can be fast-pathed. The FIRST
// genuine provider error is returned as itself with its own status; the cooldown
// only speaks about the prior failure on LATER attempts, and labels it rather
// than echoing error text.
//
// The window is short and in memory: no schema, no persistence, no background
// goroutine, so nothing becomes a permanent lockout.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// repeatedSubmitWindow is an explicit operational limit: how long a failed
// attempt suppresses an immediate retry by the same admin. Short on purpose - it
// must absorb double-clicks and retry storms without being a lockout.
const repeatedSubmitWindow = 20 * time.Second

// maxAdmissionEntries caps the in-memory table.
const maxAdmissionEntries = 256

// Closed set of prior-failure labels. A label, never err.Error() text.
const (
	failureBudget          = "budget"
	failureCredit          = "credit"
	failureProviderTimeout = "provider_timeout"
	failureProviderError   = "provider_error"
)

// admissionEntry is one admin's state: at most one attempt in flight, plus when
// and why the last attempt failed.
type admissionEntry struct {
	inFlight   bool
	failedAt   time.Time
	failedKind string
}

// orderAdmission is the per-admin admission table.
type orderAdmission struct {
	mu      sync.Mutex
	entries map[string]*admissionEntry
}

// repeatedSubmitCooldown reports the configured suppression window.
func repeatedSubmitCooldown() time.Duration {
	return repeatedSubmitWindow
}

// admission returns the lazily created table.
func (h *Handlers) admission() *orderAdmission {
	h.admissionOnce.Do(func() {
		h.admissionState = &orderAdmission{entries: make(map[string]*admissionEntry)}
	})
	return h.admissionState
}

// remainingWindow is how much of the failure cooldown is left. Caller holds the lock.
func remainingWindow(entry *admissionEntry) time.Duration {
	if entry.failedAt.IsZero() {
		return 0
	}
	if left := repeatedSubmitWindow - time.Since(entry.failedAt); left > 0 {
		return left
	}
	return 0
}

// evictIfFull keeps the table bounded. Caller holds the lock.
func evictIfFull(table *orderAdmission, keep string) {
	if len(table.entries) < maxAdmissionEntries {
		return
	}
	now := time.Now()
	for key, entry := range table.entries {
		if key == keep || entry.inFlight {
			continue
		}
		if now.Sub(entry.failedAt) > repeatedSubmitWindow {
			delete(table.entries, key)
		}
	}
	if len(table.entries) < maxAdmissionEntries {
		return
	}
	for key, entry := range table.entries {
		if key == keep || entry.inFlight {
			continue
		}
		delete(table.entries, key)
		return
	}
}

// admitAttempt atomically claims the admin's single in-flight slot.
//
// The check and the claim share one lock, so two concurrent callers can never
// both be admitted. It performs no provider I/O. On refusal it returns the
// remaining wait and the prior failure label so the response can explain itself.
func (h *Handlers) admitAttempt(userID string) (ticket *admissionEntry, wait time.Duration, priorFailure string, ok bool) {
	if userID == "" {
		// No stable identity: never throttle. A nil ticket needs no release.
		return nil, 0, "", true
	}
	table := h.admission()
	table.mu.Lock()
	defer table.mu.Unlock()

	entry, present := table.entries[userID]
	if !present {
		entry = &admissionEntry{}
		table.entries[userID] = entry
		evictIfFull(table, userID)
	}
	if entry.inFlight {
		return nil, remainingWindow(entry), entry.failedKind, false
	}
	if left := remainingWindow(entry); left > 0 {
		return nil, left, entry.failedKind, false
	}
	entry.inFlight = true
	return entry, 0, "", true
}

// releaseAttempt ends an attempt. A non-empty failureKind arms the cooldown; an
// empty one clears it. Every terminal path must call this or the slot leaks.
func (h *Handlers) releaseAttempt(ticket *admissionEntry, failureKind string) {
	if ticket == nil {
		return
	}
	table := h.admission()
	table.mu.Lock()
	defer table.mu.Unlock()
	ticket.inFlight = false
	if failureKind == "" {
		ticket.failedAt = time.Time{}
		ticket.failedKind = ""
		return
	}
	ticket.failedAt = time.Now()
	ticket.failedKind = failureKind
}

// orderAdmissionBlocked reports whether the admin must wait, and for how long.
func (h *Handlers) orderAdmissionBlocked(userID string) (bool, time.Duration) {
	if userID == "" {
		return false, 0
	}
	table := h.admission()
	table.mu.Lock()
	defer table.mu.Unlock()
	entry, present := table.entries[userID]
	if !present {
		return false, 0
	}
	if entry.inFlight {
		return true, 0
	}
	left := remainingWindow(entry)
	if left <= 0 {
		delete(table.entries, userID)
		return false, 0
	}
	return true, left
}

// clearOrderAdmission drops the admin's entry entirely.
func (h *Handlers) clearOrderAdmission(userID string) {
	if userID == "" {
		return
	}
	table := h.admission()
	table.mu.Lock()
	defer table.mu.Unlock()
	delete(table.entries, userID)
}

// recordRejectedOrderAttempt arms the cooldown without a live ticket.
func (h *Handlers) recordRejectedOrderAttempt(userID string, at time.Time) {
	if userID == "" {
		return
	}
	table := h.admission()
	table.mu.Lock()
	defer table.mu.Unlock()
	entry, present := table.entries[userID]
	if !present {
		entry = &admissionEntry{}
		table.entries[userID] = entry
		evictIfFull(table, userID)
	}
	entry.failedAt = at
	if entry.failedKind == "" {
		entry.failedKind = failureBudget
	}
}

// suppressionWriting writes the admission refusal and reports whether it handled
// the request. The response names the PRIOR failure so the admin knows what to
// fix, and never implies the current attempt was placed.
func (h *Handlers) suppressionWriting(w http.ResponseWriter, adminID string) bool {
	blocked, wait := h.orderAdmissionBlocked(adminID)
	if !blocked {
		return false
	}
	table := h.admission()
	table.mu.Lock()
	prior := ""
	if entry, present := table.entries[adminID]; present {
		prior = entry.failedKind
	}
	table.mu.Unlock()

	if wait <= 0 {
		wait = time.Second
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	body := map[string]any{
		"status":         "repeat_suppressed",
		"error":          "repeat_suppressed",
		"retry_after_ms": wait.Milliseconds(),
		"message":        suppressionMessage(prior),
	}
	if prior != "" {
		body["prior_failure"] = prior
	}
	h.JSON(w, http.StatusTooManyRequests, body)
	return true
}

// suppressionMessage explains the refusal in terms of the prior failure.
func suppressionMessage(priorFailure string) string {
	switch priorFailure {
	case failureProviderTimeout:
		return "A previous attempt did not reach Gigahost within its timeout. Wait before retrying so the provider is not re-queried while it is unhealthy; this request was not sent."
	case failureProviderError:
		return "A previous attempt failed while talking to Gigahost. Wait before retrying so the provider is not re-queried while it is unhealthy; this request was not sent."
	case failureBudget:
		return "A previous attempt was rejected by the monthly budget. Wait for the budget to change before retrying."
	case failureCredit:
		return "A previous attempt was rejected for insufficient credit. Wait for the account credit to change before retrying."
	default:
		return "A previous deployment attempt was rejected moments ago; wait for the current state to change before retrying."
	}
}

// failureKindFor classifies a completed failing attempt for the cooldown.
//
// A provider timeout/error DOES arm the cooldown: repeated stalled account reads
// were unlimited before this, and a stalled call is the expensive case. The kind
// is a closed label, never err.Error() text.
func failureKindFor(status int, err error) string {
	switch {
	case status == http.StatusPaymentRequired:
		return failureCredit
	case status == http.StatusBadRequest:
		return failureBudget
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return failureProviderTimeout
	case err != nil:
		return failureProviderError
	case status == http.StatusBadGateway:
		return failureProviderError
	default:
		return ""
	}
}

// orderEligibilityAdmission performs the pre-provider gates that precede the
// budget mutex. It reports handled=true when the request was already answered,
// plus the closed failure label the caller must use when releasing its
// reservation, so a provider timeout arms the cooldown instead of leaving
// repeated stalled reads unlimited.
func (h *Handlers) orderEligibilityAdmission(
	ctx context.Context, w http.ResponseWriter, client gigahost.Client, req OrderServerPayload,
) (plans []gigahost.HourlyPlan, handled bool, failureKind string) {
	catalogPlans, err := h.verifyAccountEligibility(ctx, client)
	if err != nil {
		h.handleEligibilityError(w, err)
		return nil, true, failureKindFor(eligibilityErrorStatus(err), err)
	}
	if err := validateOrderAgainstCatalog(catalogPlans, req); err != nil {
		h.handleBudgetCheckError(w, err)
		return nil, true, failureBudget
	}
	return catalogPlans, false, ""
}
