package handlers

// Bounded per-admin admission cooldown for repeated rejected deploy attempts.
//
// A rejected Gigahost order attempt costs provider reads (catalog, then server
// inventory). When the rejection is persistent - a budget cap already crossed, a
// stalled account call - pressing the button again re-runs the whole sequence
// against a provider that is already the suspect, and does so while the admin
// learns nothing new.
//
// This is deliberately NOT a cache of decisions:
//   - only REJECTIONS are recorded, so a positive eligibility or financial
//     verdict is never reused and no purchase can ever be fast-pathed;
//   - the entry is dropped on a successful attempt;
//   - the window is short and stateless in memory, so nothing survives a restart
//     and nothing becomes a permanent lockout;
//   - the key is the authenticated admin's own user id, so one admin can never
//     throttle another.
//
// The cooldown suppresses the retry, not the information: the response names the
// condition, says how long to wait, and carries Retry-After. A genuine provider
// error is never turned into a cooldown - only failures that were themselves
// classified as a persistent rejection arm the window.

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// repeatedSubmitWindow is how long a rejected attempt suppresses an immediate
// retry by the same admin. Short on purpose: it must absorb double-clicks and
// scripted retry storms without being a lockout, and it is only a hint - the
// admin can retry successfully the moment the underlying condition changes.
const repeatedSubmitWindow = 20 * time.Second

// maxAdmissionEntries caps the in-memory table so a long-lived process with many
// admins cannot grow it without bound.
const maxAdmissionEntries = 256

// orderAdmission tracks the last rejected attempt per admin.
type orderAdmission struct {
	mu        sync.Mutex
	rejectedA map[string]time.Time
}

// repeatedSubmitCooldown reports the configured suppression window.
func repeatedSubmitCooldown() time.Duration {
	return repeatedSubmitWindow
}

// admission returns the lazily created table. The handlers struct is shared, so
// creation is guarded by a sync.Once held on the struct itself.
func (h *Handlers) admission() *orderAdmission {
	h.admissionOnce.Do(func() {
		h.admissionState = &orderAdmission{rejectedA: make(map[string]time.Time)}
	})
	return h.admissionState
}

// orderAdmissionBlocked reports whether the admin must wait, and for how long.
//
// Purging happens on read, so an expired window disappears without a background
// goroutine and no entry can outlive its usefulness.
func (h *Handlers) orderAdmissionBlocked(userID string) (bool, time.Duration) {
	if userID == "" {
		// Without a stable identity there is nothing to key on; never throttle.
		return false, 0
	}
	table := h.admission()
	table.mu.Lock()
	defer table.mu.Unlock()
	rejectedAt, ok := table.rejectedA[userID]
	if !ok {
		return false, 0
	}
	remaining := repeatedSubmitWindow - time.Since(rejectedAt)
	if remaining <= 0 {
		delete(table.rejectedA, userID)
		return false, 0
	}
	return true, remaining
}

// recordRejectedOrderAttempt arms the cooldown for the admin. Only called for
// failures that are persistent rejections, never for transient provider errors.
func (h *Handlers) recordRejectedOrderAttempt(userID string, at time.Time) {
	if userID == "" {
		return
	}
	table := h.admission()
	table.mu.Lock()
	defer table.mu.Unlock()
	// Bound the table: drop expired entries, and if it is still full, keep the
	// newest by evicting an arbitrary stale one rather than growing forever.
	if len(table.rejectedA) >= maxAdmissionEntries {
		now := time.Now()
		for key, when := range table.rejectedA {
			if now.Sub(when) > repeatedSubmitWindow {
				delete(table.rejectedA, key)
			}
		}
		if len(table.rejectedA) >= maxAdmissionEntries {
			for key := range table.rejectedA {
				delete(table.rejectedA, key)
				break
			}
		}
	}
	table.rejectedA[userID] = at
}

// clearOrderAdmission drops the admin's entry after a successful attempt, so a
// stale rejection can never gate a later legitimate order.
func (h *Handlers) clearOrderAdmission(userID string) {
	if userID == "" {
		return
	}
	table := h.admission()
	table.mu.Lock()
	defer table.mu.Unlock()
	delete(table.rejectedA, userID)
}

// repeatedSubmitSuppressed writes the cooldown response when the admin is inside
// a window and reports whether it handled the request. Extracted from the order
// handler to keep that function under the repository complexity limit.
func (h *Handlers) repeatedSubmitSuppressed(w http.ResponseWriter, adminID string) bool {
	blocked, wait := h.orderAdmissionBlocked(adminID)
	if !blocked {
		return false
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	h.JSON(w, http.StatusTooManyRequests, map[string]any{
		"status":         "repeat_suppressed",
		"error":          "repeat_suppressed",
		"message":        "A previous deployment attempt was rejected moments ago; wait for the current state to change before retrying.",
		"retry_after_ms": wait.Milliseconds(),
	})
	return true
}

// preProviderRejection records a rejected attempt when the failure is one where an
// immediate retry cannot help, then writes the existing error response.
func (h *Handlers) preProviderRejection(adminID string, err error, status int) {
	if isPersistentRejection(status, err.Error()) {
		h.recordRejectedOrderAttempt(adminID, time.Now())
	}
}

// orderEligibilityAdmission performs the pre-provider gates that precede the
// budget mutex: the repeated-submission cooldown, the eligibility check and the
// catalog validation. It reports handled=true when the request was already
// answered, so the order handler keeps a single branch for all three.
func (h *Handlers) orderEligibilityAdmission(
	ctx context.Context, w http.ResponseWriter, client gigahost.Client, req OrderServerPayload, adminID string,
) ([]gigahost.HourlyPlan, bool) {
	if h.repeatedSubmitSuppressed(w, adminID) {
		return nil, true
	}
	catalogPlans, err := h.verifyAccountEligibility(ctx, client)
	if err != nil {
		h.preProviderRejection(adminID, err, eligibilityErrorStatus(err))
		h.handleEligibilityError(w, err)
		return nil, true
	}
	if err := validateOrderAgainstCatalog(catalogPlans, req); err != nil {
		h.recordRejectedOrderAttempt(adminID, time.Now())
		h.handleBudgetCheckError(w, err)
		return nil, true
	}
	return catalogPlans, false
}

// isPersistentRejection classifies a pre-provider failure as one where retrying
// immediately cannot help. Transient transport failures are deliberately NOT
// included: those must surface as themselves.
func isPersistentRejection(status int, body string) bool {
	switch status {
	case 400: // budget_exceeded / invalid_plan: the request or state is wrong
		return true
	case 402: // insufficient_credit: a financial rejection
		return true
	default:
		return false
	}
}
