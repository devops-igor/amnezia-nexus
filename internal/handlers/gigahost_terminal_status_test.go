package handlers

// Regression for the provider's terminal cancellation status.
//
// The provider documents the terminal deployment status as "cancelled" (two l's).
// Both spellings occur in the codebase: "cancelled" is the provider's documented
// value and what the panel writes when it decides an order was withdrawn, while
// "canceled" appears in unrelated setup-intent and process-probe state. A
// spelling-normalization sweep must therefore never change this constant: doing so
// silently un-teaches the deploy path which provider statuses are terminal.
//
// The observable consequence is a stalled order. When a provider answers
// "cancelled", isGigahostFailed must recognize it so the deploy reports failure and
// stops; if it does not, the status is treated as still-in-progress and is polled
// until the wait budget expires, showing the operator a timeout instead of the
// provider's decision.

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestGigahostTerminalCancellationRecognized pins the constant and both spellings
// the deploy path must treat as terminal.
func TestGigahostTerminalCancellationRecognized(t *testing.T) {
	if statusCancelled != "cancelled" {
		t.Fatalf("statusCancelled = %q, want the provider's documented %q", statusCancelled, "cancelled")
	}

	// Both spellings, in the case the provider and the panel actually produce. The
	// check is exact-match (lowercased), deliberately: a prefix rule would treat an
	// in-progress "cancelling" as terminal, so this pins exactly the two documented
	// spellings rather than widening the contract.
	terminal := []string{"cancelled", "canceled", "CANCELLED", "Cancelled", "Canceled"}
	for _, status := range terminal {
		if !isGigahostFailed(status) {
			t.Errorf("isGigahostFailed(%q) = false, want true: a cancelled deploy must not be polled as pending", status)
		}
	}

	// The statuses that are genuinely still in progress must stay non-terminal, or
	// the fix would be a different bug: a real deployment reported as failed.
	inProgress := []string{
		gigahost.StatusPending, gigahost.StatusDeploying, gigahost.StatusWaiting,
		gigahost.StatusInstalling, "", "installing_protocol",
	}
	for _, status := range inProgress {
		if isGigahostFailed(status) {
			t.Errorf("isGigahostFailed(%q) = true, want false: an in-progress deploy must not be reported failed", status)
		}
	}
}

// TestGigahostDeployCancelledStatusFailsFast proves the behavior end to end through
// the real deploy handler: a provider that reports "cancelled" must produce a
// failure immediately, not a poll-until-timeout.
func TestGigahostDeployCancelledStatusFailsFast(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	var statusReads int
	h.SetGigahostClient(&mockGigahostClient{
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			statusReads++
			return &gigahost.DeployStatusResponse{
				OrderID: "ord_cancelled",
				Status:  "cancelled",
			}, nil
		},
	})

	// A short wait budget: if the cancelled status were misread as in-progress the
	// handler would keep polling and the test would take this long to return.
	_, _, err := h.verifyGigahostVPSReady(context.Background(), func() gigahost.Client {
		c, _ := h.resolveGigahostClient(context.Background(), nil)
		return c.client
	}(), GigahostDeployRequest{
		OrderID:        "ord_cancelled",
		WaitReady:      true,
		WaitTimeoutSec: 5,
	}, nil)

	if err == nil {
		t.Fatal("a provider-cancelled deployment returned no error; it would be reported to the operator as progress")
	}
	if !strings.Contains(err.Error(), "failed at provider") {
		t.Errorf("error = %v, want a provider-failure error", err)
	}
	// Fail-fast, not timeout: exactly the one initial status read, never a poll loop.
	if statusReads != 1 {
		t.Errorf("provider status reads = %d, want 1 (a cancelled deploy must fail fast, not poll)", statusReads)
	}
}
