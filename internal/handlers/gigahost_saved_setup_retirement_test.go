package handlers

// Retirement reaches the saved setup work, not only the inventory.
//
// An operator can approve setup for an order long before any panel server exists: the job
// then sits pending, or pauses awaiting credentials, while the panel's inventory records
// that the provider no longer holds the deployment. That is a normal, explicitly supported
// workflow, and it was the workflow retirement did not reach.
//
// The approval's own row cannot answer the question. It carries neither the provider's
// absence observation (which is written on the ORDER ledger) nor the onboarding journal, so
// the setup-intents list reported provider_absent=false and kept offering Resume, and the
// background tracker kept calling GetDeployStatus for an order the panel had recorded as
// gone. Browser-side suppression did not help: these are independent consumers.
//
// Every case drives the real handlers over a real SQLite database and the real tracker, and
// asserts the observable effect - the rendered actions, and a provider-call counter for the
// tracker - rather than the presence of a code path.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// seedSavedSetupForOrder creates a saved setup approval against a real order row.
//
// state is the durable approval state, which is what the real list returns and the real
// renderer reads: "pending" is a job the tracker is still polling, and
// "awaiting_credentials" is a job paused before registration that still offered Resume.
func seedSavedSetupForOrder(t *testing.T, h *Handlers, orderID, state string) {
	t.Helper()
	ctx := context.Background()
	intent := buildSetupIntent(orderID, storedOrder(t, h, orderID),
		GigahostSetupApproveRequest{Protocol: "awg", UseOrderCredential: true}, "fixture-admin")
	intent.State = state
	intent.Step = "approved"
	if state == models.SetupStateAwaitingCredentials {
		intent.Step = "awaiting_credentials"
	}
	if err := h.db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("create the saved setup approval for %s: %v", orderID, err)
	}
}

// readSetupIntentsBody calls the real list handler and returns its response body.
func readSetupIntentsBody(t *testing.T, h *Handlers) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/setup-intents", nil)
	req = req.WithContext(middleware.WithSession(req.Context(),
		&models.SessionData{UserID: "fixture-admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostSetupIntentsHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("the setup-intents list answered %d: %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// savedSetupRows is the per-order part of the saved-jobs response these tests read.
type savedSetupRows struct {
	Intents []struct {
		OrderID        string `json:"order_id"`
		State          string `json:"state"`
		ProviderAbsent bool   `json:"provider_absent"`
		OrderRetired   bool   `json:"order_retired"`
	} `json:"setup_intents"`
}

// savedSetupRowFor returns one row of the saved-jobs response by order id.
func savedSetupRowFor(t *testing.T, body, orderID string) (state string, providerAbsent, orderRetired bool) {
	t.Helper()
	var rows savedSetupRows
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		t.Fatalf("the saved-jobs response is not the documented shape: %v", err)
	}
	for _, intent := range rows.Intents {
		if intent.OrderID == orderID {
			return intent.State, intent.ProviderAbsent, intent.OrderRetired
		}
	}
	t.Fatalf("the saved-jobs response does not list order %s: %s", orderID, body)
	return "", false, false
}

// hasSavedSetupAction reports whether the rendered saved-jobs view offers one action.
func hasSavedSetupAction(buttons []string, action string) bool {
	return slices.Contains(buttons, action)
}

// TestRetiredOrderSuppressesSavedSetupActions is the presentation half of F1007-03.
//
// The order is retired through the real list read - a complete inventory answer attributed
// to its own account omits it - and the saved approval is then reloaded through the real
// list endpoint and rendered with the shipped module. The paused job must not offer an
// action that contacts the deployment, while a live order's identical job keeps Resume.
func TestRetiredOrderSuppressesSavedSetupActions(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	const retiredID = "ord_f1007_03_retired"
	const liveID = "ord_f1007_03_live"
	seedExistenceOrder(t, h, retiredID, 7301, models.PurchaseOriginPanelPurchase)
	seedExistenceOrder(t, h, liveID, 7302, models.PurchaseOriginPanelPurchase)
	seedSavedSetupForOrder(t, h, retiredID, models.SetupStateAwaitingCredentials)
	seedSavedSetupForOrder(t, h, liveID, models.SetupStateAwaitingCredentials)

	// The control first, on an untouched panel: both jobs offer Resume, so the change the
	// retirement makes is a change rather than a control this view never draws.
	before := runGigahostSetupIntentsRendererLoads(t, readSetupIntentsBody(t, h))
	if !hasSavedSetupAction(before.Buttons, "setup_intents_resume") {
		t.Fatalf("the fixture must offer Resume before any retirement, got %v", before.Buttons)
	}

	// Retire the first order through the real list read: the provider answered completely
	// for its own account and did not list it.
	if err := h.db.SetGigahostOrderProviderAccount(ctx, retiredID, existenceAccount); err != nil {
		t.Fatalf("record the order's account: %v", err)
	}
	h.SetGigahostClient(existenceProvider(t,
		[]gigahost.ServerInfo{{ID: 7302, OrderID: liveID, Status: gigahost.StatusReady}}, nil, nil))
	_ = gigahostOrderStatusRead(t, h, "")
	if !storedOrder(t, h, retiredID).ProviderAbsent() {
		t.Fatalf("the fixture did not retire the order through its inventory read")
	}
	if storedOrder(t, h, liveID).ProviderAbsent() {
		t.Fatalf("the fixture retired the live order")
	}

	body := readSetupIntentsBody(t, h)
	if _, _, retired := savedSetupRowFor(t, body, retiredID); !retired {
		t.Fatalf("the saved-jobs response must carry the order-level retirement: %s", body)
	}
	if _, _, retired := savedSetupRowFor(t, body, liveID); retired {
		t.Fatalf("the saved-jobs response reported a live order as retired: %s", body)
	}
	// The retirement is the order-level fact, not the older server-row one: this job paused
	// before any registration, so provider_absent is necessarily false here and the answer
	// must come from the order ledger.
	if _, providerAbsent, _ := savedSetupRowFor(t, body, retiredID); providerAbsent {
		t.Fatalf("the fixture is meant to exercise the order-level fact alone: %s", body)
	}

	view := runGigahostSetupIntentsRendererLoads(t, body)
	// Scoped to the retired order's own row: the live order's Resume is asserted in the
	// control below, and a container-wide assertion would attribute its button to this one.
	retiredRow := view.savedSetupRowForOrder(t, retiredID)
	if hasSavedSetupAction(retiredRow.Buttons, "setup_intents_resume") {
		t.Errorf("a retired order still offers Resume: %+v", retiredRow)
	}
	if hasSavedSetupAction(retiredRow.Buttons, "setup_intents_confirm_host") {
		t.Errorf("a retired order still offers host confirmation: %+v", retiredRow)
	}
	// The retired row reads as the ending it is, in the vocabulary the other surfaces use.
	if retiredRow.Stage != "deleted" {
		t.Errorf("a retired job must carry the deleted stage, got %q in %+v", retiredRow.Stage, retiredRow)
	}

	// The negative control, on the same render: the live order's job keeps its Resume, so the
	// correction is about the retired order rather than about suppressing saved actions.
	liveRow := view.savedSetupRowForOrder(t, liveID)
	if !hasSavedSetupAction(liveRow.Buttons, "setup_intents_resume") {
		t.Errorf("a live paused job lost its Resume action: %+v", liveRow)
	}
	if liveRow.Stage == "deleted" {
		t.Errorf("a live job must not read as ended: %+v", liveRow)
	}
}

// TestRetiredOrderStopsTheBackgroundTracker is the effect half of F1007-03.
//
// A pending approval is due, so a tracker pass reads the provider for it. After the order is
// retired durably, the pass must issue no provider status request at all - not a failing one
// that leaves the job pending, and not a successful one either. The provider answers "still
// provisioning" so the job legitimately stays pending and due across both passes; that is
// what makes the retirement the only thing that can stop the second read.
func TestRetiredOrderStopsTheBackgroundTracker(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	const retiredID = "ord_f1007_03_tracker"
	seedExistenceOrder(t, h, retiredID, 7303, models.PurchaseOriginPanelPurchase)
	seedSavedSetupForOrder(t, h, retiredID, models.SetupStatePending)
	if err := h.db.SetGigahostOrderProviderAccount(ctx, retiredID, existenceAccount); err != nil {
		t.Fatalf("record the order's account: %v", err)
	}

	// The control: before retirement the pending approval is genuinely polled, and the job
	// stays pending because the provider says it is still deploying. The clock is taken from
	// the approval's own due time rather than a literal, because the approval is scheduled at
	// creation time: a fixed past instant would leave it not yet due, the first pass would do
	// nothing, and the absence of a request after retirement would prove nothing.
	storedApproval, foundApproval, err := h.db.GetGigahostSetupIntent(ctx, retiredID)
	if err != nil || !foundApproval || storedApproval == nil {
		t.Fatalf("reload the fixture's approval: found=%v err=%v", foundApproval, err)
	}
	if storedApproval.NextAttemptAt.IsZero() {
		t.Fatalf("the fixture's approval has no due time: %+v", storedApproval)
	}
	clock := storedApproval.NextAttemptAt.UTC()

	provider := &trackerFakeProvider{} // ready=false: it keeps reporting progress
	tracker := gigahostsetup.New(h.db, gigahostsetup.Options{
		Resolve: func(context.Context) (gigahostsetup.ProviderReader, error) { return provider, nil },
		Now:     func() time.Time { return clock },
	})
	if err := tracker.RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass before retirement: %v", err)
	}
	baseline := provider.statusReads
	if baseline == 0 {
		t.Fatalf("the fixture must poll a pending approval before retirement, got %d reads", baseline)
	}
	clock = clock.Add(gigahostsetup.DefaultInterval + time.Second)
	if err := tracker.RunOnce(ctx); err != nil {
		t.Fatalf("second tracker pass before retirement: %v", err)
	}
	if provider.statusReads == baseline {
		t.Fatalf("a pending, due approval must be polled on every pass (reads stayed %d)", baseline)
	}

	// Retire the order through the real inventory read.
	h.SetGigahostClient(existenceProvider(t, nil, nil, nil))
	_ = gigahostOrderStatusRead(t, h, "")
	if !storedOrder(t, h, retiredID).ProviderAbsent() {
		t.Fatalf("the fixture did not retire the order through its inventory read")
	}

	// From here the count must not move, even though the approval is still pending and due.
	clock = clock.Add(gigahostsetup.DefaultInterval + time.Second)
	before := provider.statusReads
	if err := tracker.RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass after retirement: %v", err)
	}
	if provider.statusReads != before {
		t.Errorf("the background tracker polled a retired order: %d -> %d provider status reads", before, provider.statusReads)
	}
	// The row is still pending and due, so the only thing that stopped the read is the
	// retirement rather than the schedule having run out.
	if intent, _, err := h.GetGigahostSetupIntent(ctx, retiredID); err == nil && intent != nil {
		if intent.State != models.SetupStatePending {
			t.Fatalf("the fixture's approval left the pending state: %+v", intent)
		}
	}
}

// TestRetirementRefusesNewSetupWork closes the admission direction: no new approval, resume
// or host confirmation may be recorded against an order the panel has recorded as over.
//
// These are the three actions that hand a job to a worker, so each is checked through its
// real handler-level entry point. The paired control is an identical live order, which must
// still be admitted - otherwise a refusal that simply rejected everything would pass.
func TestRetirementRefusesNewSetupWork(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	const retiredID = "ord_f1007_03_admission"
	const liveID = "ord_f1007_03_admission_live"
	seedExistenceOrder(t, h, retiredID, 7304, models.PurchaseOriginPanelPurchase)
	seedExistenceOrder(t, h, liveID, 7305, models.PurchaseOriginPanelPurchase)
	if err := h.db.SetGigahostOrderProviderAccount(ctx, retiredID, existenceAccount); err != nil {
		t.Fatalf("record the order's account: %v", err)
	}
	if err := h.db.SetGigahostOrderProviderAccount(ctx, liveID, existenceAccount); err != nil {
		t.Fatalf("record the live order's account: %v", err)
	}

	// Retire only the first: the inventory names the live order.
	h.SetGigahostClient(existenceProvider(t,
		[]gigahost.ServerInfo{{ID: 7305, OrderID: liveID, Status: gigahost.StatusReady}}, nil, nil))
	_ = gigahostOrderStatusRead(t, h, "")
	if !storedOrder(t, h, retiredID).ProviderAbsent() {
		t.Fatalf("the fixture did not retire the order through its inventory read")
	}
	if storedOrder(t, h, liveID).ProviderAbsent() {
		t.Fatalf("the fixture retired the live order")
	}

	// An approval cannot be recorded for a retired order.
	_, created, err := h.ApproveGigahostSetup(ctx, retiredID,
		GigahostSetupApproveRequest{Protocol: "awg", UseOrderCredential: true}, "fixture-admin")
	if err == nil {
		t.Errorf("approving setup for a retired order was accepted (created=%v)", created)
	} else {
		var validation *setupValidationError
		if !errors.As(err, &validation) {
			t.Errorf("the refusal must be a client validation failure, got %T: %v", err, err)
		}
	}
	// No job may have been created by the refused approval.
	if intent, _, err := h.GetGigahostSetupIntent(ctx, retiredID); err == nil && intent != nil {
		t.Errorf("a refused approval left a job behind: %+v", intent)
	}

	// The control: the same request against a live order is still admitted.
	liveIntent, liveCreated, err := h.ApproveGigahostSetup(ctx, liveID,
		GigahostSetupApproveRequest{Protocol: "awg", UseOrderCredential: true}, "fixture-admin")
	if err != nil || liveIntent == nil || !liveCreated {
		t.Fatalf("approval for a live order must still be admitted: created=%v err=%v", liveCreated, err)
	}

	// A resume cannot revive a paused job for a retired order.
	seedSavedSetupForOrder(t, h, retiredID, models.SetupStateAwaitingCredentials)
	if _, changed, err := h.ResumeGigahostSetup(ctx, retiredID); err != nil {
		t.Fatalf("resume against a retired order reported a server fault: %v", err)
	} else if changed {
		t.Errorf("resume of a retired order reported a transition")
	}
	if intent, _, _ := h.GetGigahostSetupIntent(ctx, retiredID); intent == nil ||
		intent.State != models.SetupStateAwaitingCredentials {
		t.Errorf("the retired order's approval state was rewritten: %+v", intent)
	}

	// A host confirmation cannot hand a retired job onward either. The fingerprint is a
	// well-formed value the panel never displayed, so the only thing refusing it is the
	// retirement gate.
	if _, changed, err := h.ConfirmGigahostSetupHost(ctx, retiredID,
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatalf("host confirmation against a retired order reported a server fault: %v", err)
	} else if changed {
		t.Errorf("host confirmation of a retired order reported a transition")
	}
}

// TestProviderFinalFailureReachesSavedSetupWork is the fourth consumer: an order that ended
// at the provider before any setup work is also retired, so a job saved against it must be
// suppressed even though no inventory omission will ever exist for it.
func TestProviderFinalFailureReachesSavedSetupWork(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	const orderID = "ord_f1007_03_final"
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: orderID, Status: "failed", PlanID: 1, RegionID: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	seedSavedSetupForOrder(t, h, orderID, models.SetupStateAwaitingCredentials)

	body := readSetupIntentsBody(t, h)
	if _, _, retired := savedSetupRowFor(t, body, orderID); !retired {
		t.Fatalf("a provider-final failure must be retired for saved setup too: %s", body)
	}
	view := runGigahostSetupIntentsRendererLoads(t, body)
	if hasSavedSetupAction(view.Buttons, "setup_intents_resume") {
		t.Errorf("a job for a provider-final failure still offers Resume: %v", view.Buttons)
	}
}

// TestLiveSavedSetupStillOffersItsActions is the standing positive control for the whole
// file: nothing above may have suppressed saved setup work for an order that is fine.
func TestLiveSavedSetupStillOffersItsActions(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_f1007_03_healthy"
	seedExistenceOrder(t, h, orderID, 7306, models.PurchaseOriginPanelPurchase)
	if err := h.db.SetGigahostOrderProviderAccount(context.Background(), orderID, existenceAccount); err != nil {
		t.Fatalf("record the order's account: %v", err)
	}
	seedSavedSetupForOrder(t, h, orderID, models.SetupStateAwaitingCredentials)

	// The provider lists the order, so no absence is recorded and nothing is retired.
	h.SetGigahostClient(existenceProvider(t,
		[]gigahost.ServerInfo{{ID: 7306, OrderID: orderID, Status: gigahost.StatusReady}}, nil, nil))
	_ = gigahostOrderStatusRead(t, h, "")

	body := readSetupIntentsBody(t, h)
	if _, _, retired := savedSetupRowFor(t, body, orderID); retired {
		t.Fatalf("a listed order must not be reported retired: %s", body)
	}
	view := runGigahostSetupIntentsRendererLoads(t, body)
	if !hasSavedSetupAction(view.Buttons, "setup_intents_resume") {
		t.Errorf("a live paused job lost its Resume action: %v", view.Buttons)
	}
}
