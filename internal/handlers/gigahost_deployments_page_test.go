package handlers

// The Servers page lists one grid.
//
// A deployment that exists but has had no setup requested must be visible there with its
// recorded state, a deployment that already has a server card must not be shown twice, and
// a deployment whose order has ended must be presented as the deletion it is rather than
// as one still waiting for setup. These tests render the shipped page and read the grid.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// insertServersPageOrder writes one ledger row the Servers page may have to show.
func insertServersPageOrder(t *testing.T, db *database.DB, order models.GigahostOrder) {
	t.Helper()
	now := time.Now().UTC()
	if order.CreatedAt.IsZero() {
		order.CreatedAt = now
	}
	if order.UpdatedAt.IsZero() {
		order.UpdatedAt = now
	}
	if err := db.InsertGigahostOrder(context.Background(), &order); err != nil {
		t.Fatalf("insert ledger row %q: %v", order.OrderID, err)
	}
}

// badgeWithState reports a card's state badge matching the badge class, the state it
// declares and its visible label.
//
// The declaration is asserted rather than tolerated: the badge's ink is keyed on the state
// it carries, so a badge without it keeps the shared danger colour and the label falls
// under the contrast floor. Asserting only the class and the word would let the attribute
// disappear while the markup still "looked" right.
func badgeWithState(card, class, stage, label string) bool {
	want := `<span class="badge ` + class + `" data-stage="` + stage + `">` + label + `</span>`
	return strings.Contains(card, want)
}

// deploymentCard returns one deployment card's markup. The grid holds server cards and
// deployment cards side by side, so the card is cut where the next one begins rather than
// at a section boundary that no longer exists.
func deploymentCard(t *testing.T, body, orderID string) string {
	t.Helper()
	start := strings.Index(body, `id="deployment-`+orderID+`"`)
	if start < 0 {
		t.Fatalf("deployment card %q is missing from the Servers page", orderID)
	}
	card := body[start:]
	end := len(card)
	for _, marker := range []string{`id="deployment-`, `id="server-`, `id="serverSearchEmpty"`} {
		if i := strings.Index(card[1:], marker); i >= 0 && i+1 < end {
			end = i + 1
		}
	}
	return card[:end]
}

// gridSection returns the page's grid and the markup around it, from the grid's opening
// element to the hosting card that follows it.
func gridSection(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `id="serverGrid"`)
	if start < 0 {
		t.Fatalf("the Servers page has no grid: %s", body)
	}
	section := body[start:]
	if end := strings.Index(section, `id="gigahostCard"`); end >= 0 {
		section = section[:end]
	}
	return section
}

// renderServersPageAs renders the Servers page for one role, through the real handler
// and template.
func renderServersPageAs(t *testing.T, h *Handlers, role models.UserRole) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	reqCtx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "servers-page-" + string(role),
		Role:   role,
	})
	w := httptest.NewRecorder()
	h.IndexPageHandler(w, req.WithContext(reqCtx))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from the servers page, got %d", w.Code)
	}
	return w.Body.String()
}

// renderServersPage renders the Servers page as an administrator.
func renderServersPage(t *testing.T, h *Handlers) string {
	t.Helper()
	return renderServersPageAs(t, h, models.RoleAdmin)
}

// TestServersPageListsDeploymentInTheSameGridAsTheServerCard is the reported defect and
// the consolidation in one assertion: the deployment without a setup request appears as a
// card in the one grid, beside an operator-added server, and no second grid is rendered.
func TestServersPageListsDeploymentInTheSameGridAsTheServerCard(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	createPresentationServer(t, h, models.Server{Name: "operator-added", Host: "198.51.100.11"})
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID:  "ord_1005_awaiting_setup",
		Status:   "deploying",
		PlanID:   1,
		RegionID: 1,
	})

	body := renderServersPage(t, h)
	grid := gridSection(t, body)

	if strings.Contains(body, `id="deploymentGrid"`) {
		t.Fatalf("the page renders a second grid for deployments:\n%s", body)
	}
	// No heading from the removed settings block survives on this page either.
	if strings.Contains(body, "Gigahost Cloud Hosting") {
		t.Fatalf("the page still carries the removed block's heading")
	}
	if !strings.Contains(grid, `id="server-1"`) {
		t.Fatalf("the operator-added server is not in the one grid")
	}
	if !strings.Contains(grid, `id="deployment-ord_1005_awaiting_setup"`) {
		t.Fatalf("the deployment is not a card in the one grid")
	}
	// The card names the deployment the same way setup will name the server, so the
	// operator can follow it from here to the registered server.
	card := deploymentCard(t, body, "ord_1005_awaiting_setup")
	if !strings.Contains(card, `data-server-name="Gigahost-ord_1005_awaiting_setup"`) {
		t.Fatalf("the deployment card does not carry its name")
	}
	// The address attribute drives the existing server search; it stays empty until an
	// address exists, while the visible line says so in words.
	if !strings.Contains(card, `data-server-host=""`) {
		t.Fatalf("the deployment card is not wired into the server search attributes")
	}
	// The state is the recorded one, labelled in the deployment state vocabulary, and it
	// never reads as a usable server.
	if !badgeWithState(card, "badge-info", "deploying", "Deploying") {
		t.Fatalf("the deployment card does not carry its state label: %s", card)
	}
	if strings.Contains(card, "badge-success") {
		t.Fatalf("an unset-up deployment must not carry a success badge")
	}
	// The recorded provider state stays visible as the panel's own record.
	if !strings.Contains(card, "Recorded state: deploying") {
		t.Fatalf("the deployment card does not show its recorded state: %s", card)
	}
	// The control that finishes it is offered here, where the card is.
	if !strings.Contains(card, "triggerGigahostSetup('ord_1005_awaiting_setup')") {
		t.Fatalf("the deployment card offers no setup control: %s", card)
	}
}

// TestServersPageRendersNoDeploymentCardsForAnEmptyLedger is the negative control: the
// cards are the ledger speaking, so an empty ledger renders none of them.
func TestServersPageRendersNoDeploymentCardsForAnEmptyLedger(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	body := renderServersPage(t, h)

	if strings.Contains(body, `id="deployment-`) || strings.Contains(body, `id="deploymentGrid"`) {
		t.Fatalf("an empty ledger must not render deployment cards")
	}
}

// TestServersPageDoesNotDuplicateAnAlreadyRegisteredDeployment pins the other half: a
// deployment that setup already registered has a server card, and showing the ledger row
// beside it would present one deployment as two.
func TestServersPageDoesNotDuplicateAnAlreadyRegisteredDeployment(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	if _, err := db.CreateServer(ctx, &models.Server{
		Name:      "Gigahost-ord_1005_registered",
		Host:      "198.51.100.44",
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 4242},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create the registered server: %v", err)
	}
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID:  "ord_1005_registered",
		Status:   "ready",
		ServerID: 4242,
		PlanID:   1,
		RegionID: 1,
	})

	body := renderServersPage(t, h)

	if strings.Contains(body, `id="deployment-ord_1005_registered"`) {
		t.Fatalf("a registered deployment must not also appear as a pending deployment")
	}
	if !strings.Contains(body, `id="server-1"`) {
		t.Fatalf("the registered server card is missing from the Servers page")
	}
}

// TestServersPageKeepsTwoDeploymentsThatShareAnAddressButNotAProviderID is the regression
// for the owner's finding: an address is not identity. Two deployments with different
// provider server ids are two deployments even when they report the same address, so the
// one without a panel server must still be listed.
func TestServersPageKeepsTwoDeploymentsThatShareAnAddressButNotAProviderID(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	const sharedIP = "198.51.100.70"

	if _, err := db.CreateServer(ctx, &models.Server{
		Name:      "Gigahost-ord_1005_first",
		Host:      sharedIP,
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 900},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create the registered server: %v", err)
	}
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: "ord_1005_first", Status: "ready", ServerID: 900, AssignedIP: sharedIP, PlanID: 1, RegionID: 1,
	})
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: "ord_1005_second", Status: "ready", ServerID: 901, AssignedIP: sharedIP, PlanID: 1, RegionID: 1,
	})

	body := renderServersPage(t, h)

	if strings.Contains(body, `id="deployment-ord_1005_first"`) {
		t.Fatalf("the deployment whose provider id owns the server was listed again")
	}
	if !strings.Contains(body, `id="deployment-ord_1005_second"`) {
		t.Fatalf("a different provider server id at the same address disappeared from Servers")
	}
}

// TestServersPageTellsSupportWhoFinishesSetup pins the owner's finding: the hosting
// controls are administrator-only, so a support user must be told who has to act instead
// of being offered a control they cannot use.
func TestServersPageTellsSupportWhoFinishesSetup(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: "ord_1005_support_view", Status: "active", AssignedIP: "198.51.100.71", PlanID: 1, RegionID: 1,
	})

	supportBody := renderServersPageAs(t, h, models.RoleSupport)
	supportCard := deploymentCard(t, supportBody, "ord_1005_support_view")
	if strings.Contains(supportCard, "triggerGigahostSetup") {
		t.Fatalf("a support user was offered the setup control: %s", supportCard)
	}
	if strings.Contains(strings.ToLower(supportCard), "<button") {
		t.Fatalf("the support card must carry no control, got one: %s", supportCard)
	}
	if !strings.Contains(supportCard, "An administrator must finish the setup.") {
		t.Fatalf("the card must name the role that finishes the setup: %s", supportCard)
	}
	// The hosting controls are not rendered for a role that cannot use them, so the
	// page does not carry a credential form a support user cannot submit.
	if strings.Contains(supportBody, `id="gigahostCard"`) {
		t.Fatalf("a support user is shown the administrator's hosting controls")
	}

	// Control: the administrator keeps the control and the copy they had, so the
	// difference is the role and nothing else.
	adminCard := deploymentCard(t, renderServersPage(t, h), "ord_1005_support_view")
	if !strings.Contains(adminCard, "triggerGigahostSetup('ord_1005_support_view')") {
		t.Fatalf("an administrator must be offered the setup control: %s", adminCard)
	}
	if strings.Contains(adminCard, "An administrator must finish the setup.") {
		t.Fatalf("the administrator is offered the control and needs no handoff sentence")
	}
}

// TestServersPagePresentsAFinishedOrderAsDeleted is the owner's presentation rule: a
// cancelled order and an order the provider no longer lists are DELETED, and a DELETED
// card offers nothing at all.
func TestServersPagePresentsAFinishedOrderAsDeleted(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: "ord_1005_cancelled", Status: statusCancelled, AssignedIP: "198.51.100.72", PlanID: 1, RegionID: 1,
	})
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: "ord_1005_gone", Status: "ready", AssignedIP: "198.51.100.73", PlanID: 1, RegionID: 1,
	})
	// The panel's durable existence record: a successful provider listing omitted the
	// order. It is what makes a ready row presentable as a deletion.
	if err := db.SetGigahostOrderAbsence(ctx, "ord_1005_gone", time.Now().UTC(), "1111"); err != nil {
		t.Fatalf("record the absence: %v", err)
	}

	body := renderServersPage(t, h)

	for _, orderID := range []string{"ord_1005_cancelled", "ord_1005_gone"} {
		card := deploymentCard(t, body, orderID)
		if !badgeWithState(card, "badge-danger", "deleted", "Deleted") {
			t.Fatalf("%s must be presented as the deletion it is: %s", orderID, card)
		}
		if strings.Contains(card, "triggerGigahostSetup") || strings.Contains(card, "server-actions") {
			t.Fatalf("%s is finished and must offer no control: %s", orderID, card)
		}
	}
}

// TestServersPageNeverPresentsAnUnsetUpDeploymentAsUsable pins the design review's
// finding: a deployment whose provider status is "active" still has no panel server, so
// the card must not carry a green, active-sounding badge. The recorded state stays visible
// as a scoped fact, which is what keeps the deployment state visible.
func TestServersPageNeverPresentsAnUnsetUpDeploymentAsUsable(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID:    "ord_1005_active_no_setup",
		Status:     "active",
		AssignedIP: "198.51.100.62",
		PlanID:     1,
		RegionID:   1,
	})

	body := renderServersPage(t, h)

	card := deploymentCard(t, body, "ord_1005_active_no_setup")
	if !badgeWithState(card, "badge-secondary", "ready", "Ready at provider") {
		t.Fatalf("the card's state label must say the deployment is ready at the provider: %s", card)
	}
	if strings.Contains(card, "badge-success") {
		t.Fatalf("a deployment with no setup request must not carry a success badge")
	}
	// The provider's own word survives as the panel's record, never as the label.
	if !strings.Contains(card, "Recorded state: active") {
		t.Fatalf("the recorded provider state must still be visible, scoped as a record")
	}
	if strings.Contains(card, ">active</span>") || strings.Contains(card, ">ACTIVE</span>") {
		t.Fatalf("the recorded word must not be rendered as the card's own badge label")
	}
}

// TestGigahostDeploymentsForServers covers the selection and presentation rules directly,
// including the cases a database fixture makes awkward: a purchase the provider never
// acknowledged, a deployment that is over, and a registration recorded only by the address.
func TestGigahostDeploymentsForServers(t *testing.T) {
	servers := []models.Server{
		{ID: 1, Name: "by-provider-id", Host: "198.51.100.1",
			Protocols: map[string]any{"provider": "gigahost", "provider_server_id": float64(900)}},
		{ID: 2, Name: "by-address", Host: "198.51.100.2", Protocols: map[string]any{}},
	}
	absentAt := time.Now().UTC().Format(time.RFC3339)
	orders := []models.GigahostOrder{
		{OrderID: "ord_unregistered", Status: "deploying"},
		{OrderID: "ord_registered", Status: "ready", ServerID: 900},
		{OrderID: "ord_by_address", Status: "ready", AssignedIP: "198.51.100.2"},
		{OrderID: "ord_cancelled", Status: "cancelled"},
		{OrderID: "ord_failed", Status: "failed"},
		{OrderID: "ord_recorded_absent", Status: "ready", ProviderAbsentAt: absentAt},
		{OrderID: "ord_blank_state", Status: "   "},
		{OrderID: "intent_1700000000000", Status: "pending_order"},
		{OrderID: "", Status: "deploying"},
	}

	rows := gigahostDeploymentsForServers(orders, servers)

	got := make([]string, 0, len(rows))
	stages := make(map[string]string, len(rows))
	for _, row := range rows {
		got = append(got, row.OrderID)
		stages[row.OrderID] = row.Stage
	}
	want := []string{"ord_unregistered", "ord_cancelled", "ord_failed", "ord_recorded_absent", "ord_blank_state"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("selection mismatch: got %v, want %v", got, want)
	}
	if rows[0].Name != "Gigahost-ord_unregistered" {
		t.Fatalf("unexpected card name %q", rows[0].Name)
	}
	// A finished order is listed so it can be presented as finished, not dropped: being
	// absent from the page is what made it invisible.
	if stages["ord_cancelled"] != gigahostDeploymentStageDeleted {
		t.Fatalf("a cancelled deployment must be presented as deleted, got %q", stages["ord_cancelled"])
	}
	if stages["ord_recorded_absent"] != gigahostDeploymentStageDeleted {
		t.Fatalf("a recorded absence must be presented as deleted, got %q", stages["ord_recorded_absent"])
	}
	if stages["ord_failed"] != gigahostDeploymentStageFailed {
		t.Fatalf("a failed deployment keeps its own state, got %q", stages["ord_failed"])
	}
	// An empty recorded status is not a state: it is shown as unknown, never as blank.
	if rows[4].Status != "unknown" || stages["ord_blank_state"] != gigahostDeploymentStageUnknown {
		t.Fatalf("a blank recorded status must read as unknown, got %q / %q", rows[4].Status, stages["ord_blank_state"])
	}
	// Every presented state names a label in the deployment state vocabulary, and the
	// ones a card can render are the ones the interface has words for.
	for _, row := range rows {
		if row.StageKey != "gigahost_status_stage_"+row.Stage {
			t.Fatalf("row %q has no stage label key: %q", row.OrderID, row.StageKey)
		}
	}
	// The action each state allows: a finished order offers none.
	actions := make(map[string]string, len(rows))
	for _, row := range rows {
		actions[row.OrderID] = row.Action
	}
	if actions["ord_cancelled"] != "" || actions["ord_recorded_absent"] != "" {
		t.Fatalf("a finished deployment must offer no action: %v", actions)
	}
	if actions["ord_failed"] != gigahostDeploymentActionRetry {
		t.Fatalf("a failed deployment offers the retry its state allows, got %q", actions["ord_failed"])
	}
	if actions["ord_unregistered"] != gigahostDeploymentActionSetup {
		t.Fatalf("an awaiting deployment offers setup, got %q", actions["ord_unregistered"])
	}
}
