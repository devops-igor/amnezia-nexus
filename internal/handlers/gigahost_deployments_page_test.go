package handlers

// Acceptance for issue 970's Servers-list half: a deployment that exists but has had no
// setup requested must be visible on the Servers page with its recorded state, and a
// deployment that already has a server card must not be shown twice.

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

// deploymentCard returns one deployment card's markup. Assertions about the card are
// made on this slice: the page chrome carries a badge-success of its own (the sidebar's
// ADMIN badge), so a whole-body check could pass or fail for the wrong reason.
func deploymentCard(t *testing.T, body, orderID string) string {
	t.Helper()
	start := strings.Index(body, `id="deployment-`+orderID+`"`)
	if start < 0 {
		t.Fatalf("deployment card %q is missing from the Servers page", orderID)
	}
	card := body[start:]
	if end := strings.Index(card, "</section>"); end >= 0 {
		card = card[:end]
	}
	return card
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

// TestServersPageListsDeploymentWithoutSetupRequest is the reported defect itself: the
// deployment has no servers row, so before this change nothing on the page mentioned it.
func TestServersPageListsDeploymentWithoutSetupRequest(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID:  "ord_970_awaiting_setup",
		Status:   "deploying",
		PlanID:   1,
		RegionID: 1,
	})

	body := renderServersPage(t, h)

	if !strings.Contains(body, `id="deploymentGrid"`) {
		t.Fatalf("the Servers page did not render the deployments section:\n%s", body)
	}
	if !strings.Contains(body, `id="deployment-ord_970_awaiting_setup"`) {
		t.Fatalf("the deployment without a setup request is missing from the Servers page")
	}
	// The card names the deployment the same way setup will name the server, so the
	// operator can follow it from here to the registered server.
	if !strings.Contains(body, `data-server-name="Gigahost-ord_970_awaiting_setup"`) {
		t.Fatalf("the deployment card does not carry its name")
	}
	// The address attribute drives the existing server search; it stays empty until an
	// address exists, while the visible line says so in words.
	if !strings.Contains(body, `data-server-host=""`) {
		t.Fatalf("the deployment card is not wired into the server search attributes")
	}
	// The state label states the deployment's situation, not the provider's: no setup has
	// run, so it cannot carry traffic, and the badge must not read as a usable server.
	card := deploymentCard(t, body, "ord_970_awaiting_setup")
	if !strings.Contains(card, `>Not set up</span>`) {
		t.Fatalf("the deployment card does not carry its not-set-up state label")
	}
	if !strings.Contains(card, "badge-secondary") || strings.Contains(card, "badge-success") {
		t.Fatalf("an unset-up deployment must not carry a badge that reads as usable")
	}
	// The recorded provider state stays visible as the panel's own record.
	if !strings.Contains(card, "Recorded state: deploying") {
		t.Fatalf("the deployment card does not show its recorded state")
	}
}

// TestServersPageOmitsDeploymentsSectionWhenThereAreNone is the negative control: the
// section is the ledger speaking, so an empty ledger renders no section at all.
func TestServersPageOmitsDeploymentsSectionWhenThereAreNone(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	body := renderServersPage(t, h)

	if strings.Contains(body, `id="deploymentGrid"`) {
		t.Fatalf("an empty ledger must not render the deployments section")
	}
}

// TestServersPageDoesNotDuplicateAnAlreadyRegisteredDeployment pins the other half: a
// deployment that setup already registered has a server card, and showing the ledger row
// beside it would present one deployment as two.
func TestServersPageDoesNotDuplicateAnAlreadyRegisteredDeployment(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	if _, err := db.CreateServer(ctx, &models.Server{
		Name:      "Gigahost-ord_970_registered",
		Host:      "198.51.100.44",
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 4242},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create the registered server: %v", err)
	}
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID:  "ord_970_registered",
		Status:   "ready",
		ServerID: 4242,
		PlanID:   1,
		RegionID: 1,
	})

	body := renderServersPage(t, h)

	if strings.Contains(body, `id="deployment-ord_970_registered"`) {
		t.Fatalf("a registered deployment must not also appear as a pending deployment")
	}
	if !strings.Contains(body, `id="server-1"`) {
		t.Fatalf("the registered server card is missing from the Servers page")
	}
}

// TestServersPageKeepsTwoDeploymentsThatShareAnAddressButNotAProviderID is the
// regression for the owner's finding: an address is not identity. Two deployments with
// different provider server ids are two deployments even when they report the same
// address, so the one without a panel server must still be listed.
func TestServersPageKeepsTwoDeploymentsThatShareAnAddressButNotAProviderID(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	const sharedIP = "198.51.100.70"

	if _, err := db.CreateServer(ctx, &models.Server{
		Name:      "Gigahost-ord_970_first",
		Host:      sharedIP,
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 900},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create the registered server: %v", err)
	}
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: "ord_970_first", Status: "ready", ServerID: 900, AssignedIP: sharedIP, PlanID: 1, RegionID: 1,
	})
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: "ord_970_second", Status: "ready", ServerID: 901, AssignedIP: sharedIP, PlanID: 1, RegionID: 1,
	})

	body := renderServersPage(t, h)

	if strings.Contains(body, `id="deployment-ord_970_first"`) {
		t.Fatalf("the deployment whose provider id owns the server was listed again")
	}
	if !strings.Contains(body, `id="deployment-ord_970_second"`) {
		t.Fatalf("a different provider server id at the same address disappeared from Servers")
	}
}

// TestServersPageTellsSupportWhoFinishesSetup pins the owner's finding: the Settings
// page that finishes a deployment is administrator-only, so a support user must be told
// who has to act instead of being offered a control whose page refuses them.
func TestServersPageTellsSupportWhoFinishesSetup(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: "ord_970_support_view", Status: "active", AssignedIP: "198.51.100.71", PlanID: 1, RegionID: 1,
	})

	supportCard := deploymentCard(t, renderServersPageAs(t, h, models.RoleSupport), "ord_970_support_view")
	if strings.Contains(supportCard, `href="/settings#gigahostCard"`) {
		t.Fatalf("a support user was offered the Settings action whose page refuses them")
	}
	if strings.Contains(strings.ToLower(supportCard), "<a ") {
		t.Fatalf("the support card must carry no link at all, got one")
	}
	if !strings.Contains(supportCard, "An administrator must finish the setup.") {
		t.Fatalf("the card must name the role that finishes the setup")
	}

	// Control: the administrator keeps the copy and the action they had, so the
	// difference is the role and nothing else.
	adminCard := deploymentCard(t, renderServersPage(t, h), "ord_970_support_view")
	if !strings.Contains(adminCard, `href="/settings#gigahostCard"`) {
		t.Fatalf("an administrator must still be offered the Settings action")
	}
	if !strings.Contains(adminCard, "Request setup in Settings") {
		t.Fatalf("the administrator's copy must be unchanged")
	}
	if strings.Contains(adminCard, "An administrator must finish the setup.") {
		t.Fatalf("the administrator is offered the action and needs no handoff sentence")
	}
}

// TestSupportCardDoesNotSendASupportUserToSettings pins the copy correction: the removed
// link was only half the dead end, because the sentence beside it still directed a support
// user to a page that refuses them. The card now says who acts, never where to go.
func TestSupportCardDoesNotSendASupportUserToSettings(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: "ord_970_support_copy", Status: "active", PlanID: 1, RegionID: 1,
	})

	supportCard := deploymentCard(t, renderServersPageAs(t, h, models.RoleSupport), "ord_970_support_copy")

	for _, deadEnd := range []string{"Request setup in Settings", "Settings > Gigahost Cloud Hosting"} {
		if strings.Contains(supportCard, deadEnd) {
			t.Fatalf("the support card still sends the reader to a page they cannot open (%q)", deadEnd)
		}
	}
	// The state label and the recorded state keep the deployment identifiable without
	// the action, so the card is not merely an apology.
	if !strings.Contains(supportCard, ">Not set up</span>") {
		t.Fatalf("the support card lost its state label")
	}
	if !strings.Contains(supportCard, "Recorded state: active") {
		t.Fatalf("the support card lost the recorded state")
	}
	if !strings.Contains(supportCard, "Gigahost-ord_970_support_copy") {
		t.Fatalf("the support card lost the deployment's identity")
	}
}

// TestGigahostDeploymentsForServers covers the selection rules directly, including the
// cases a database fixture makes awkward: a purchase the provider never acknowledged, a
// deployment that is over, and a registration recorded only by the address.
func TestGigahostDeploymentsForServers(t *testing.T) {
	servers := []models.Server{
		{ID: 1, Name: "by-provider-id", Host: "198.51.100.1",
			Protocols: map[string]any{"provider": "gigahost", "provider_server_id": float64(900)}},
		{ID: 2, Name: "by-address", Host: "198.51.100.2", Protocols: map[string]any{}},
	}
	orders := []models.GigahostOrder{
		{OrderID: "ord_unregistered", Status: "deploying"},
		{OrderID: "ord_registered", Status: "ready", ServerID: 900},
		{OrderID: "ord_by_address", Status: "ready", AssignedIP: "198.51.100.2"},
		{OrderID: "ord_cancelled", Status: "cancelled"},
		{OrderID: "ord_failed", Status: "failed"},
		{OrderID: "ord_blank_state", Status: "   "},
		{OrderID: "intent_1700000000000", Status: "pending_order"},
		{OrderID: "", Status: "deploying"},
	}

	rows := gigahostDeploymentsForServers(orders, servers)

	got := make([]string, 0, len(rows))
	for _, row := range rows {
		got = append(got, row.OrderID)
	}
	want := []string{"ord_unregistered", "ord_failed", "ord_blank_state"}
	if len(got) != len(want) {
		t.Fatalf("selection mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("selection mismatch: got %v, want %v", got, want)
		}
	}
	if rows[0].Name != "Gigahost-ord_unregistered" {
		t.Fatalf("unexpected card name %q", rows[0].Name)
	}
	if rows[1].Status != "failed" {
		t.Fatalf("a failed deployment keeps its recorded state, got %q", rows[1].Status)
	}
	// An empty recorded status is not a state: it is shown as unknown, never as blank.
	if rows[2].Status != "unknown" {
		t.Fatalf("a blank recorded status must read as unknown, got %q", rows[2].Status)
	}
}

// TestServersPageNeverPresentsAnUnsetUpDeploymentAsUsable pins the design review's
// finding: a deployment whose provider status is "active" still has no panel server, so
// the card must not carry a green, active-sounding badge. The recorded state stays
// visible as a scoped fact, which is what keeps issue 970's "state visible" acceptance.
func TestServersPageNeverPresentsAnUnsetUpDeploymentAsUsable(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID:    "ord_970_active_no_setup",
		Status:     "active",
		AssignedIP: "198.51.100.62",
		PlanID:     1,
		RegionID:   1,
	})

	body := renderServersPage(t, h)

	card := deploymentCard(t, body, "ord_970_active_no_setup")
	if !strings.Contains(card, `>Not set up</span>`) {
		t.Fatalf("the card's state label must say the deployment is not set up")
	}
	if strings.Contains(card, "badge-success") {
		t.Fatalf("a deployment with no setup request must not carry a success badge")
	}
	// The provider's own word survives as the panel's record, never as the label.
	if !strings.Contains(card, "Recorded state: active") {
		t.Fatalf("the recorded provider state must still be visible, scoped as a record")
	}
	// And the provider's word never stands alone as a badge label.
	if strings.Contains(card, ">active</span>") || strings.Contains(card, ">ACTIVE</span>") {
		t.Fatalf("the recorded word must not be rendered as the card's own badge label")
	}
}
