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

// renderServersPage renders the admin dashboard through the real handler and template.
func renderServersPage(t *testing.T, h *Handlers) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	reqCtx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-servers-page",
		Role:   models.RoleAdmin,
	})
	w := httptest.NewRecorder()
	h.IndexPageHandler(w, req.WithContext(reqCtx))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from the servers page, got %d", w.Code)
	}
	return w.Body.String()
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
