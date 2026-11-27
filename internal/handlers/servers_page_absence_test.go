package handlers

// Presentation of a provider-confirmed absence, on the two surfaces an operator reads.
//
// The absence state itself is recorded, written and cleared elsewhere; these tests are
// only about what the panel shows. They are kept separate from the deployment-selection
// tests because the selection rules did not change - what changed is which rows reach the
// Servers grid, and that the deployments section keeps treating a hidden server's
// deployment as registered rather than as a deployment waiting for setup.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// createPresentationServer registers one server row directly, which is what both the
// provisioning path and the operator's Add Server form end up writing.
func createPresentationServer(t *testing.T, h *Handlers, server models.Server) int64 {
	t.Helper()
	if server.SSHPort == 0 {
		server.SSHPort = 22
	}
	if server.SSHUser == "" {
		server.SSHUser = "root"
	}
	if server.CreatedAt.IsZero() {
		server.CreatedAt = time.Now().UTC()
	}
	id, err := h.db.CreateServer(context.Background(), &server)
	if err != nil {
		t.Fatalf("create server %q: %v", server.Name, err)
	}
	return id
}

// markServerProviderAbsent records the observation the inventory read would have written.
func markServerProviderAbsent(t *testing.T, h *Handlers, serverID int64) {
	t.Helper()
	if err := h.db.SetServerProviderAbsence(context.Background(), serverID, time.Now().UTC(), "acct_presentation"); err != nil {
		t.Fatalf("mark server %d provider-absent: %v", serverID, err)
	}
}

// clearServerProviderAbsence records the reappearance the inventory read would have
// written: a zero observation time clears the mark.
func clearServerProviderAbsence(t *testing.T, h *Handlers, serverID int64) {
	t.Helper()
	if err := h.db.SetServerProviderAbsence(context.Background(), serverID, time.Time{}, ""); err != nil {
		t.Fatalf("clear provider absence for server %d: %v", serverID, err)
	}
}

// serverCardID is the element id the Servers grid gives one server.
func serverCardID(serverID int64) string {
	return fmt.Sprintf(`id="server-%d"`, serverID)
}

// TestServersSectionOmitsProviderDeletedServersAndKeepsTheRest is the Servers-section
// half: the row the provider's inventory has confirmed gone is not listed, and every
// other row - portal-provisioned and operator-added alike - is listed exactly as before,
// in the section's one grid.
func TestServersSectionOmitsProviderDeletedServersAndKeepsTheRest(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	absentID := createPresentationServer(t, h, models.Server{
		Name:      "Gigahost-ord_986_vanished",
		Host:      "198.51.100.141",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 5100},
	})
	portalKeepID := createPresentationServer(t, h, models.Server{
		Name:      "Gigahost-ord_986_present",
		Host:      "198.51.100.142",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 5101},
	})
	operatorID := createPresentationServer(t, h, models.Server{
		Name:      "Operator-added box",
		Host:      "198.51.100.143",
		Protocols: map[string]any{"wireguard": map[string]any{"installed": true}},
	})

	// The vanished deployment's ledger row: the panel purchased it and registered a
	// server from it, so the deployments section must keep treating it as registered.
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID:    "ord_986_vanished",
		Status:     "ready",
		ServerID:   5100,
		AssignedIP: "198.51.100.141",
		PlanID:     1,
		RegionID:   1,
	})

	// Control first: before the observation, all three cards are listed.
	before := renderServersPage(t, h)
	for _, id := range []int64{absentID, portalKeepID, operatorID} {
		if !strings.Contains(before, serverCardID(id)) {
			t.Fatalf("server %d is missing from the Servers section before any absence is recorded", id)
		}
	}

	markServerProviderAbsent(t, h, absentID)

	body := renderServersPage(t, h)

	if strings.Contains(body, serverCardID(absentID)) {
		t.Fatalf("a server the provider's inventory no longer lists is still listed in the Servers section")
	}
	// The row is hidden, not deleted: the rest of the panel keeps it.
	if server, err := db.GetServer(context.Background(), absentID); err != nil || server == nil {
		t.Fatalf("the absent server's row must be preserved, got %v %v", server, err)
	}
	// Every server that exists is listed, whether the panel provisioned it or an
	// operator added it.
	for _, id := range []int64{portalKeepID, operatorID} {
		if !strings.Contains(body, serverCardID(id)) {
			t.Fatalf("server %d disappeared from the Servers section although nothing is known against it", id)
		}
	}
	// The hidden server's deployment must not come back as a deployment waiting for
	// setup: that card would show the same vanished deployment under another name.
	if strings.Contains(body, `id="deployment-ord_986_vanished"`) {
		t.Fatalf("the deployment of a hidden server was re-listed as a deployment without a server")
	}
	// One grid and one deployment section at most: the section separates nothing by
	// provider, so a second grid would be the grouping this change must not introduce.
	if got := strings.Count(body, `class="server-grid"`); got != 1 {
		t.Fatalf("expected exactly one server grid and no deployment section, got %d server grids", got)
	}
	if strings.Contains(body, `id="deploymentGrid"`) {
		t.Fatalf("an empty deployments selection must render no deployments section")
	}
}

// TestServersSectionListsTheServerAgainWhenTheProviderListsItAgain is criterion 6 on the
// Servers surface: the recorded state is corrected, not left deleted.
func TestServersSectionListsTheServerAgainWhenTheProviderListsItAgain(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	serverID := createPresentationServer(t, h, models.Server{
		Name:      "Gigahost-ord_986_returns",
		Host:      "198.51.100.144",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 5102},
	})

	markServerProviderAbsent(t, h, serverID)
	if body := renderServersPage(t, h); strings.Contains(body, serverCardID(serverID)) {
		t.Fatalf("a server recorded absent is listed before the provider lists it again")
	}

	clearServerProviderAbsence(t, h, serverID)

	if body := renderServersPage(t, h); !strings.Contains(body, serverCardID(serverID)) {
		t.Fatalf("a server the provider lists again was not returned to the Servers section")
	}
}

// TestDeployStatusReportsProviderAbsenceForItsRegisteredServer is the source half of the
// Recent Deployments change: the per-order deploy read, which is the only place the view
// learns which panel server an order registered, carries that server's recorded absence.
func TestDeployStatusReportsProviderAbsenceForItsRegisteredServer(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)

	serverID := createPresentationServer(t, h, models.Server{
		Name:      "Gigahost-ord_986_status",
		Host:      "198.51.100.145",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 5103},
	})
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: "ord_986_status", Status: DeployStatusReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed the order: %v", err)
	}
	// The onboarding journal write that links the order to the panel server.
	if err := h.updateDeployOrderStatus(ctx, "ord_986_status", DeployStatusReady, DeployStatusReady,
		"", 5103, serverID, "198.51.100.145"); err != nil {
		t.Fatalf("write the onboarding journal: %v", err)
	}
	// An order that registered no panel server is the negative control: it can never be
	// reported absent, whatever the servers table holds.
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: "ord_986_unregistered", Status: DeployStatusReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed the unregistered order: %v", err)
	}

	before, err := h.GetGigahostDeployStatus(ctx, "ord_986_status")
	if err != nil {
		t.Fatalf("read the deploy status: %v", err)
	}
	if before.ProviderAbsent {
		t.Fatalf("the order's server is listed by the provider, so the status must not report it absent")
	}
	if before.ServerID != serverID {
		t.Fatalf("expected the deploy read to name panel server %d, got %d", serverID, before.ServerID)
	}

	markServerProviderAbsent(t, h, serverID)

	marked, err := h.GetGigahostDeployStatus(ctx, "ord_986_status")
	if err != nil {
		t.Fatalf("read the deploy status after the observation: %v", err)
	}
	if !marked.ProviderAbsent {
		t.Fatalf("the deploy read must report the panel server the provider no longer lists as absent")
	}
	// The order's own recorded fields are untouched by that fact.
	if marked.Status != DeployStatusReady || marked.ServerID != serverID {
		t.Fatalf("the absence report changed the deploy read: %+v", marked)
	}

	unregistered, err := h.GetGigahostDeployStatus(ctx, "ord_986_unregistered")
	if err != nil {
		t.Fatalf("read the unregistered order's status: %v", err)
	}
	if unregistered.ProviderAbsent {
		t.Fatalf("an order with no registered panel server must never report provider absence")
	}

	// Criterion 6 on this surface: a server the provider lists again reports normally.
	clearServerProviderAbsence(t, h, serverID)
	cleared, err := h.GetGigahostDeployStatus(ctx, "ord_986_status")
	if err != nil {
		t.Fatalf("read the deploy status after the correction: %v", err)
	}
	if cleared.ProviderAbsent {
		t.Fatalf("a server the provider lists again must stop being reported absent")
	}
}
