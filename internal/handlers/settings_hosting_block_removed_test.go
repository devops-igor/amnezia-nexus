package handlers

// The Settings hosting block is gone, and the controls it hosted are on the Servers page.
//
// Two facts have to hold together: the Settings page renders no hosting card and loads no
// controller that binds one, and the same controls are reachable on the page whose cards
// they act on. The locale side is asserted in the web package, where the bundles live.

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestSettingsPageRendersNoHostingBlock is the removal itself, read from the rendered
// page for both roles that can reach Settings.
func TestSettingsPageRendersNoHostingBlock(t *testing.T) {
	for _, role := range []models.UserRole{models.RoleAdmin, models.RoleSupport} {
		body := renderSettingsPage(t, role)
		for _, absent := range []string{
			`id="gigahostCard"`,
			`data-settings-card="gigahost"`,
			`id="gigahost_api_key"`,
			`id="deployPlanSelect"`,
			`id="recentOrdersContainer"`,
			`id="setupIntentsContainer"`,
			`id="gigahostAssociationSection"`,
			`/static/js/gigahost`,
			"gigahost_settings_title",
		} {
			if strings.Contains(body, absent) {
				t.Errorf("the settings page still carries %s for role %s", absent, role)
			}
		}
	}
}

// TestServersPageCarriesTheRelocatedHostingControls is the other half: the administrator's
// page still offers the provider credential, the order form, the deployment list, the
// saved setup approvals and the inventory association.
func TestServersPageCarriesTheRelocatedHostingControls(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const storedKey = "flux_live_secret_probe_0123456789"
	if err := h.db.SetSetting(context.Background(), "gigahost", map[string]any{"api_key": storedKey}); err != nil {
		t.Fatalf("seed the provider credential: %v", err)
	}

	body := renderServersPage(t, h)

	for _, required := range []string{
		`id="gigahostCard"`,
		`id="gigahost_api_key"`,
		`id="deployPlanSelect"`,
		`id="recentOrdersContainer"`,
		`id="setupIntentsContainer"`,
		`id="gigahostAssociationSection"`,
		`data-settings-card="gigahost"`,
	} {
		if !strings.Contains(body, required) {
			t.Errorf("the servers page does not carry the relocated control %s", required)
		}
	}
	// The card keeps the commit control its section saves through, so the credential is
	// still written by the shipped save path rather than by a second one.
	if !strings.Contains(body, `data-commit`) {
		t.Error("the relocated credential card has no commit control")
	}
	// The saved credential never reaches the markup: the same masking the settings API
	// applies is applied here.
	if strings.Contains(body, storedKey) || strings.Contains(body, "secret_probe") {
		t.Error("the servers page publishes stored credential material")
	}
	if !strings.Contains(body, `value="********"`) {
		t.Error("the relocated credential field does not show the masked placeholder")
	}
}
