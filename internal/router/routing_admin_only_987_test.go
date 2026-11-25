package router

// Route-level contract for the Routing page (#987): GET /routing is Admin-only,
// refused to Support and to a plain user, and redirects an anonymous visitor to
// login exactly as /settings does. It is deliberately in the admin group and not
// in the admin-or-support VPN group, so a role that could reach the VPN page cannot
// reach the policy surface behind it.
//
// Every case runs through the real router, the real session, CSRF and role
// middlewares and a real database. The page's own content is asserted only where it
// distinguishes the routing page from a partially rendered shell: the full markup
// contract is in internal/handlers/routing_page_987_test.go.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

var routingPageEntry = settingsEntryPoint{"routing page", http.MethodGet, "/routing", ""}

// TestRoutingPageAccessMatrix pins the table the design contract settles: admin
// opens it, Support and user are refused with the existing JSON denial, and an
// anonymous visitor is sent to login rather than told the page exists.
func TestRoutingPageAccessMatrix(t *testing.T) {
	r, _ := newSettingsRoleRouter(t)

	t.Run("admin", func(t *testing.T) {
		w := serveAs(t, r, models.RoleAdmin, routingPageEntry)
		if w.Code != http.StatusOK {
			t.Fatalf("Admin GET /routing = %d, want 200; body=%s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		// The whole surface, not a blank shell: the card, its form and the
		// diagnosis card all render in one response.
		for _, id := range []string{"policyRoutingCard", "policyRoutingForm", "policyClientCard", "policyPanelStatus"} {
			if !strings.Contains(body, `id="`+id+`"`) {
				t.Errorf("Admin GET /routing does not render #%s", id)
			}
		}
		if !strings.Contains(body, `href="/routing"`) {
			t.Error("Admin GET /routing does not offer its own sidebar entry")
		}
	})

	for _, role := range []models.UserRole{models.RoleSupport, models.RoleUser} {
		t.Run(string(role)+" is refused", func(t *testing.T) {
			w := serveAs(t, r, role, routingPageEntry)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s GET /routing = %d, want 403; body=%s", role, w.Code, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, "forbidden") {
				t.Errorf("%s refusal is not the existing JSON denial: %s", role, body)
			}
			if !strings.Contains(body, "Admin privileges required") {
				t.Errorf("%s refusal does not carry the established detail: %s", role, body)
			}
			// A refusal must not carry the surface it refused: the page is not
			// partially rendered around the denial.
			for _, leaked := range []string{`id="policyRoutingCard"`, "policy_routing.js"} {
				if strings.Contains(body, leaked) {
					t.Errorf("%s refusal contains the admin-only surface (%q)", role, leaked)
				}
			}
		})
	}

	t.Run("anonymous is sent to login", func(t *testing.T) {
		w := serveAnonymous(r, routingPageEntry)
		if w.Code != http.StatusFound {
			t.Fatalf("anonymous GET /routing = %d, want 302; body=%s", w.Code, w.Body.String())
		}
		if loc := w.Header().Get("Location"); loc != "/login" {
			t.Errorf("anonymous GET /routing redirects to %q, want /login", loc)
		}
	})
}

// TestRoutingStaysOutOfTheSupportReachableVpnGroup is the placement check that
// matters for a role: Support keeps the VPN page it always had and does not gain the
// policy page beside it. A route added to the wrong group would pass every other
// test here.
func TestRoutingStaysOutOfTheSupportReachableVpnGroup(t *testing.T) {
	r, _ := newSettingsRoleRouter(t)

	if w := serveAs(t, r, models.RoleSupport, settingsEntryPoint{"vpn page", http.MethodGet, "/vpn", ""}); w.Code != http.StatusOK {
		t.Fatalf("Support GET /vpn = %d, want the page it always had", w.Code)
	}
	if w := serveAs(t, r, models.RoleSupport, routingPageEntry); w.Code != http.StatusForbidden {
		t.Fatalf("Support GET /routing = %d, want 403: Routing is not part of the VPN page's group", w.Code)
	}
}

// TestRoutingRefusalCarriesNoRedirect pins the bookmark-handling half of the design:
// /routing answers 403 with a JSON body for a refused role, never a redirect, and
// the handoff from a Settings fragment is a client-side navigation in the browser.
// A server-side redirect here would be derived from a request the role may not make.
func TestRoutingRefusalCarriesNoRedirect(t *testing.T) {
	r, _ := newSettingsRoleRouter(t)
	w := serveAs(t, r, models.RoleSupport, routingPageEntry)
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("the refusal carries a Location header %q; the handoff is client-side and this answer is a denial", loc)
	}
	if w := serveAs(t, r, models.RoleAdmin, routingPageEntry); w.Header().Get("Location") != "" {
		t.Error("GET /routing redirects an administrator; it must render the page")
	}
}

// TestRoutingPageNeedsNoPolicyFetchToRender states the wire contract: the page
// renders from the shell alone, and every policy value arrives afterwards from the
// APIs that already existed. A page handler that read the policy record would make a
// second source of truth for it.
func TestRoutingPageNeedsNoPolicyFetchToRender(t *testing.T) {
	r, _ := newSettingsRoleRouter(t)
	w := serveAs(t, r, models.RoleAdmin, routingPageEntry)
	if w.Code != http.StatusOK {
		t.Fatalf("Admin GET /routing = %d, want 200", w.Code)
	}
	body := w.Body.String()
	// The readouts start in their loading state and carry no data of their own.
	for _, placeholder := range []string{
		`id="policyStatusAnswer" data-state="loading"`,
		`id="policySyncState">…<`,
	} {
		if !strings.Contains(body, placeholder) {
			t.Errorf("the rendered readouts do not start unloaded (%q missing)", placeholder)
		}
	}
	if strings.Contains(body, "/api/vpn/policy/stats") {
		t.Error("the page fetches the retained stats endpoint, which the design kept as an API only")
	}
}
