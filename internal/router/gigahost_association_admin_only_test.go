package router

// The one-time provider account association is an administrative action: it changes
// which hosting account a server row belongs to, and its confirmed form lets the
// next inventory read mark a server absent. Both verbs therefore live in the
// admin-only group, and this test proves the route refuses every other role rather
// than only the page that offers the control.

import (
	"net/http"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const gigahostAssociationPath = "/api/admin/hosting/gigahost/account-association"

func TestGigahostAccountAssociationIsAdministratorOnly(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, role := range []models.UserRole{models.RoleSupport, models.RoleUser} {
			t.Run(method+"-"+string(role), func(t *testing.T) {
				if w := serveAs(t, r, role, settingsEntryPoint{"association", method, gigahostAssociationPath, ""}); w.Code != http.StatusForbidden {
					t.Fatalf("%s %s as %q = %d, want 403; body=%s", method, gigahostAssociationPath, role, w.Code, w.Body.String())
				}
			})
		}
		t.Run(method+"-anonymous", func(t *testing.T) {
			w := serveAnonymous(r, settingsEntryPoint{"association", method, gigahostAssociationPath, ""})
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s anonymously = %d, want 401; body=%s", method, gigahostAssociationPath, w.Code, w.Body.String())
			}
		})
	}
}

// TestGigahostAccountAssociationReachesTheHandlerForAnAdministrator proves the two
// routes are registered in the group that admits an administrator, so a refusal
// above cannot be mistaken for "the route exists and works for nobody". The asserted
// answer is the handler's own: the preview reports the empty plan's counts, and the
// action refuses a confirmation that names no preview - which is this handler's
// contract, not the middleware's refusal.
func TestGigahostAccountAssociationReachesTheHandlerForAnAdministrator(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	t.Run("GET", func(t *testing.T) {
		w := serveAs(t, r, models.RoleAdmin, settingsEntryPoint{"association", http.MethodGet, gigahostAssociationPath, ""})
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s as admin = %d, want the handler's 200; body=%s", gigahostAssociationPath, w.Code, w.Body.String())
		}
		body := decodeJSON(t, w)
		if _, ok := body["candidates"]; !ok {
			t.Fatalf("the preview answered without a candidates count: %v", body)
		}
		if _, ok := body["preview_id"]; !ok {
			t.Fatalf("the preview answered without the token a confirmation must name: %v", body)
		}
	})

	t.Run("POST", func(t *testing.T) {
		// A confirmation that names no preview is refused by the handler itself, so
		// this proves the route reached it rather than only that the role check ran.
		w := serveAs(t, r, models.RoleAdmin, settingsEntryPoint{"association", http.MethodPost, gigahostAssociationPath, ""})
		if w.Code != http.StatusConflict {
			t.Fatalf("POST %s as admin = %d, want the handler's 409; body=%s", gigahostAssociationPath, w.Code, w.Body.String())
		}
		body := decodeJSON(t, w)
		if got, _ := body["error"].(string); got != "gigahost_association_preview_required" {
			t.Fatalf("the action's refusal is not its own preview requirement: %v", body)
		}
	})
}
