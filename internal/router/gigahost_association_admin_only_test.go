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
// answer is the handler's own empty plan: no provider-provisioned row exists, so the
// handler answers with the counts instead of resolving a provider.
func TestGigahostAccountAssociationReachesTheHandlerForAnAdministrator(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			w := serveAs(t, r, models.RoleAdmin, settingsEntryPoint{"association", method, gigahostAssociationPath, ""})
			if w.Code != http.StatusOK {
				t.Fatalf("%s %s as admin = %d, want the handler's 200; body=%s", method, gigahostAssociationPath, w.Code, w.Body.String())
			}
			body := decodeJSON(t, w)
			if _, ok := body["candidates"]; !ok && method == http.MethodGet {
				t.Fatalf("the preview answered without a candidates count: %v", body)
			}
			if _, ok := body["associated"]; !ok && method == http.MethodPost {
				t.Fatalf("the action answered without an associated count: %v", body)
			}
		})
	}
}
