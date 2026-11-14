package handlers

// HTTP-boundary tests for the actionable half of a durable setup approval.
//
// These go through the real router wiring and the real SQLite database, because
// the promise is that a portal consumer can see a paused job and act on it. What
// they prove: only the states that stopped for a decision accept an action, a
// refusal reports the stored state rather than a fabricated success, and the
// confirmation is bound to the exact fingerprint (never to a bare boolean).

import (
	"context"
	"net/http"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
)

// setupActionTestRouter wires the durable setup routes plus the two actions a
// pause offers, mirroring the production router's admin sub-tree.
func setupActionTestRouter(t *testing.T, h *Handlers) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := middleware.WithSession(req.Context(), &models.SessionData{
				UserID:   "admin-1",
				Username: "admin",
				Role:     models.RoleAdmin,
			})
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Route("/api/admin/hosting/gigahost", func(r chi.Router) {
		r.Get("/setup-intents", h.GigahostSetupIntentsHandler)
		r.Post("/orders/{order_id}/setup-approval", h.GigahostSetupApproveHandler)
		r.Get("/orders/{order_id}/setup-approval", h.GigahostSetupStatusHandler)
		r.Delete("/orders/{order_id}/setup-approval", h.GigahostSetupCancelHandler)
		r.Post("/orders/{order_id}/setup-resume", h.GigahostSetupResumeHandler)
		r.Post("/orders/{order_id}/setup-host-confirmation", h.GigahostSetupConfirmHostHandler)
	})
	return r
}

// TestSetupResumeEndpointContinuesAPausedInstall proves the portal can resume a
// paused job, and that the durable row is what changes.
func TestSetupResumeEndpointContinuesAPausedInstall(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.pauseAtEnablement("ord_ui_resume", 6101, "198.51.100.101")
	r := setupActionTestRouter(t, env.h)

	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_ui_resume/setup-resume", nil)
	if code != http.StatusOK {
		t.Fatalf("resume = %d, want 200 (body: %v)", code, body)
	}
	if resumed, _ := body["resumed"].(bool); !resumed {
		t.Fatalf("resumed = %v, want true", body["resumed"])
	}
	setup, _ := body["setup"].(map[string]any)
	if setup["state"] != models.SetupStateInstalling {
		t.Fatalf("state = %v, want %q", setup["state"], models.SetupStateInstalling)
	}
	env.requireState("ord_ui_resume", models.SetupStateInstalling)
}

// TestSetupResumeEndpointRefusesASettledJob proves a resume cannot revive work that
// already finished, and that the refusal reports the real state.
func TestSetupResumeEndpointRefusesASettledJob(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_ui_done", 6102, "198.51.100.102")
	env.seedManagedCredential("ord_ui_done")
	env.providerServes("ord_ui_done", 6102, "198.51.100.102")
	env.approve("ord_ui_done", models.ProtocolAWG, "51820", installFixtureFingerprint)
	env.trackerAndInstall()
	env.requireState("ord_ui_done", models.SetupStateReady)

	r := setupActionTestRouter(t, env.h)
	enablesBefore := env.counters.enables
	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_ui_done/setup-resume", nil)
	if code != http.StatusConflict {
		t.Fatalf("resume of a completed job = %d, want 409 (body: %v)", code, body)
	}
	if body["status"] != "not_resumable" {
		t.Fatalf("status = %v, want not_resumable", body["status"])
	}
	setup, _ := body["setup"].(map[string]any)
	if setup["state"] != models.SetupStateReady {
		t.Fatalf("reported state = %v, want the real %q", setup["state"], models.SetupStateReady)
	}
	env.requireState("ord_ui_done", models.SetupStateReady)
	if env.counters.enables != enablesBefore {
		t.Fatal("a refused resume still enabled the backend again")
	}
}

// TestSetupResumeEndpointUnknownOrderIs404 keeps the two refusals distinct: an
// absent approval is not a job that refused to resume.
func TestSetupResumeEndpointUnknownOrderIs404(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	r := setupActionTestRouter(t, h)

	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_missing/setup-resume", nil)
	if code != http.StatusNotFound {
		t.Fatalf("resume of an unknown order = %d, want 404 (body: %v)", code, body)
	}
}

// TestSetupHostConfirmationBindsExactFingerprint proves the trust pause is
// actionable and that the stored identity is exactly what was confirmed.
func TestSetupHostConfirmationBindsExactFingerprint(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_ui_host", 6103, "198.51.100.103")
	env.seedManagedCredential("ord_ui_host")
	env.providerServes("ord_ui_host", 6103, "198.51.100.103")
	// No fingerprint in the approval: the charted trust pause.
	env.approve("ord_ui_host", models.ProtocolAWG, "51820", "")
	if err := env.tracker(nil).RunOnce(context.Background()); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	env.requireState("ord_ui_host", models.SetupStateAwaitingHostConfirm)

	r := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_ui_host/setup-host-confirmation",
		map[string]any{"fingerprint": installFixtureFingerprint})
	if code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200 (body: %v)", code, body)
	}
	if confirmed, _ := body["confirmed"].(bool); !confirmed {
		t.Fatalf("confirmed = %v, want true", body["confirmed"])
	}
	if body["fingerprint"] != installFixtureFingerprint {
		t.Fatalf("echoed fingerprint = %v, want the exact value confirmed", body["fingerprint"])
	}
	got := env.requireState("ord_ui_host", models.SetupStatePending)
	if got.HostFingerprint != installFixtureFingerprint {
		t.Fatalf("stored identity = %q, want the confirmed one", got.HostFingerprint)
	}
	if got.HostMismatch {
		t.Fatal("confirmation left a mismatch flag set")
	}
}

// TestSetupHostConfirmationRejectsMalformedIdentity proves a malformed value never
// reaches storage, where it would only fail much later at the handshake.
func TestSetupHostConfirmationRejectsMalformedIdentity(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_ui_badfp", 6104, "198.51.100.104")
	env.seedManagedCredential("ord_ui_badfp")
	env.providerServes("ord_ui_badfp", 6104, "198.51.100.104")
	env.approve("ord_ui_badfp", models.ProtocolAWG, "51820", "")
	if err := env.tracker(nil).RunOnce(context.Background()); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	env.requireState("ord_ui_badfp", models.SetupStateAwaitingHostConfirm)

	r := setupActionTestRouter(t, env.h)
	for _, fp := range []string{"", "SHA256:short", "md5:aa:bb:cc", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		code, body := doJSON(t, r, http.MethodPost,
			"/api/admin/hosting/gigahost/orders/ord_ui_badfp/setup-host-confirmation",
			map[string]any{"fingerprint": fp})
		if code != http.StatusBadRequest {
			t.Fatalf("fingerprint %q = %d, want 400 (body: %v)", fp, code, body)
		}
	}
	got := env.requireState("ord_ui_badfp", models.SetupStateAwaitingHostConfirm)
	if got.HostFingerprint != "" {
		t.Fatalf("a rejected confirmation stored %q", got.HostFingerprint)
	}
}

// TestSetupHostConfirmationRefusesAJobNotWaiting proves confirmation is only
// accepted where it means something, and that it cannot move a running job.
func TestSetupHostConfirmationRefusesAJobNotWaiting(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder("ord_ui_nohost", 6105, "198.51.100.105")
	env.seedManagedCredential("ord_ui_nohost")
	env.providerServes("ord_ui_nohost", 6105, "198.51.100.105")
	env.approve("ord_ui_nohost", models.ProtocolAWG, "51820", installFixtureFingerprint)
	env.trackerAndInstall()
	env.requireState("ord_ui_nohost", models.SetupStateReady)

	r := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_ui_nohost/setup-host-confirmation",
		map[string]any{"fingerprint": installFixtureFingerprintBound})
	if code != http.StatusConflict {
		t.Fatalf("confirmation on a completed job = %d, want 409 (body: %v)", code, body)
	}
	if body["status"] != "not_confirmable" {
		t.Fatalf("status = %v, want not_confirmable", body["status"])
	}
	env.requireState("ord_ui_nohost", models.SetupStateReady)
}
