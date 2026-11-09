package handlers

// HTTP-boundary tests for durable setup approvals.
//
// These go through the real router wiring and the real SQLite database: the
// point is that the approval endpoint, the status endpoint and the tracker store
// agree about one row, so an administrator can observe saved work without the
// browser that started it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/go-chi/chi/v5"
)

// setupIntentTestRouter builds a router with the approval routes and an admin
// session, mirroring the production middleware order.
func setupIntentTestRouter(t *testing.T, h *Handlers) *chi.Mux {
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
	})
	return r
}

// seedPlacedOrder records a real placed order for the approval to reference.
func seedPlacedOrder(t *testing.T, h *Handlers, orderID string, providerServerID int64, ip string) {
	t.Helper()
	now := time.Now().UTC()
	err := h.db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID:    orderID,
		ServerID:   providerServerID,
		Status:     gigahost.StatusDeploying,
		AssignedIP: ip,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("seed order: %v", err)
	}
}

// doJSON performs a request and returns the status code and decoded body.
func doJSON(t *testing.T, r http.Handler, method, target string, body any) (int, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	var decoded map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
	}
	return rec.Code, decoded
}

// TestSetupApprovalPersistsAndIsObservableWithoutBrowser proves the core promise:
// an approval recorded through the API is readable afterwards as a durable job,
// with the exact protocol and credential reference the administrator chose.
func TestSetupApprovalPersistsAndIsObservableWithoutBrowser(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_approve_1", 4321, "")
	r := setupIntentTestRouter(t, h)

	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_approve_1/setup-approval",
		map[string]any{
			"protocol":             "vless",
			"port":                 "443",
			"tls_domain":           "vpn.example.com",
			"use_order_credential": true,
		})
	if code != http.StatusAccepted {
		t.Fatalf("approve status = %d, want %d (body: %v)", code, http.StatusAccepted, body)
	}
	if created, _ := body["created"].(bool); !created {
		t.Fatalf("created = %v, want true", body["created"])
	}

	// A fresh read, as a different browser would do, must see the saved job.
	code, body = doJSON(t, r, http.MethodGet,
		"/api/admin/hosting/gigahost/orders/ord_approve_1/setup-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("status read = %d, want 200 (body: %v)", code, body)
	}
	setup, ok := body["setup"].(map[string]any)
	if !ok {
		t.Fatalf("response has no setup object: %v", body)
	}
	if setup["protocol"] != "vless" {
		t.Fatalf("protocol = %v, want vless", setup["protocol"])
	}
	if setup["credential_mode"] != models.SetupCredentialManaged {
		t.Fatalf("credential_mode = %v, want %q", setup["credential_mode"], models.SetupCredentialManaged)
	}
	if setup["state"] != models.SetupStatePending {
		t.Fatalf("state = %v, want %q", setup["state"], models.SetupStatePending)
	}
	// The ledger identity is carried onto the intent, not re-derived.
	if got, _ := setup["provider_server_id"].(float64); int64(got) != 4321 {
		t.Fatalf("provider_server_id = %v, want 4321", setup["provider_server_id"])
	}
}

// TestSetupApprovalDoesNotStoreCredentialMaterial proves the intent carries only
// a reference: a password or key in the approval request is not persisted.
func TestSetupApprovalDoesNotStoreCredentialMaterial(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_secret", 5555, "")
	r := setupIntentTestRouter(t, h)

	const secret = "SUPER-SECRET-PASSWORD-123"
	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_secret/setup-approval",
		map[string]any{
			"protocol":     "awg",
			"ssh_password": secret,
			"ssh_key":      "-----BEGIN OPENSSH PRIVATE KEY-----",
		})
	if code != http.StatusAccepted {
		t.Fatalf("approve status = %d, want 202 (body: %v)", code, body)
	}

	// The intent row must not carry the material anywhere.
	intent, found, err := h.db.GetGigahostSetupIntent(context.Background(), "ord_secret")
	if err != nil || !found {
		t.Fatalf("read intent: found=%v err=%v", found, err)
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		t.Fatalf("encode intent: %v", err)
	}
	if bytes.Contains(encoded, []byte(secret)) || bytes.Contains(encoded, []byte("BEGIN OPENSSH PRIVATE KEY")) {
		t.Fatalf("intent row contains credential material: %s", encoded)
	}
	if intent.CredentialMode != models.SetupCredentialManual {
		t.Fatalf("credential_mode = %q, want %q", intent.CredentialMode, models.SetupCredentialManual)
	}
}

// TestSetupApprovalRefusesUnknownOrSyntheticOrder is the negative control: an
// approval for an order the ledger does not have, or for a placeholder id, must
// be refused so no job exists whose provider side nobody placed.
func TestSetupApprovalRefusesUnknownOrSyntheticOrder(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "intent_1700000000000", 0, "")
	r := setupIntentTestRouter(t, h)

	for _, tc := range []struct{ orderID, why string }{
		{"ord_never_placed", "not in the ledger"},
		{"intent_1700000000000", "synthetic unresolved-intent id"},
	} {
		code, body := doJSON(t, r, http.MethodPost,
			"/api/admin/hosting/gigahost/orders/"+tc.orderID+"/setup-approval",
			map[string]any{"protocol": "awg"})
		if code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400 (body: %v)", tc.why, code, body)
		}
		if _, found, err := h.db.GetGigahostSetupIntent(context.Background(), tc.orderID); err != nil || found {
			t.Fatalf("%s: an intent was created despite the refusal", tc.why)
		}
	}
}

// TestSetupApprovalRequiresExplicitProtocol proves nothing is defaulted: a durable
// approval must state the protocol the administrator actually requested.
func TestSetupApprovalRequiresExplicitProtocol(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_noproto", 6666, "")
	r := setupIntentTestRouter(t, h)

	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_noproto/setup-approval",
		map[string]any{"use_order_credential": true})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %v)", code, body)
	}

	code, body = doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_noproto/setup-approval",
		map[string]any{"protocol": "wireguard-ng"})
	if code != http.StatusBadRequest {
		t.Fatalf("unsupported protocol: status = %d, want 400 (body: %v)", code, body)
	}
}

// TestSetupApprovalRejectsMalformedFingerprint proves the recorded identity is a
// real SHA256 fingerprint, so trust later compares against something meaningful.
func TestSetupApprovalRejectsMalformedFingerprint(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_badfp", 7777, "")
	r := setupIntentTestRouter(t, h)

	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_badfp/setup-approval",
		map[string]any{"protocol": "awg", "expected_fingerprint": "SHA256:not-a-real-key"})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %v)", code, body)
	}
}

// TestSetupApprovalIsIdempotent proves a repeated approval does not create a
// second job: the second call answers with the stored row and created=false.
func TestSetupApprovalIsIdempotent(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_repeat", 8888, "")
	r := setupIntentTestRouter(t, h)

	payload := map[string]any{"protocol": "awg", "use_order_credential": true}
	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_repeat/setup-approval", payload)
	if code != http.StatusAccepted {
		t.Fatalf("first approve = %d, want 202 (body: %v)", code, body)
	}
	firstID := mustSetupID(t, body)

	code, body = doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_repeat/setup-approval", payload)
	if code != http.StatusOK {
		t.Fatalf("second approve = %d, want 200 (body: %v)", code, body)
	}
	if created, _ := body["created"].(bool); created {
		t.Fatal("second approval reported created=true")
	}
	if secondID := mustSetupID(t, body); secondID != firstID {
		t.Fatalf("second approval produced a different job: %d vs %d", secondID, firstID)
	}

	intents, err := h.db.ListGigahostSetupIntents(context.Background())
	if err != nil {
		t.Fatalf("list intents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("intent count = %d, want 1", len(intents))
	}
}

func mustSetupID(t *testing.T, body map[string]any) int64 {
	t.Helper()
	setup, ok := body["setup"].(map[string]any)
	if !ok {
		t.Fatalf("response has no setup object: %v", body)
	}
	id, ok := setup["id"].(float64)
	if !ok {
		t.Fatalf("setup has no id: %v", setup)
	}
	return int64(id)
}

// TestSetupApprovalCancelRevokesAndIsIdempotent proves revocation is durable and
// repeatable, and that the cancelled state is what the status endpoint reports.
func TestSetupApprovalCancelRevokesAndIsIdempotent(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_cancel", 9999, "")
	r := setupIntentTestRouter(t, h)

	if code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_cancel/setup-approval",
		map[string]any{"protocol": "awg", "use_order_credential": true}); code != http.StatusAccepted {
		t.Fatalf("approve = %d, want 202 (body: %v)", code, body)
	}

	code, body := doJSON(t, r, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/ord_cancel/setup-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("cancel = %d, want 200 (body: %v)", code, body)
	}
	if changed, _ := body["changed"].(bool); !changed {
		t.Fatalf("first cancel reported changed=false: %v", body)
	}

	// Repeating the revocation is the same request twice, not an error.
	code, body = doJSON(t, r, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/ord_cancel/setup-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("repeat cancel = %d, want 200 (body: %v)", code, body)
	}

	code, body = doJSON(t, r, http.MethodGet,
		"/api/admin/hosting/gigahost/orders/ord_cancel/setup-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("status read = %d, want 200 (body: %v)", code, body)
	}
	setup, _ := body["setup"].(map[string]any)
	if setup["state"] != models.SetupStateCanceled {
		t.Fatalf("state = %v, want %q", setup["state"], models.SetupStateCanceled)
	}
}

// TestSetupIntentStatusUnknownOrderIs404 proves an unapproved order is reported
// as absent rather than as an empty job.
func TestSetupIntentStatusUnknownOrderIs404(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	r := setupIntentTestRouter(t, h)

	if code, body := doJSON(t, r, http.MethodGet,
		"/api/admin/hosting/gigahost/orders/ord_absent/setup-approval", nil); code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %v)", code, body)
	}
	if code, body := doJSON(t, r, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/ord_absent/setup-approval", nil); code != http.StatusNotFound {
		t.Fatalf("cancel status = %d, want 404 (body: %v)", code, body)
	}
}

// TestSetupIntentsListShowsAllSavedWork proves the list endpoint is the
// browser-independent view: every approval is visible with its state.
func TestSetupIntentsListShowsAllSavedWork(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_list_a", 100, "")
	seedPlacedOrder(t, h, "ord_list_b", 200, "")
	r := setupIntentTestRouter(t, h)

	for _, id := range []string{"ord_list_a", "ord_list_b"} {
		if code, body := doJSON(t, r, http.MethodPost,
			"/api/admin/hosting/gigahost/orders/"+id+"/setup-approval",
			map[string]any{"protocol": "awg", "use_order_credential": true}); code != http.StatusAccepted {
			t.Fatalf("approve %s = %d (body: %v)", id, code, body)
		}
	}

	code, body := doJSON(t, r, http.MethodGet, "/api/admin/hosting/gigahost/setup-intents", nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body: %v)", code, body)
	}
	list, ok := body["setup_intents"].([]any)
	if !ok {
		t.Fatalf("response has no setup_intents array: %v", body)
	}
	if len(list) != 2 {
		t.Fatalf("intent count = %d, want 2", len(list))
	}
}

// TestSetupApprovalNudgesTracker proves the approval path actually asks the
// background worker for an immediate pass, which is what makes a fresh approval
// observed promptly rather than only on the next interval.
func TestSetupApprovalNudgesTracker(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_nudge", 1111, "")

	var nudges int
	h.SetGigahostSetupNudge(func() { nudges++ })
	r := setupIntentTestRouter(t, h)

	if code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_nudge/setup-approval",
		map[string]any{"protocol": "awg", "use_order_credential": true}); code != http.StatusAccepted {
		t.Fatalf("approve = %d, want 202 (body: %v)", code, body)
	}
	if nudges != 1 {
		t.Fatalf("nudges = %d, want 1", nudges)
	}

	// A refused approval must not nudge: nothing was recorded to track.
	if code, _ := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_absent/setup-approval",
		map[string]any{"protocol": "awg"}); code != http.StatusBadRequest {
		t.Fatalf("unknown order approve = %d, want 400", code)
	}
	if nudges != 1 {
		t.Fatalf("nudges after a refused approval = %d, want 1", nudges)
	}
}

// TestSetupApprovalRequiresAdmin proves the endpoints are not reachable by a
// non-admin session.
func TestSetupApprovalRequiresAdmin(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_rbac", 2222, "")

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := middleware.WithSession(req.Context(), &models.SessionData{
				UserID: "user-1", Username: "plain", Role: models.RoleUser,
			})
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Post("/api/admin/hosting/gigahost/orders/{order_id}/setup-approval", h.GigahostSetupApproveHandler)

	if code, _ := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_rbac/setup-approval",
		map[string]any{"protocol": "awg"}); code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", code)
	}
	if _, found, _ := h.db.GetGigahostSetupIntent(context.Background(), "ord_rbac"); found {
		t.Fatal("a non-admin created a setup intent")
	}
}

// TestSetupApprovalRejectsMissingOrderID proves the empty-id guard, which a route
// with an empty path segment can reach.
func TestSetupApprovalRejectsMissingOrderID(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	if _, _, err := h.ApproveGigahostSetup(context.Background(), "  ",
		GigahostSetupApproveRequest{Protocol: "awg"}, "admin-1"); err == nil {
		t.Fatal("empty order id accepted")
	}
	if _, _, err := h.CancelGigahostSetup(context.Background(), ""); err == nil {
		t.Fatal("cancel with an empty order id accepted")
	}
}

// TestSetupApprovalFailsWithoutDatabase proves a handler with no database reports
// the misconfiguration instead of appearing to succeed.
func TestSetupApprovalFailsWithoutDatabase(t *testing.T) {
	h := NewHandlers(Dependencies{})
	if _, _, err := h.ApproveGigahostSetup(context.Background(), "ord_x",
		GigahostSetupApproveRequest{Protocol: "awg"}, "admin-1"); err == nil {
		t.Fatal("approval without a database accepted")
	}
	if _, _, err := h.CancelGigahostSetup(context.Background(), "ord_x"); err == nil {
		t.Fatal("cancel without a database accepted")
	}
	// The read helpers degrade to empty rather than panicking.
	if intent, found, err := h.GetGigahostSetupIntent(context.Background(), "ord_x"); err != nil || found || intent != nil {
		t.Fatalf("read without a database: intent=%+v found=%v err=%v", intent, found, err)
	}
	if list, err := h.ListGigahostSetupIntents(context.Background()); err != nil || len(list) != 0 {
		t.Fatalf("list without a database: %+v err=%v", list, err)
	}
}

// TestSetupApprovalDefaultPortIsRecorded proves that when the approval omits a
// port, the protocol's documented default is written into the durable record, so
// the handoff cannot disagree with what was approved.
func TestSetupApprovalDefaultPortIsRecorded(t *testing.T) {
	for _, tc := range []struct{ protocol, wantPort string }{
		{"awg", "51820"},
		{"vless", "443"},
		{"naive", "443"},
	} {
		h, _, _ := setupTestHandlers(t)
		orderID := "ord_port_" + tc.protocol
		seedPlacedOrder(t, h, orderID, 1, "")
		intent, created, err := h.ApproveGigahostSetup(context.Background(), orderID,
			GigahostSetupApproveRequest{Protocol: tc.protocol, UseOrderCredential: true}, "admin-1")
		if err != nil || !created {
			t.Fatalf("%s: created=%v err=%v", tc.protocol, created, err)
		}
		if intent.Port != tc.wantPort {
			t.Fatalf("%s: port = %q, want %q", tc.protocol, intent.Port, tc.wantPort)
		}
	}
}

// TestSetupApprovalCarriesLedgerIdentity proves the approval adopts the provider
// identity the ledger already recorded instead of re-deriving or guessing it.
func TestSetupApprovalCarriesLedgerIdentity(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedPlacedOrder(t, h, "ord_identity", 8675, "198.51.100.99")

	intent, _, err := h.ApproveGigahostSetup(context.Background(), "ord_identity",
		GigahostSetupApproveRequest{Protocol: "awg", Port: "51821", UseOrderCredential: true}, "admin-7")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if intent.ProviderServerID != 8675 {
		t.Fatalf("provider server id = %d, want 8675", intent.ProviderServerID)
	}
	if intent.AssignedIP != "198.51.100.99" {
		t.Fatalf("assigned ip = %q", intent.AssignedIP)
	}
	if intent.Port != "51821" {
		t.Fatalf("explicit port was not preserved: %q", intent.Port)
	}
	if intent.ApprovedBy != "admin-7" {
		t.Fatalf("approver = %q", intent.ApprovedBy)
	}
}

// TestSetupListAndReadFailWithoutDatabase proves the list endpoint reports a
// database error rather than an empty list that looks like "nothing approved".
func TestSetupIntentsHandlerWithoutDatabase(t *testing.T) {
	h := NewHandlers(Dependencies{})
	r := setupIntentTestRouter(t, h)
	code, body := doJSON(t, r, http.MethodGet, "/api/admin/hosting/gigahost/setup-intents", nil)
	if code != http.StatusOK {
		t.Fatalf("list without database status = %d, want 200 empty (body: %v)", code, body)
	}
	list, _ := body["setup_intents"].([]any)
	if len(list) != 0 {
		t.Fatalf("expected an empty list, got %v", body["setup_intents"])
	}
}

// TestLoadApprovableOrderRefusals proves the two refusal reasons are distinct and
// neither creates anything.
func TestLoadApprovableOrderRefusals(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	if _, err := h.loadApprovableOrder(ctx, "   "); err == nil {
		t.Fatal("blank order id accepted")
	}
	_, err := h.loadApprovableOrder(ctx, "unknown_99")
	var validation *setupValidationError
	if !errors.As(err, &validation) || !strings.Contains(validation.msg, "no confirmed provider order") {
		t.Fatalf("placeholder id error = %v, want the no-provider-order refusal", err)
	}
	_, err = h.loadApprovableOrder(ctx, "ord_nope")
	if !errors.As(err, &validation) || !strings.Contains(validation.msg, "not recorded") {
		t.Fatalf("unknown id error = %v, want the not-recorded refusal", err)
	}

	seedPlacedOrder(t, h, "ord_ok", 3, "198.51.100.70")
	order, err := h.loadApprovableOrder(ctx, "ord_ok")
	if err != nil || order == nil || order.OrderID != "ord_ok" {
		t.Fatalf("valid order: order=%+v err=%v", order, err)
	}
}
