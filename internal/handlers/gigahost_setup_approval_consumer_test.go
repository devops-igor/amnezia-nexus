package handlers

// Consumer proof for portal-initiated saved setup approvals.
//
// The portal test (web/gigahost_setup_approval_consumer_test.go) proves the
// shipped page posts the approval. This file proves the other half of the same
// journey against the real router, the real SQLite database and the real
// background tracker:
//
//	POST .../setup-approval        records the job and answers immediately
//	                               without asking the provider anything
//	GET  .../setup-approval        a later request - a different browser, a
//	                               restarted panel - reads the same job
//	tracker pass                   the panel's own worker consumes it after the
//	                               original request is over, from durable state
//	POST .../setup-host-confirmation
//	                               the administrator confirms the identity the
//	                               panel displayed; the job continues
//
// Two properties are asserted throughout because they are the reason this path
// exists rather than a synchronous install: the approval performs no provider
// write (so no purchase can be caused by approving, repeating or restarting),
// and a long provisioning window costs the administrator nothing but a saved job.

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
	"github.com/go-chi/chi/v5"
)

// providerCallCounts records every provider write the approval path must never
// perform, plus the reads the tracker is allowed to make.
type providerCallCounts struct {
	orders        int
	safeOrders    int
	keyRegistrars int
	statusReads   int
	serverReads   int
}

// countingProvider is a gigahost.Client that counts writes. The approval handler
// has no access to a provider at all, so a non-zero write count here is the
// finding: it would mean approving setup bought or registered something.
type countingProvider struct {
	mockGigahostClient
	counts *providerCallCounts
}

func (p *countingProvider) OrderServer(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	p.counts.orders++
	return p.mockGigahostClient.OrderServer(ctx, req)
}

func (p *countingProvider) OrderServerSafe(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	p.counts.safeOrders++
	return p.mockGigahostClient.OrderServerSafe(ctx, req)
}

func (p *countingProvider) RegisterSSHKey(ctx context.Context, name, publicKey string) error {
	p.counts.keyRegistrars++
	return p.mockGigahostClient.RegisterSSHKey(ctx, name, publicKey)
}

func (p *countingProvider) GetDeployStatus(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
	p.counts.statusReads++
	return p.mockGigahostClient.GetDeployStatus(ctx, orderID)
}

func (p *countingProvider) GetServers(ctx context.Context) ([]gigahost.ServerInfo, error) {
	p.counts.serverReads++
	return p.mockGigahostClient.GetServers(ctx)
}

// newApprovalConsumerHandlers builds handlers over an existing database, the way
// a restarted panel would.
func newApprovalConsumerHandlers(t *testing.T, db *database.DB) *Handlers {
	t.Helper()
	return newHandlersOverDB(t, db)
}

// seedManagedOrder records a placed order that already carries the managed SSH
// credential a portal order is created with.
func seedManagedOrder(t *testing.T, h *Handlers, orderID string, providerServerID int64, ip string) {
	t.Helper()
	seedPlacedOrder(t, h, orderID, providerServerID, ip)
	if err := h.db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID:    orderID,
		PrivateKey: "FIXTURE-PRIVATE-MATERIAL-NOT-A-KEY",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
	}); err != nil {
		t.Fatalf("seed managed credential: %v", err)
	}
}

// portalApproval creates the approval exactly as the shipped page does: the
// protocol and the managed-credential reference, and nothing else.
func portalApproval(t *testing.T, r http.Handler, orderID, protocol string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval",
		map[string]any{"protocol": protocol, "use_order_credential": true})
}

// TestPortalApprovalIsDurableAndCostsNoProviderWrite is the core promise of the
// saved path: approving records work the panel owns, answers without waiting for
// the provider, and buys or registers nothing.
func TestPortalApprovalIsDurableAndCostsNoProviderWrite(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	seedManagedOrder(t, h, "ord_portal_1", 4321, "198.51.100.10")

	counts := &providerCallCounts{}
	h.SetGigahostClient(&countingProvider{counts: counts})
	r := setupIntentTestRouter(t, h)

	started := time.Now()
	code, body := portalApproval(t, r, "ord_portal_1", "vless")
	elapsed := time.Since(started)

	// A durable approval is a database write and a nudge, not a provisioning
	// wait: it must return long before any provider readiness could be observed.
	if elapsed > 5*time.Second {
		t.Fatalf("approval took %s: it must not wait for provisioning", elapsed)
	}
	if code != http.StatusAccepted {
		t.Fatalf("approve = %d, want 202 (body: %v)", code, body)
	}
	if created, _ := body["created"].(bool); !created {
		t.Fatal("approval reported created=false on its first request")
	}
	// The response is the existing DTO, carrying what the portal actually chose.
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
	if got, _ := setup["provider_server_id"].(float64); int64(got) != 4321 {
		t.Fatalf("provider_server_id = %v, want 4321", got)
	}

	// Approving performs no provider effect of any kind.
	if counts.orders != 0 || counts.safeOrders != 0 || counts.keyRegistrars != 0 {
		t.Fatalf("approval caused provider writes: orders=%d safe=%d keys=%d",
			counts.orders, counts.safeOrders, counts.keyRegistrars)
	}
	if counts.statusReads != 0 {
		t.Fatalf("approval read provider status %d times: it must not wait on readiness", counts.statusReads)
	}

	// A repeated approval is the same job, still with no provider effect.
	code, body = portalApproval(t, r, "ord_portal_1", "vless")
	if code != http.StatusOK {
		t.Fatalf("repeat approve = %d, want 200 (body: %v)", code, body)
	}
	if created, _ := body["created"].(bool); created {
		t.Fatal("a repeated approval reported created=true")
	}
	if counts.orders != 0 || counts.safeOrders != 0 || counts.keyRegistrars != 0 {
		t.Fatalf("repeated approval caused provider writes: orders=%d safe=%d keys=%d",
			counts.orders, counts.safeOrders, counts.keyRegistrars)
	}
	intents, err := db.ListGigahostSetupIntents(context.Background())
	if err != nil {
		t.Fatalf("list intents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("intent count = %d, want 1: a repeat must not create a second job", len(intents))
	}

	// A later, independent reader sees the same saved job.
	restarted := newApprovalConsumerHandlers(t, db)
	code, body = doJSON(t, setupIntentTestRouter(t, restarted), http.MethodGet,
		"/api/admin/hosting/gigahost/orders/ord_portal_1/setup-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("read after restart = %d, want 200 (body: %v)", code, body)
	}
	saved, _ := body["setup"].(map[string]any)
	if saved["protocol"] != "vless" || saved["port"] != "443" {
		t.Fatalf("saved job = %v, want vless:443", saved)
	}
}

// TestPortalApprovalIsConsumedByLaterTrackerPass proves the saved job is picked up
// by the panel's own worker after the original request ended: the browser that
// approved it is gone, a fresh Handlers instance runs the pass, and a fake
// provider keeps the server provisioning for 100 virtual minutes without blocking
// anything.
func TestPortalApprovalIsConsumedByLaterTrackerPass(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	seedManagedOrder(t, h, "ord_portal_2", 7777, "198.51.100.20")
	r := setupIntentTestRouter(t, h)

	if code, body := portalApproval(t, r, "ord_portal_2", "awg"); code != http.StatusAccepted {
		t.Fatalf("approve = %d, want 202 (body: %v)", code, body)
	}

	// The approving request is over. Build the worker the restarted panel would
	// build, over the same database file, with a fake provider and clock. The
	// clock starts at the approval's own schedule so the saved row is due, and is
	// advanced from there - no real wait is spent on provisioning.
	restarted := newApprovalConsumerHandlers(t, db)
	start := time.Now().UTC()
	clock := &virtualClock{now: start}
	provider := &trackerFakeProvider{}
	tracker, challengedFn := newPortalTracker(t, db, provider, clock)

	// Ten virtual minutes apart, eleven times: the server provisions for 100
	// virtual minutes. Nothing here waits on real time.
	for i := 0; i < 11; i++ {
		if err := tracker.RunOnce(context.Background()); err != nil {
			t.Fatalf("tracking pass %d: %v", i, err)
		}
		saved, found, err := db.GetGigahostSetupIntent(context.Background(), "ord_portal_2")
		if err != nil || !found {
			t.Fatalf("read intent after pass %d: found=%v err=%v", i, found, err)
		}
		if saved.State != models.SetupStatePending {
			t.Fatalf("pass %d: state = %q, want %q while provisioning", i, saved.State, models.SetupStatePending)
		}
		if saved.ProviderStatus != gigahost.StatusDeploying {
			t.Fatalf("pass %d: provider status = %q, want %q", i, saved.ProviderStatus, gigahost.StatusDeploying)
		}
		clock.Advance(10 * time.Minute)
	}
	if clock.now.Sub(start) < 100*time.Minute {
		t.Fatalf("virtual elapsed = %v, want at least 100m", clock.now.Sub(start))
	}

	// The provider becomes ready. The job stops at the trust pause with the
	// identity the panel observed - it authorizes nothing on its own.
	provider.ready = true
	if err := tracker.RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass after readiness: %v", err)
	}
	saved, found, err := db.GetGigahostSetupIntent(context.Background(), "ord_portal_2")
	if err != nil || !found {
		t.Fatalf("read intent: found=%v err=%v", found, err)
	}
	if saved.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want %q (detail %q)", saved.State, models.SetupStateAwaitingHostConfirm, saved.LastError)
	}
	if challengedFn() != 1 {
		t.Fatalf("host challenges = %d, want 1", challengedFn())
	}
	const observed = "SHA256:REREREREREREREREREREREREREREREREREREREREREQ"
	if saved.HostCandidateFingerprint != observed {
		t.Fatalf("displayed candidate = %q, want %q", saved.HostCandidateFingerprint, observed)
	}
	// Still no provider write, from either the handler or the worker.
	if provider.orders != 0 || provider.keyRegistrations != 0 {
		t.Fatalf("worker caused provider writes: orders=%d keys=%d", provider.orders, provider.keyRegistrations)
	}

	// The administrator confirms the displayed identity from the saved list. The
	// job then reaches the install handoff, still with no provider write.
	code, body := doJSON(t, setupIntentTestRouter(t, restarted), http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_portal_2/setup-host-confirmation",
		map[string]any{"fingerprint": observed})
	if code != http.StatusOK {
		t.Fatalf("host confirmation = %d, want 200 (body: %v)", code, body)
	}
	if err := tracker.RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass after confirmation: %v", err)
	}
	saved, found, err = db.GetGigahostSetupIntent(context.Background(), "ord_portal_2")
	if err != nil || !found {
		t.Fatalf("read intent after confirmation: found=%v err=%v", found, err)
	}
	if saved.State != models.SetupStateReadyForSetup {
		t.Fatalf("state = %q, want %q (detail %q)", saved.State, models.SetupStateReadyForSetup, saved.LastError)
	}
	if provider.orders != 0 || provider.keyRegistrations != 0 {
		t.Fatalf("confirmation caused provider writes: orders=%d keys=%d", provider.orders, provider.keyRegistrations)
	}
}

// TestPortalApprovalRefusalsCreateNothing covers the denied choices at the HTTP
// boundary: a non-admin session, an unrecorded order, a placeholder id and a job
// the administrator revokes all leave no approval behind, so no worker can pick
// up work nobody approved.
func TestPortalApprovalRefusalsCreateNothing(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	seedManagedOrder(t, h, "ord_portal_ok", 555, "198.51.100.30")
	counts := &providerCallCounts{}
	h.SetGigahostClient(&countingProvider{counts: counts})
	r := setupIntentTestRouter(t, h)

	for _, tc := range []struct {
		orderID string
		why     string
	}{
		{"ord_never_placed", "not in the ledger"},
		{"unknown_1700000000000", "unknown purchase outcome"},
	} {
		code, body := portalApproval(t, r, tc.orderID, "awg")
		if code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400 (body: %v)", tc.why, code, body)
		}
		if _, found, err := db.GetGigahostSetupIntent(context.Background(), tc.orderID); err != nil || found {
			t.Fatalf("%s: an approval was created despite the refusal", tc.why)
		}
	}

	// A non-admin session cannot approve anything.
	nonAdmin := chi.NewRouter()
	nonAdmin.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := middleware.WithSession(req.Context(), &models.SessionData{
				UserID: "user-1", Username: "plain", Role: models.RoleUser,
			})
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	nonAdmin.Post("/api/admin/hosting/gigahost/orders/{order_id}/setup-approval", h.GigahostSetupApproveHandler)
	if code, _ := portalApproval(t, nonAdmin, "ord_portal_ok", "awg"); code != http.StatusForbidden {
		t.Fatalf("non-admin approve = %d, want 403", code)
	}
	if _, found, _ := db.GetGigahostSetupIntent(context.Background(), "ord_portal_ok"); found {
		t.Fatal("a non-admin created a setup approval")
	}

	// The administrator approves, then revokes: the saved job is canceled and a
	// subsequent worker pass performs no provider write.
	if code, body := portalApproval(t, r, "ord_portal_ok", "awg"); code != http.StatusAccepted {
		t.Fatalf("approve = %d, want 202 (body: %v)", code, body)
	}
	if code, body := doJSON(t, r, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/ord_portal_ok/setup-approval", nil); code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200 (body: %v)", code, body)
	}
	saved, found, err := db.GetGigahostSetupIntent(context.Background(), "ord_portal_ok")
	if err != nil || !found {
		t.Fatalf("read revoked intent: found=%v err=%v", found, err)
	}
	if saved.State != models.SetupStateCanceled {
		t.Fatalf("state = %q, want %q", saved.State, models.SetupStateCanceled)
	}

	provider := &trackerFakeProvider{ready: true}
	tracker := gigahostsetup.New(db, gigahostsetup.Options{
		Resolve: func(context.Context) (gigahostsetup.ProviderReader, error) { return provider, nil },
		Now:     func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC) },
	})
	if err := tracker.RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass over a revoked job: %v", err)
	}
	if provider.statusReads != 0 {
		t.Fatalf("a revoked approval produced %d provider reads", provider.statusReads)
	}
	if counts.orders != 0 || counts.safeOrders != 0 || counts.keyRegistrars != 0 {
		t.Fatalf("the approval journey caused provider writes: orders=%d safe=%d keys=%d",
			counts.orders, counts.safeOrders, counts.keyRegistrars)
	}
}

// TestPortalApprovalBeforeProviderAddressIsSupported is the consumer-side control
// for the state the saved path exists for: a confirmed, recorded order the provider
// has not yet addressed. The portal approves it now; the panel owns the job and
// discovers the address and provider identity on a later pass, so the approving
// browser can close.
//
// Nothing here is faked on the backend side: the real router, the real SQLite file
// and the real tracker are driven, and the fake provider only stands in for the
// remote API. The assertions are exactly the two facts the portal relies on - the
// approval succeeds with no address, and the worker picks the address up later
// without any further request from the administrator.
func TestPortalApprovalBeforeProviderAddressIsSupported(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	// A real placed order with a real provider order id, still provisioning: no
	// public address and no nexus server id yet.
	seedPlacedOrder(t, h, "ord_portal_noip", 0, "")
	if err := db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID:    "ord_portal_noip",
		PrivateKey: "FIXTURE-PRIVATE-MATERIAL-NOT-A-KEY",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
	}); err != nil {
		t.Fatalf("seed managed credential: %v", err)
	}

	counts := &providerCallCounts{}
	h.SetGigahostClient(&countingProvider{counts: counts})
	r := setupIntentTestRouter(t, h)

	// The approval must be accepted while there is nothing to install on yet.
	started := time.Now()
	code, body := portalApproval(t, r, "ord_portal_noip", "awg")
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("approval took %s: it must not wait for an address", elapsed)
	}
	if code != http.StatusAccepted {
		t.Fatalf("approve = %d, want 202 (body: %v)", code, body)
	}
	if created, _ := body["created"].(bool); !created {
		t.Fatal("approval reported created=false on its first request")
	}
	setup, ok := body["setup"].(map[string]any)
	if !ok {
		t.Fatalf("response has no setup object: %v", body)
	}
	// Both fields are omitted from the DTO when unset, which is exactly the state
	// the approval recorded: no address and no provider server id yet.
	if ip, present := setup["assigned_ip"]; present {
		t.Fatalf("assigned_ip = %v, want absent: no address had been assigned", ip)
	}
	if sid, present := setup["provider_server_id"]; present {
		t.Fatalf("provider_server_id = %v, want absent before the provider assigns one", sid)
	}
	if setup["state"] != models.SetupStatePending {
		t.Fatalf("state = %v, want %q", setup["state"], models.SetupStatePending)
	}

	// The approving request is over. A restarted panel builds its worker over the
	// same database and a fake provider; no further request from the administrator
	// is made in this test.
	restarted := newApprovalConsumerHandlers(t, db)
	clock := &virtualClock{now: time.Now().UTC()}
	provider := &trackerFakeProvider{}
	tracker, challengedFn := newPortalTracker(t, db, provider, clock)

	// Six passes, ten virtual minutes apart: an hour of provisioning with no address.
	for i := 0; i < 6; i++ {
		if err := tracker.RunOnce(context.Background()); err != nil {
			t.Fatalf("tracking pass %d: %v", i, err)
		}
		saved, found, err := db.GetGigahostSetupIntent(context.Background(), "ord_portal_noip")
		if err != nil || !found {
			t.Fatalf("read intent after pass %d: found=%v err=%v", i, found, err)
		}
		if saved.State != models.SetupStatePending {
			t.Fatalf("pass %d: state = %q, want %q while provisioning (detail %q)",
				i, saved.State, models.SetupStatePending, saved.LastError)
		}
		if saved.AssignedIP != "" || saved.ProviderServerID != 0 {
			t.Fatalf("pass %d: identity = %q/%d, want none before the provider assigns it",
				i, saved.AssignedIP, saved.ProviderServerID)
		}
		clock.Advance(10 * time.Minute)
	}

	// The provider now reports the address and server identity. The worker learns
	// both from that read alone and stops at the trust pause with the identity it
	// observed - it authorizes nothing on its own.
	provider.ready = true
	if err := tracker.RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass after readiness: %v", err)
	}
	saved, found, err := db.GetGigahostSetupIntent(context.Background(), "ord_portal_noip")
	if err != nil || !found {
		t.Fatalf("read intent: found=%v err=%v", found, err)
	}
	if saved.AssignedIP != "198.51.100.20" || saved.ProviderServerID != 7777 {
		t.Fatalf("discovered identity = %q/%d, want 198.51.100.20/7777",
			saved.AssignedIP, saved.ProviderServerID)
	}
	if saved.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want %q (detail %q)",
			saved.State, models.SetupStateAwaitingHostConfirm, saved.LastError)
	}
	if challengedFn() != 1 {
		t.Fatalf("host challenges = %d, want 1", challengedFn())
	}
	const observed = "SHA256:REREREREREREREREREREREREREREREREREREREREREQ"
	if saved.HostCandidateFingerprint != observed {
		t.Fatalf("displayed candidate = %q, want %q", saved.HostCandidateFingerprint, observed)
	}

	// Confirming the displayed value from the saved list - the same round trip an
	// administrator performs in another browser - advances the job.
	code, body = doJSON(t, setupIntentTestRouter(t, restarted), http.MethodPost,
		"/api/admin/hosting/gigahost/orders/ord_portal_noip/setup-host-confirmation",
		map[string]any{"fingerprint": observed})
	if code != http.StatusOK {
		t.Fatalf("host confirmation = %d, want 200 (body: %v)", code, body)
	}
	if err := tracker.RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass after confirmation: %v", err)
	}
	saved, found, err = db.GetGigahostSetupIntent(context.Background(), "ord_portal_noip")
	if err != nil || !found {
		t.Fatalf("read intent after confirmation: found=%v err=%v", found, err)
	}
	if saved.State != models.SetupStateReadyForSetup {
		t.Fatalf("state = %q, want %q (detail %q)",
			saved.State, models.SetupStateReadyForSetup, saved.LastError)
	}

	// Approving before an address existed bought and registered nothing.
	if counts.orders != 0 || counts.safeOrders != 0 || counts.keyRegistrars != 0 {
		t.Fatalf("the addressless journey caused provider writes: orders=%d safe=%d keys=%d",
			counts.orders, counts.safeOrders, counts.keyRegistrars)
	}
	if provider.orders != 0 || provider.keyRegistrations != 0 {
		t.Fatalf("the worker caused provider writes: orders=%d keys=%d",
			provider.orders, provider.keyRegistrations)
	}
}

// newPortalTracker builds the worker a restarted panel would build over the same
// database: a fake provider, a virtual clock and a host challenge that answers with
// a fixed identity. It returns the tracker plus a counter of how many times that
// challenge ran, because "the panel observed the identity exactly once" is a claim
// both consumer tests make.
func newPortalTracker(
	t *testing.T, db *database.DB, provider *trackerFakeProvider, clock *virtualClock,
) (*gigahostsetup.Tracker, func() int) {
	t.Helper()
	var mu sync.Mutex
	challenged := 0
	tracker := gigahostsetup.New(db, gigahostsetup.Options{
		Resolve: func(context.Context) (gigahostsetup.ProviderReader, error) { return provider, nil },
		ChallengeHost: func(context.Context, models.GigahostSetupIntent) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			challenged++
			return "SHA256:REREREREREREREREREREREREREREREREREREREREREQ", nil
		},
		Now:         clock.Now,
		Interval:    5 * time.Minute,
		FailureBack: time.Minute,
		MaxBackoff:  time.Hour,
		Batch:       10,
		CallTimeout: 5 * time.Second,
	})
	return tracker, func() int {
		mu.Lock()
		defer mu.Unlock()
		return challenged
	}
}

// virtualClock is an explicit clock for the tracker, so a long provisioning
// window is advanced rather than waited out.
type virtualClock struct{ now time.Time }

func (c *virtualClock) Now() time.Time { return c.now }

func (c *virtualClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// trackerFakeProvider is the fake the tracker drives: it reports provisioning
// until ready is set, then a ready server with an identity. It counts the reads
// the tracker is allowed and the writes it must never perform.
type trackerFakeProvider struct {
	ready            bool
	statusReads      int
	serverReads      int
	orders           int
	keyRegistrations int
}

func (p *trackerFakeProvider) GetDeployStatus(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
	p.statusReads++
	if !p.ready {
		return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusDeploying, Progress: 25}, nil
	}
	return &gigahost.DeployStatusResponse{
		OrderID: orderID, Status: gigahost.StatusReady,
		ServerID: 7777, AssignedIP: "198.51.100.20",
	}, nil
}

func (p *trackerFakeProvider) GetServers(context.Context) ([]gigahost.ServerInfo, error) {
	p.serverReads++
	return nil, nil
}
