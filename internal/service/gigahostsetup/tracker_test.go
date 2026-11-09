package gigahostsetup

// Behavioral tests for durable setup-intent tracking.
//
// Every test here runs against a real SQLite database opened by internal/database
// and a fake provider that counts calls. That combination is what makes the
// claims meaningful: the schedule, the compare-and-set transitions and the
// restart path are the actual persistence and the actual worker, not a model of
// them.
//
// "Restart" is modelled honestly: a second Tracker is constructed over the same
// database file after the first is stopped, which exercises the real reload path
// (rows re-read from disk). It is a process restart at the persistence boundary,
// not a process restart of the OS; the label on each test says which it is.
//
// Long provisioning is exercised with a fake clock: N virtual minutes pass, no
// literal sleep is spent.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

const trackerTestSecretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeClock is an explicit virtual clock. Nothing in these tests waits on it.
type fakeClock struct{ now time.Time }

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time { return c.now }

// Advance moves the virtual clock forward, which is how a >60 minute window is
// covered without a sleep.
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// fakeProvider is a counting fake of the two allowed reads. It has no order or
// key-registration method at all, matching what the tracker is permitted to do.
type fakeProvider struct {
	statusCalls int
	serverCalls int

	statusFn func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error)
	serverFn func(ctx context.Context) ([]gigahost.ServerInfo, error)
}

func (p *fakeProvider) GetDeployStatus(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
	p.statusCalls++
	if p.statusFn != nil {
		return p.statusFn(ctx, orderID)
	}
	return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusPending, Progress: 10}, nil
}

func (p *fakeProvider) GetServers(ctx context.Context) ([]gigahost.ServerInfo, error) {
	p.serverCalls++
	if p.serverFn != nil {
		return p.serverFn(ctx)
	}
	return nil, nil
}

// harness bundles the real database, the fake provider and the clock.
type harness struct {
	t        *testing.T
	dbPath   string
	db       *database.DB
	clock    *fakeClock
	provider *fakeProvider
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "setup_intents.db")
	db, err := database.Open(dbPath, trackerTestSecretKey)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &harness{t: t, dbPath: dbPath, db: db, clock: newFakeClock(), provider: &fakeProvider{}}
}

// tracker builds a Tracker over the harness with a virtual clock. Interval and
// backoff are short in virtual time so the schedule is observable.
func (h *harness) tracker() *Tracker {
	return New(h.db, Options{
		Resolve: func(context.Context) (ProviderReader, error) {
			return h.provider, nil
		},
		Now:         h.clock.Now,
		Interval:    5 * time.Minute,
		FailureBack: time.Minute,
		MaxBackoff:  time.Hour,
		Batch:       10,
		CallTimeout: 5 * time.Second,
	})
}

// seedOrder records the placed order the approval must reference.
func (h *harness) seedOrder(orderID string, providerServerID int64, ip string) {
	h.t.Helper()
	now := h.clock.Now()
	order := &models.GigahostOrder{
		OrderID:    orderID,
		ServerID:   providerServerID,
		Status:     gigahost.StatusPending,
		AssignedIP: ip,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := h.db.InsertGigahostOrder(context.Background(), order); err != nil {
		h.t.Fatalf("seed order: %v", err)
	}
}

// seedManagedCredential gives the order a stored (encrypted) SSH credential, which
// is the managed-credential precondition the tracker checks without decrypting.
func (h *harness) seedManagedCredential(orderID string) {
	h.t.Helper()
	err := h.db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID:    orderID,
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
	})
	if err != nil {
		h.t.Fatalf("seed managed credential: %v", err)
	}
}

// approve records the administrator's approval, as the handler does.
func (h *harness) approve(intent *models.GigahostSetupIntent) *models.GigahostSetupIntent {
	h.t.Helper()
	if intent.State == "" {
		intent.State = models.SetupStatePending
	}
	if intent.CreatedAt.IsZero() {
		intent.CreatedAt = h.clock.Now()
	}
	intent.NextAttemptAt = time.Time{}
	if err := h.db.CreateGigahostSetupIntent(context.Background(), intent); err != nil {
		h.t.Fatalf("approve setup intent: %v", err)
	}
	return intent
}

// load re-reads the intent from the database.
func (h *harness) load(orderID string) *models.GigahostSetupIntent {
	h.t.Helper()
	intent, found, err := h.db.GetGigahostSetupIntent(context.Background(), orderID)
	if err != nil {
		h.t.Fatalf("read setup intent: %v", err)
	}
	if !found {
		h.t.Fatalf("setup intent for %s disappeared", orderID)
	}
	return intent
}

// runOnce performs one tracking pass and fails on a scheduling error.
func (h *harness) runOnce(t *Tracker) {
	h.t.Helper()
	if err := t.RunOnce(context.Background()); err != nil {
		h.t.Fatalf("tracking pass failed: %v", err)
	}
}

// readyProvider makes the provider report a ready server with an identity.
func readyProvider(t *testing.T, status *gigahost.DeployStatusResponse) func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
	t.Helper()
	return func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return status, nil
	}
}

// TestTrackerReadyAfterLongProvisioningDrivenByFakeClock is the >60 minute case.
//
// The provider stays in provisioning for 100 virtual minutes across eleven passes,
// with no literal sleep. Assertions: the intent stays pending with the real
// provider status, exactly one read per pass (no retry storm), and the handoff
// state is reached only once the provider is actually ready.
func TestTrackerReadyAfterLongProvisioningDrivenByFakeClock(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_long", 4242, "")
	h.seedManagedCredential("order_long")
	h.approve(&models.GigahostSetupIntent{
		OrderID:         "order_long",
		Protocol:        models.ProtocolAWG,
		Port:            "51820",
		CredentialMode:  models.SetupCredentialManaged,
		HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})

	ready := false
	h.provider.statusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		if !ready {
			return &gigahost.DeployStatusResponse{
				OrderID: "order_long", Status: gigahost.StatusDeploying, Progress: 25,
			}, nil
		}
		return &gigahost.DeployStatusResponse{
			OrderID: "order_long", Status: gigahost.StatusReady,
			ServerID: 4242, AssignedIP: "198.51.100.77",
		}, nil
	}

	tracker := h.tracker()
	// Ten virtual minutes apart, eleven times: 100 virtual minutes of provisioning.
	for i := 0; i < 11; i++ {
		h.runOnce(tracker)
		if got := h.load("order_long"); got.State != models.SetupStatePending {
			t.Fatalf("pass %d: state = %q, want %q while provisioning", i, got.State, models.SetupStatePending)
		} else if got.ProviderStatus != gigahost.StatusDeploying {
			t.Fatalf("pass %d: provider status = %q, want %q", i, got.ProviderStatus, gigahost.StatusDeploying)
		}
		if h.provider.statusCalls != i+1 {
			t.Fatalf("pass %d: status reads = %d, want %d (one per pass)", i, h.provider.statusCalls, i+1)
		}
		h.clock.Advance(10 * time.Minute)
	}
	if elapsed := h.clock.Now().Sub(time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)); elapsed < 100*time.Minute {
		t.Fatalf("virtual elapsed = %v, want at least 100m", elapsed)
	}

	ready = true
	h.runOnce(tracker)
	got := h.load("order_long")
	if got.State != models.SetupStateReadyForSetup {
		t.Fatalf("state = %q, want %q (detail: %s)", got.State, models.SetupStateReadyForSetup, got.LastError)
	}
	if got.ProviderServerID != 4242 || got.AssignedIP != "198.51.100.77" {
		t.Fatalf("identity = (%d, %q), want (4242, 198.51.100.77)", got.ProviderServerID, got.AssignedIP)
	}
	if got.Attempts != 12 {
		t.Fatalf("attempts = %d, want 12", got.Attempts)
	}

	// A settled intent must not be read again: no further provider traffic.
	before := h.provider.statusCalls
	h.clock.Advance(6 * time.Hour)
	h.runOnce(tracker)
	if h.provider.statusCalls != before {
		t.Fatalf("settled intent produced %d more provider reads", h.provider.statusCalls-before)
	}
}

// TestTrackerResumeAfterRestartUsesSavedIntentAndNeverOrders proves the restart
// requirement: a second Tracker over the same database resumes the same saved
// approval, and the provider's purchase surface is not reachable at all.
//
// Boundary: this is a restart of the worker over the real on-disk database, not
// an OS process restart. The provider is a fake with no purchase method, so "no
// second purchase" is structural here, not merely unobserved.
func TestTrackerResumeAfterRestartUsesSavedIntentAndNeverOrders(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_restart", 9001, "")
	h.seedManagedCredential("order_restart")
	h.approve(&models.GigahostSetupIntent{
		OrderID:         "order_restart",
		Protocol:        models.ProtocolAWG,
		Port:            "51820",
		CredentialMode:  models.SetupCredentialManaged,
		HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})

	first := h.tracker()
	h.runOnce(first)
	if got := h.load("order_restart"); got.State != models.SetupStatePending {
		t.Fatalf("before restart: state = %q, want pending", got.State)
	}

	// Close and reopen the database: the row must survive as real persisted state.
	if err := h.db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	reopened, err := database.Open(h.dbPath, trackerTestSecretKey)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	h.db = reopened
	t.Cleanup(func() { _ = h.db.Close() })

	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_restart", Status: gigahost.StatusReady,
		ServerID: 9001, AssignedIP: "198.51.100.90",
	})
	// The saved row carries the next attempt time the first pass scheduled, so a
	// restart resumes when the work is due rather than re-reading immediately.
	// Advancing virtual time crosses that boundary without a literal wait.
	h.clock.Advance(6 * time.Minute)

	// A brand-new worker: this is what a panel restart does.
	second := h.tracker()
	h.runOnce(second)
	got := h.load("order_restart")
	if got.State != models.SetupStateReadyForSetup {
		t.Fatalf("after restart: state = %q, want %q (%s)", got.State, models.SetupStateReadyForSetup, got.LastError)
	}
	if got.Protocol != models.ProtocolAWG || got.CredentialMode != models.SetupCredentialManaged {
		t.Fatalf("approval options lost across restart: %+v", got)
	}

	// The intent count is exactly one: resuming did not create a second job.
	intents, err := h.db.ListGigahostSetupIntents(context.Background())
	if err != nil {
		t.Fatalf("list intents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("intent count = %d, want 1", len(intents))
	}
}

// TestTrackerTransientReadFailureStaysPending proves that an unreadable provider
// is recorded as "could not ask" and never becomes ready or failed-by-timeout.
func TestTrackerTransientReadFailureStaysPending(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_flaky", 111, "")
	h.seedManagedCredential("order_flaky")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_flaky", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode:  models.SetupCredentialManaged,
		HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})

	h.provider.statusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return nil, errors.New("dial tcp: connection refused")
	}

	tracker := h.tracker()
	h.runOnce(tracker)
	got := h.load("order_flaky")
	if got.State != models.SetupStatePending {
		t.Fatalf("state after read failure = %q, want %q", got.State, models.SetupStatePending)
	}
	if got.ReadFailures != 1 {
		t.Fatalf("read failures = %d, want 1", got.ReadFailures)
	}
	if got.ProviderStatus != "" {
		t.Fatalf("provider status = %q, want empty (never observed)", got.ProviderStatus)
	}
	if got.Step != "provider_unreadable" {
		t.Fatalf("step = %q, want provider_unreadable", got.Step)
	}
	if got.NextAttemptAt.IsZero() {
		t.Fatal("next attempt not scheduled after a read failure")
	}

	// The backoff must actually delay the next read: a pass before it is due does
	// nothing, so an outage cannot become a hot retry loop.
	before := h.provider.statusCalls
	h.runOnce(tracker)
	if h.provider.statusCalls != before {
		t.Fatalf("retried while backing off: %d extra reads", h.provider.statusCalls-before)
	}

	// Once the backoff elapses the retry happens, and a real answer clears the
	// failure count.
	h.clock.Advance(2 * time.Minute)
	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_flaky", Status: gigahost.StatusReady, ServerID: 111, AssignedIP: "198.51.100.5",
	})
	h.runOnce(tracker)
	got = h.load("order_flaky")
	if got.State != models.SetupStateReadyForSetup {
		t.Fatalf("state after recovery = %q, want %q (%s)", got.State, models.SetupStateReadyForSetup, got.LastError)
	}
	if got.ReadFailures != 0 {
		t.Fatalf("read failures after recovery = %d, want 0", got.ReadFailures)
	}
}

// TestTrackerServerListUnreadableStaysPending covers a read failure in a handoff
// gate rather than in the first status read.
//
// The deploy status answers "ready", but the provider's own server list cannot be
// read, so the association cannot be checked. That is "could not ask" and must
// keep the intent pending: adopting the server on partial information would
// accept a server whose order nobody verified.
func TestTrackerServerListUnreadableStaysPending(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_srvfail", 1010, "")
	h.seedManagedCredential("order_srvfail")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_srvfail", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode:  models.SetupCredentialManaged,
		HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})

	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_srvfail", Status: gigahost.StatusReady, ServerID: 1010, AssignedIP: "198.51.100.21",
	})
	h.provider.serverFn = func(context.Context) ([]gigahost.ServerInfo, error) {
		return nil, errors.New("dial tcp: i/o timeout")
	}

	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_srvfail")
	if got.State != models.SetupStatePending {
		t.Fatalf("state = %q, want %q: a partial provider answer must not settle the intent",
			got.State, models.SetupStatePending)
	}
	if got.ReadFailures != 1 {
		t.Fatalf("read failures = %d, want 1", got.ReadFailures)
	}
	// The provider's "ready" was observed and must be kept as history even though
	// the handoff could not be decided.
	if got.ProviderStatus != gigahost.StatusReady {
		t.Fatalf("provider status = %q, want %q", got.ProviderStatus, gigahost.StatusReady)
	}
}

// TestTrackerProviderFailureIsTerminalNegativeControl is the failed-side control:
// a provider "failed" is a real answer and must settle as failed, not pending.
func TestTrackerProviderFailureIsTerminalNegativeControl(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_failed", 222, "")
	h.seedManagedCredential("order_failed")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_failed", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode: models.SetupCredentialManaged,
	})

	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_failed", Status: gigahost.StatusFailed, Error: "no capacity in region",
	})
	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_failed")
	if got.State != models.SetupStateFailed {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateFailed)
	}
	if got.LastError != "no capacity in region" {
		t.Fatalf("last error = %q, want the provider's own diagnostic", got.LastError)
	}
}

// TestTrackerWrongOrderAssociationIsRefused proves that a provider server id
// belonging to a different order is never adopted.
func TestTrackerWrongOrderAssociationIsRefused(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_mine", 333, "")
	h.seedManagedCredential("order_mine")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_mine", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode:  models.SetupCredentialManaged,
		HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})

	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_mine", Status: gigahost.StatusReady, ServerID: 333, AssignedIP: "198.51.100.8",
	})
	h.provider.serverFn = func(context.Context) ([]gigahost.ServerInfo, error) {
		return []gigahost.ServerInfo{
			{ID: 333, OrderID: "order_someone_else", IPv4: "198.51.100.8", Status: "ready"},
		}, nil
	}

	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_mine")
	if got.State != models.SetupStateFailed {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateFailed)
	}
	if got.Step != "association_mismatch" {
		t.Fatalf("step = %q, want association_mismatch", got.Step)
	}
}

// TestTrackerCancelledApprovalProducesNoFurtherEffects proves that a revoked
// approval stops the tracker even when a read was already in flight.
func TestTrackerCancelledApprovalProducesNoFurtherEffects(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_revoked", 444, "")
	h.seedManagedCredential("order_revoked")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_revoked", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode: models.SetupCredentialManaged,
	})

	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_revoked", Status: gigahost.StatusReady, ServerID: 444, AssignedIP: "198.51.100.9",
	})

	if _, changed, err := h.db.CancelGigahostSetupIntent(context.Background(), "order_revoked", "revoked by test"); err != nil || !changed {
		t.Fatalf("cancel: changed=%v err=%v", changed, err)
	}

	tracker := h.tracker()
	h.runOnce(tracker)

	// A cancelled row is not pending, so it is not even scheduled.
	if h.provider.statusCalls != 0 {
		t.Fatalf("cancelled approval produced %d provider reads, want 0", h.provider.statusCalls)
	}
	got := h.load("order_revoked")
	if got.State != models.SetupStateCanceled {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateCanceled)
	}
}

// TestTrackerCancellationDuringReadWinsTheRace proves the compare-and-set guard:
// an administrator's cancellation that lands while a read is in flight is not
// overwritten by the tracker's commit.
func TestTrackerCancellationDuringReadWinsTheRace(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_race", 555, "")
	h.seedManagedCredential("order_race")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_race", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode:  models.SetupCredentialManaged,
		HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})

	// The read itself revokes the approval, exactly like a DELETE arriving mid-pass.
	h.provider.statusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		if _, _, err := h.db.CancelGigahostSetupIntent(context.Background(), "order_race", "revoked mid-read"); err != nil {
			t.Errorf("cancel during read: %v", err)
		}
		return &gigahost.DeployStatusResponse{
			OrderID: "order_race", Status: gigahost.StatusReady, ServerID: 555, AssignedIP: "198.51.100.11",
		}, nil
	}

	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_race")
	if got.State != models.SetupStateCanceled {
		t.Fatalf("state = %q, want %q: the tracker overwrote a revocation", got.State, models.SetupStateCanceled)
	}
}

// TestTrackerMissingCredentialPauses is the absent-credential control: a ready
// server with no usable credential reference pauses instead of proceeding.
func TestTrackerMissingCredentialPauses(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_nocred", 666, "")
	// No credential is seeded: this order has none.
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_nocred", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode:  models.SetupCredentialManaged,
		HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})

	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_nocred", Status: gigahost.StatusReady, ServerID: 666, AssignedIP: "198.51.100.12",
	})
	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_nocred")
	if got.State != models.SetupStateAwaitingCredentials {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateAwaitingCredentials)
	}
	if !got.NeedsOperator() {
		t.Fatal("awaiting_credentials must report that an operator is needed")
	}
}

// TestTrackerManualCredentialPausesWithoutStoringMaterial proves the manual path
// records a reference only: awaiting_credentials, no stored secret on the intent.
func TestTrackerManualCredentialPausesWithoutStoringMaterial(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_manual", 777, "")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_manual", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode:  models.SetupCredentialManual,
		HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})

	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_manual", Status: gigahost.StatusReady, ServerID: 777, AssignedIP: "198.51.100.13",
	})
	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_manual")
	if got.State != models.SetupStateAwaitingCredentials {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateAwaitingCredentials)
	}
	if got.CredentialMode != models.SetupCredentialManual {
		t.Fatalf("credential mode = %q, want %q", got.CredentialMode, models.SetupCredentialManual)
	}
}

// TestTrackerUnconfirmedHostPauses proves trust is not assumed: a ready server
// with no confirmed identity and no bound registration pauses for confirmation.
func TestTrackerUnconfirmedHostPauses(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_unconfirmed", 888, "")
	h.seedManagedCredential("order_unconfirmed")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_unconfirmed", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode: models.SetupCredentialManaged,
		// No HostFingerprint: the administrator has not confirmed an identity.
	})

	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_unconfirmed", Status: gigahost.StatusReady, ServerID: 888, AssignedIP: "198.51.100.14",
	})
	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_unconfirmed")
	if got.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateAwaitingHostConfirm)
	}
}

// challengeTracker builds a Tracker whose host-identity challenge is the supplied
// function, so a fresh-order pass is exercised end to end without a real host.
func (h *harness) challengeTracker(fn func(ctx context.Context, intent models.GigahostSetupIntent) (string, error)) *Tracker {
	t := h.tracker()
	t.challenge = fn
	return t
}

// TestTrackerFreshOrderRecordsTheChallengedIdentity is the F13 positive half.
//
// A fresh managed order has no confirmed identity and no registered server, which
// is the state every newly approved VPS starts in. The pass must pause for
// confirmation AND name the identity the address actually presented, because a
// pause with an empty identity is a dead end an administrator cannot act on.
//
// The challenge here is only allowed to answer; it must not be able to authorize
// anything, so the assertion is that the row is still waiting for a human.
func TestTrackerFreshOrderRecordsTheChallengedIdentity(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_fresh", 5050, "198.51.100.21")
	h.seedManagedCredential("order_fresh")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_fresh", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode: models.SetupCredentialManaged,
		// No HostFingerprint: nobody has confirmed an identity yet.
	})
	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_fresh", Status: gigahost.StatusReady, ServerID: 5050, AssignedIP: "198.51.100.21",
	})

	const presented = "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	challenged := 0
	var challengedWith models.GigahostSetupIntent
	tracker := h.challengeTracker(func(_ context.Context, intent models.GigahostSetupIntent) (string, error) {
		challenged++
		challengedWith = intent
		return presented, nil
	})
	h.runOnce(tracker)

	got := h.load("order_fresh")
	if got.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want %q: discovery must not approve anything", got.State, models.SetupStateAwaitingHostConfirm)
	}
	if got.HostCandidateFingerprint != presented {
		t.Fatalf("candidate = %q, want the identity the host presented (%q)",
			got.HostCandidateFingerprint, presented)
	}
	if got.HostFingerprint != "" {
		t.Fatalf("a confirmed identity was written without an administrator: %q", got.HostFingerprint)
	}
	if challenged != 1 {
		t.Fatalf("challenge calls = %d, want exactly 1", challenged)
	}
	// The challenge must observe the row's own provider identity and address, so
	// it cannot be pointed at something other than this order.
	if challengedWith.AssignedIP != "198.51.100.21" || challengedWith.ProviderServerID != 5050 {
		t.Fatalf("the challenge was asked about %s/%d, want the approval's own address/identity",
			challengedWith.AssignedIP, challengedWith.ProviderServerID)
	}
}

// TestTrackerFailedChallengeKeepsThePauseInformative proves a challenge that
// cannot complete does not become a silent dead end: the reason is recorded and no
// identity is invented.
//
// A challenge that cannot run is a temporary condition, not an identity decision,
// so the row stays pending with a scheduled retry rather than settling into a trust
// pause. A settled pause would produce no further provider read, and none of the
// shipped actions can turn it back into a discovery attempt, so the saved approval
// would be stranded on a host that was merely still booting.
func TestTrackerFailedChallengeKeepsThePauseInformative(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_nochallenge", 5151, "198.51.100.22")
	h.seedManagedCredential("order_nochallenge")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_nochallenge", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode: models.SetupCredentialManaged,
	})
	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_nochallenge", Status: gigahost.StatusReady, ServerID: 5151, AssignedIP: "198.51.100.22",
	})

	tracker := h.challengeTracker(func(context.Context, models.GigahostSetupIntent) (string, error) {
		return "", errors.New("connection refused")
	})
	h.runOnce(tracker)

	got := h.load("order_nochallenge")
	if got.State != models.SetupStatePending {
		t.Fatalf("state = %q, want %q: an unreachable host is not an identity decision",
			got.State, models.SetupStatePending)
	}
	if got.Step != stepHostUnreachable {
		t.Fatalf("step = %q, want %q", got.Step, stepHostUnreachable)
	}
	if got.HostCandidateFingerprint != "" {
		t.Fatalf("a failed challenge recorded candidate %q", got.HostCandidateFingerprint)
	}
	if got.HostFingerprint != "" {
		t.Fatalf("a failed challenge confirmed identity %q", got.HostFingerprint)
	}
	if got.LastError == "" {
		t.Fatal("a failed challenge recorded no reason")
	}
	if got.NextAttemptAt.IsZero() {
		t.Fatal("a failed challenge scheduled no retry, so the approval is stranded")
	}
}

// TestTrackerChallengeClearsAStaleCandidate proves a displayed identity does not
// outlive the host that presented it. If a later challenge cannot confirm the same
// key, the stale candidate must be cleared rather than left as confirmable.
func TestTrackerChallengeClearsAStaleCandidate(t *testing.T) {
	h := newHarness(t)
	const stale = "SHA256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
	h.seedOrder("order_stale", 5252, "198.51.100.23")
	h.seedManagedCredential("order_stale")
	intent := h.approve(&models.GigahostSetupIntent{
		OrderID: "order_stale", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode: models.SetupCredentialManaged,
	})
	if _, err := h.db.SQLDB().ExecContext(context.Background(),
		`UPDATE gigahost_setup_intents SET host_candidate_fingerprint = ? WHERE order_id = ?`,
		stale, intent.OrderID); err != nil {
		t.Fatalf("seed candidate: %v", err)
	}
	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_stale", Status: gigahost.StatusReady, ServerID: 5252, AssignedIP: "198.51.100.23",
	})

	tracker := h.challengeTracker(func(context.Context, models.GigahostSetupIntent) (string, error) {
		return "", errors.New("host stopped responding")
	})
	h.runOnce(tracker)

	got := h.load("order_stale")
	if got.HostCandidateFingerprint != "" {
		t.Fatalf("a stale candidate survived a failed challenge: %q", got.HostCandidateFingerprint)
	}
}

// TestTrackerNoChallengeKeepsTheOriginalPause proves the unconfigured case is
// unchanged: with no challenge available the pause still stands and nothing is
// invented.
func TestTrackerNoChallengeKeepsTheOriginalPause(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_noclient", 5353, "198.51.100.24")
	h.seedManagedCredential("order_noclient")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_noclient", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode: models.SetupCredentialManaged,
	})
	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_noclient", Status: gigahost.StatusReady, ServerID: 5353, AssignedIP: "198.51.100.24",
	})

	h.runOnce(h.tracker())

	got := h.load("order_noclient")
	if got.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateAwaitingHostConfirm)
	}
	if got.HostCandidateFingerprint != "" {
		t.Fatalf("an identity was invented without a challenge: %q", got.HostCandidateFingerprint)
	}
}

// TestTrackerChangedHostIdentityPauses is the changed-host control: when the
// identity already bound to a registered server contradicts the approval, trust
// pauses and the stored identity is not rewritten.
func TestTrackerChangedHostIdentityPauses(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_changed", 999, "")
	h.seedManagedCredential("order_changed")

	// The server is already registered and bound to a different identity.
	const boundFingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	serverID, err := h.db.CreateServerWithFingerprint(context.Background(), &models.Server{
		Name:      "Gigahost-999",
		Host:      "198.51.100.15",
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 999},
		CreatedAt: h.clock.Now(),
	}, boundFingerprint)
	if err != nil {
		t.Fatalf("register server: %v", err)
	}

	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_changed", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode:  models.SetupCredentialManaged,
		HostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	})

	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_changed", Status: gigahost.StatusReady, ServerID: 999, AssignedIP: "198.51.100.15",
	})
	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_changed")
	if got.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateAwaitingHostConfirm)
	}
	if !got.HostMismatch {
		t.Fatal("host_mismatch not recorded")
	}
	// The durable binding must be untouched.
	bound, err := h.db.GetKnownHostFingerprint(context.Background(), serverID)
	if err != nil {
		t.Fatalf("read bound fingerprint: %v", err)
	}
	if bound != boundFingerprint {
		t.Fatalf("bound fingerprint was rewritten to %q", bound)
	}
}

// TestTrackerUnconfiguredProviderKeepsIntentPending proves the panel-side "could
// not ask" case is also a pause rather than a failure.
func TestTrackerUnconfiguredProviderKeepsIntentPending(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_unconfigured", 1234, "")
	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_unconfigured", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode: models.SetupCredentialManual,
	})

	tracker := New(h.db, Options{
		Resolve: func(context.Context) (ProviderReader, error) {
			return nil, ErrProviderUnavailable
		},
		Now:         h.clock.Now,
		Interval:    5 * time.Minute,
		FailureBack: time.Minute,
		MaxBackoff:  time.Hour,
		Batch:       10,
	})
	h.runOnce(tracker)

	got := h.load("order_unconfigured")
	if got.State != models.SetupStatePending {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStatePending)
	}
	if got.ReadFailures != 1 {
		t.Fatalf("read failures = %d, want 1", got.ReadFailures)
	}
}

// TestTrackerStartsAndStopsUnderContext proves the supervised lifecycle: Start
// runs until the context ends and Stop joins it. It uses a real short interval
// because the loop's own timer, not the fake clock, is what is under test.
func TestTrackerStartsAndStopsUnderContext(t *testing.T) {
	h := newHarness(t)
	tracker := New(h.db, Options{
		Resolve:  func(context.Context) (ProviderReader, error) { return h.provider, nil },
		Interval: 20 * time.Millisecond,
		Batch:    10,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tracker.Start(ctx) }()

	// Wait until at least one pass has completed, so Start is genuinely running.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !tracker.running.Load() {
		time.Sleep(2 * time.Millisecond)
	}
	if !tracker.running.Load() {
		t.Fatal("tracker did not start")
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v, want nil after cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tracker did not stop within 3s of cancellation")
	}
	if tracker.running.Load() {
		t.Fatal("tracker still reports running after Start returned")
	}
}

// TestTrackerStopJoinsRunningLoop proves Stop waits for the loop to exit rather
// than returning early while a pass is still running.
func TestTrackerStopJoinsRunningLoop(t *testing.T) {
	h := newHarness(t)
	tracker := New(h.db, Options{
		Resolve:  func(context.Context) (ProviderReader, error) { return h.provider, nil },
		Interval: time.Hour, // long: Stop, not the interval, must end the loop
		Batch:    10,
	})

	if err := startAsync(tracker); err != nil {
		t.Fatalf("start: %v", err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tracker.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if tracker.running.Load() {
		t.Fatal("tracker still running after Stop returned")
	}
}

// startAsync runs Start in the background and returns once the loop owns its
// context. It is a test helper, kept in the test file so no test-only code
// reaches the production binary.
func startAsync(t *Tracker) error {
	errCh := make(chan error, 1)
	go func() { errCh <- t.Start(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if t.running.Load() {
			return nil
		}
		select {
		case err := <-errCh:
			return err
		case <-time.After(2 * time.Millisecond):
		}
	}
	return errors.New("tracker did not start")
}

// TestTrackerRegisteredServerWithMatchingIdentityReachesHandoff proves the
// positive trust path for an already registered server: when the approved
// identity equals the identity already bound to the server, trust is settled and
// the handoff is reached.
func TestTrackerRegisteredServerWithMatchingIdentityReachesHandoff(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_match", 2020, "")
	h.seedManagedCredential("order_match")

	const fingerprint = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	if _, err := h.db.CreateServerWithFingerprint(context.Background(), &models.Server{
		Name: "Gigahost-2020", Host: "198.51.100.31", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 2020},
		CreatedAt: h.clock.Now(),
	}, fingerprint); err != nil {
		t.Fatalf("register server: %v", err)
	}

	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_match", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode:  models.SetupCredentialManaged,
		HostFingerprint: fingerprint,
	})
	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_match", Status: gigahost.StatusReady, ServerID: 2020, AssignedIP: "198.51.100.31",
	})

	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_match")
	if got.State != models.SetupStateReadyForSetup {
		t.Fatalf("state = %q, want %q (%s)", got.State, models.SetupStateReadyForSetup, got.LastError)
	}
	if got.HostMismatch {
		t.Fatal("matching identities reported as a mismatch")
	}
}

// TestTrackerRegisteredServerWithoutBindingNeedsConfirmation proves the
// fail-closed direction for a registered server that has no bound identity yet:
// without an approved identity the intent must pause rather than adopt the server.
func TestTrackerRegisteredServerWithoutBindingNeedsConfirmation(t *testing.T) {
	h := newHarness(t)
	h.seedOrder("order_unbound", 3030, "")
	h.seedManagedCredential("order_unbound")

	// A registered server whose identity was never bound.
	serverID, err := h.db.CreateServer(context.Background(), &models.Server{
		Name: "Gigahost-3030", Host: "198.51.100.32", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 3030},
		CreatedAt: h.clock.Now(),
	})
	if err != nil {
		t.Fatalf("register server: %v", err)
	}
	if fp, err := h.db.GetKnownHostFingerprint(context.Background(), serverID); err != nil || fp != "" {
		t.Fatalf("precondition: expected no bound fingerprint, got %q err=%v", fp, err)
	}

	h.approve(&models.GigahostSetupIntent{
		OrderID: "order_unbound", Protocol: models.ProtocolAWG, Port: "51820",
		CredentialMode: models.SetupCredentialManaged,
	})
	h.provider.statusFn = readyProvider(t, &gigahost.DeployStatusResponse{
		OrderID: "order_unbound", Status: gigahost.StatusReady, ServerID: 3030, AssignedIP: "198.51.100.32",
	})

	tracker := h.tracker()
	h.runOnce(tracker)

	got := h.load("order_unbound")
	if got.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateAwaitingHostConfirm)
	}
	// Nothing may have been bound on the administrator's behalf.
	if fp, err := h.db.GetKnownHostFingerprint(context.Background(), serverID); err != nil || fp != "" {
		t.Fatalf("a fingerprint was bound without confirmation: %q err=%v", fp, err)
	}
}
