package gigahostsetup

// First-contact automatic host trust: the durable primitive and the tracking
// decision.
//
// Every test here runs the real SQLite store and the real tracking pass. The
// provider and the read-only challenge are the two boundaries replaced, because
// they are the external systems; the pin statement, the compare-and-set transitions
// and the restart path are the production ones.
//
// What these tests prove and what they do not: they prove that exactly one identity
// becomes durable, that no later writer replaces it, and that a refusal never
// authorises anything. They do not prove that a real host presented the key - the
// challenge is a fake here - and that is proven separately against a real loopback
// SSH peer, where the number of authentication attempts and sessions is observable.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// firstContactFingerprintA and B are two distinct canonical SHA256 fingerprints.
// They are the strict unpadded base64 of real 32-byte digests, which is what the
// stored-identity validator requires.
const (
	firstContactFingerprintA = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	firstContactFingerprintB = "SHA256:ERERERERERERERERERERERERERERERERERERERERERE"
)

// firstContactTracker builds a tracker whose challenge answers with the supplied
// fingerprint and whose ownership check answers with the supplied verdict.
//
// The two seams are explicit arguments rather than harness defaults so every test
// states which half of the decision it is exercising. The current-policy gate is wired
// permissive here for the same reason the eligibility seam is: these tests are about the
// trust mechanics, and each test that cares about the policy passes its own gate in
// automaticEffectTracker below.
func (h *harness) firstContactTracker(
	fingerprint string,
	eligible func(ctx context.Context, intent models.GigahostSetupIntent) (bool, string),
) *Tracker {
	return New(h.db, Options{
		Resolve: func(context.Context) (ProviderReader, error) {
			return h.provider, nil
		},
		ChallengeHost: func(context.Context, models.GigahostSetupIntent) (string, error) {
			return fingerprint, nil
		},
		FirstContactEligible:   eligible,
		Pinner:                 h.db,
		AutomaticEffectAllowed: allowAllEffects,
		Now:                    h.clock.Now,
		Interval:               5 * time.Minute,
		FailureBack:            time.Minute,
		MaxBackoff:             time.Hour,
		Batch:                  10,
		CallTimeout:            5 * time.Second,
	})
}

// allowAllEligibility is the positive ownership answer: the test decides
// eligibility has already been established and exercises the trust mechanics.
func allowAllEligibility(context.Context, models.GigahostSetupIntent) (bool, string) {
	return true, ""
}

// allowAllEffects is the positive current-policy answer. Tests that exercise the policy
// pass their own gate instead.
func allowAllEffects(context.Context, models.GigahostSetupIntent) (bool, string) {
	return true, ""
}

// executeSQL applies a fixture statement to the ledger. It is used only to place a row in a
// state a real operator action or provider answer produces; the behaviour under test always
// runs through production code.
func (h *harness) executeSQL(query string, args ...any) {
	h.t.Helper()
	if _, err := h.db.SQLDB().ExecContext(context.Background(), query, args...); err != nil {
		h.t.Fatalf("fixture statement failed: %v", err)
	}
}

// grantBoundAuthority proves the ownership binding for this harness order and records it,
// exactly as the internal caller does: proof first, then the grant.
func (h *harness) grantBoundAuthority(orderID string, providerServerID int64) {
	h.t.Helper()
	ctx := context.Background()
	binding, err := h.db.ProveAutomationBinding(ctx, orderID, providerServerID)
	if err != nil {
		h.t.Fatalf("prove binding for %s: %v", orderID, err)
	}
	if _, changed, err := h.db.SetGigahostSetupAutomationBinding(ctx, binding); err != nil || !changed {
		h.t.Fatalf("grant bound authority for %s: changed=%v err=%v", orderID, changed, err)
	}
}

// seedFirstContactJob records a ready order that a first-contact pass can act on,
// grants it the automation policy through the real writer, and returns the intent.
func (h *harness) seedFirstContactJob(orderID string, providerServerID int64, ip string) *models.GigahostSetupIntent {
	h.t.Helper()
	h.seedOrder(orderID, providerServerID, ip)
	h.seedManagedCredential(orderID)
	h.provider.statusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID: orderID, Status: gigahost.StatusReady,
			ServerID: providerServerID, AssignedIP: ip,
		}, nil
	}
	h.provider.serverFn = func(context.Context) ([]gigahost.ServerInfo, error) {
		return []gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, IPv4: ip, Status: "ready"}}, nil
	}
	h.approve(&models.GigahostSetupIntent{
		OrderID:          orderID,
		ProviderServerID: providerServerID,
		AssignedIP:       ip,
		Protocol:         models.ProtocolAWG,
		Port:             "51820",
		CredentialMode:   models.SetupCredentialManaged,
	})
	h.grantBoundAuthority(orderID, providerServerID)
	return h.load(orderID)
}

// TestTrackerFirstContactPinsObservedIdentity is the positive tracking proof.
//
// An eligible job with the automation policy must settle at the install handoff with
// the identity the challenge observed recorded as durable trust, and with its
// provenance saying the panel pinned it - not that a person confirmed it.
func TestTrackerFirstContactPinsObservedIdentity(t *testing.T) {
	h := newHarness(t)
	h.seedFirstContactJob("ord_fc_positive", 5101, "198.51.100.11")

	h.runOnce(h.firstContactTracker(firstContactFingerprintA, allowAllEligibility))

	got := h.load("ord_fc_positive")
	if got.State != models.SetupStateReadyForSetup {
		t.Fatalf("state = %q, want %q (step %q, detail %q)",
			got.State, models.SetupStateReadyForSetup, got.Step, got.LastError)
	}
	if got.Step != stepHostTrustedFirstContact {
		t.Fatalf("step = %q, want %q", got.Step, stepHostTrustedFirstContact)
	}
	if got.HostFingerprint != firstContactFingerprintA {
		t.Fatalf("pinned identity = %q, want the observed %q", got.HostFingerprint, firstContactFingerprintA)
	}
	if got.HostTrustMode != models.SetupTrustModeFirstContact {
		t.Fatalf("trust provenance = %q, want %q", got.HostTrustMode, models.SetupTrustModeFirstContact)
	}
	if got.HostCandidateFingerprint != "" {
		t.Fatalf("the pinned identity was also left as a displayed candidate: %q", got.HostCandidateFingerprint)
	}
}

// TestTrackerFirstContactRestartKeepsThePin proves the pin is durable state, not a
// pass's memory: a brand-new tracker over a reopened database sees the same identity
// and proceeds without re-deciding trust.
func TestTrackerFirstContactRestartKeepsThePin(t *testing.T) {
	h := newHarness(t)
	h.seedFirstContactJob("ord_fc_restart", 5102, "198.51.100.12")
	h.runOnce(h.firstContactTracker(firstContactFingerprintA, allowAllEligibility))
	pinned := h.load("ord_fc_restart")
	if pinned.State != models.SetupStateReadyForSetup {
		t.Fatalf("precondition: state = %q, want %q (%s)", pinned.State, models.SetupStateReadyForSetup, pinned.LastError)
	}

	// A real reopen: the durable row must survive without the process that wrote it.
	if err := h.db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	reopened, err := database.Open(h.dbPath, trackerTestSecretKey)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	h.db = reopened
	t.Cleanup(func() { _ = h.db.Close() })

	after := h.load("ord_fc_restart")
	if after.HostFingerprint != firstContactFingerprintA || after.HostTrustMode != models.SetupTrustModeFirstContact {
		t.Fatalf("the pin did not survive the restart: identity=%q mode=%q",
			after.HostFingerprint, after.HostTrustMode)
	}
	if after.State != models.SetupStateReadyForSetup {
		t.Fatalf("state after restart = %q, want %q", after.State, models.SetupStateReadyForSetup)
	}

	// A new worker re-reads the row and finds the job already trusted, so it must
	// not run a discovery pass that could reach a changed host.
	challenges := 0
	second := New(h.db, Options{
		Resolve: func(context.Context) (ProviderReader, error) { return h.provider, nil },
		ChallengeHost: func(context.Context, models.GigahostSetupIntent) (string, error) {
			challenges++
			return firstContactFingerprintB, nil
		},
		FirstContactEligible: allowAllEligibility,
		Pinner:               h.db,
		Now:                  h.clock.Now,
		Interval:             5 * time.Minute,
		Batch:                10,
		CallTimeout:          5 * time.Second,
	})
	h.runOnce(second)
	if challenges != 0 {
		t.Fatalf("a job already at the install handoff was challenged again (%d challenges)", challenges)
	}
	if final := h.load("ord_fc_restart"); final.HostFingerprint != firstContactFingerprintA {
		t.Fatalf("the pin changed after a second worker: %q", final.HostFingerprint)
	}
}

// TestFirstContactPinIsFirstWriterWins is the concurrency control.
//
// Competing first-contact observations of the same job must produce exactly one
// durable binding. The losers are told the identity changed, which is a refusal, so
// no caller can mistake a lost race for a decision it made. Run with -race, this also
// proves the statement and its outcome read are not racy in-process.
func TestFirstContactPinIsFirstWriterWins(t *testing.T) {
	h := newHarness(t)
	h.seedFirstContactJob("ord_fc_race", 5103, "198.51.100.13")

	const writers = 8
	fingerprints := make([]string, writers)
	for i := 0; i < writers; i++ {
		if i%2 == 0 {
			fingerprints[i] = firstContactFingerprintA
		} else {
			fingerprints[i] = firstContactFingerprintB
		}
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		outcomes = map[string]int{}
	)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(fp string) {
			defer wg.Done()
			outcome, err := h.db.PinGigahostSetupFirstContact(context.Background(), "ord_fc_race", fp)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				outcomes["error"]++
				return
			}
			outcomes[outcome]++
		}(fingerprints[i])
	}
	wg.Wait()

	if outcomes[models.FirstContactPinned] != 1 {
		t.Fatalf("pinned outcomes = %d, want exactly 1 (%v)",
			outcomes[models.FirstContactPinned], outcomes)
	}
	stored := h.load("ord_fc_race").HostFingerprint
	if stored == "" {
		t.Fatal("no identity was pinned after the race")
	}
	// Every other writer must have been refused as a changed identity, never as a
	// second success: the stored value is the only one anybody may trust.
	wantLost := 0
	for _, fp := range fingerprints {
		if fp != stored {
			wantLost++
		}
	}
	if outcomes[models.FirstContactIdentityChanged] != wantLost {
		t.Fatalf("changed-identity refusals = %d, want %d (%v)",
			outcomes[models.FirstContactIdentityChanged], wantLost, outcomes)
	}
	if outcomes["error"] != 0 {
		t.Fatalf("the pin race produced %d errors; the store must answer, not fail", outcomes["error"])
	}
}

// TestFirstContactPinIsIdempotentForTheSameIdentity proves a repeated observation of
// the same key is the same answer, so a retried or duplicated pass cannot turn a
// correct state into a refusal.
func TestFirstContactPinIsIdempotentForTheSameIdentity(t *testing.T) {
	h := newHarness(t)
	h.seedFirstContactJob("ord_fc_idempotent", 5104, "198.51.100.14")

	for _, want := range []string{models.FirstContactPinned, models.FirstContactAlreadyPinnedSame} {
		got, err := h.db.PinGigahostSetupFirstContact(
			context.Background(), "ord_fc_idempotent", firstContactFingerprintA)
		if err != nil {
			t.Fatalf("pin: %v", err)
		}
		if got != want {
			t.Fatalf("pin outcome = %q, want %q", got, want)
		}
	}
	if stored := h.load("ord_fc_idempotent").HostFingerprint; stored != firstContactFingerprintA {
		t.Fatalf("stored identity = %q, want %q", stored, firstContactFingerprintA)
	}
}

// TestFirstContactPinRefusesAnIneligibleRow covers the durable half of the
// authority check: what the row itself must still say for a pin to be allowed.
//
// Each case is a row a caller could plausibly try to pin. None of them may record an
// identity, because none of them carries the authority to skip a person.
func TestFirstContactPinRefusesAnIneligibleRow(t *testing.T) {
	cases := []struct {
		name string
		// prepare places the row in the state under test and returns its order id.
		prepare func(t *testing.T, h *harness) string
	}{
		{
			name: "manual policy",
			prepare: func(t *testing.T, h *harness) string {
				h.seedOrder("ord_fc_manual", 5201, "198.51.100.21")
				h.seedManagedCredential("ord_fc_manual")
				h.approve(&models.GigahostSetupIntent{
					OrderID: "ord_fc_manual", ProviderServerID: 5201, AssignedIP: "198.51.100.21",
					Protocol: models.ProtocolAWG, Port: "51820",
					CredentialMode: models.SetupCredentialManaged,
				})
				return "ord_fc_manual"
			},
		},
		{
			name: "authority withdrawn before the pin",
			prepare: func(t *testing.T, h *harness) string {
				h.seedFirstContactJob("ord_fc_withdrawn", 5202, "198.51.100.22")
				// The ledger row stops being the panel's purchase, which is what the
				// binding re-proves at pin time: the authority no longer describes the
				// resource, so the pin must not happen.
				h.t.Helper()
				h.executeSQL(`UPDATE gigahost_orders SET purchase_origin = '' WHERE order_id = ?`, "ord_fc_withdrawn")
				return "ord_fc_withdrawn"
			},
		},
		{
			name: "revoked during the challenge",
			prepare: func(t *testing.T, h *harness) string {
				h.seedFirstContactJob("ord_fc_revoked", 5203, "198.51.100.23")
				if _, _, err := h.db.CancelGigahostSetupIntent(
					context.Background(), "ord_fc_revoked", "revoked by an administrator"); err != nil {
					t.Fatalf("cancel: %v", err)
				}
				return "ord_fc_revoked"
			},
		},
		{
			name: "already at the install handoff",
			prepare: func(t *testing.T, h *harness) string {
				h.seedFirstContactJob("ord_fc_claimed", 5204, "198.51.100.24")
				current := h.load("ord_fc_claimed")
				current.State = models.SetupStateReadyForSetup
				current.Step = "ready_for_setup"
				if _, err := h.db.TransitionGigahostSetupIntent(
					context.Background(), current, []string{models.SetupStatePending}); err != nil {
					t.Fatalf("place the row at the handoff: %v", err)
				}
				if got := h.load("ord_fc_claimed"); got.State != models.SetupStateReadyForSetup {
					t.Fatalf("precondition: state = %q", got.State)
				}
				return "ord_fc_claimed"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			orderID := tc.prepare(t, h)
			before := h.load(orderID)

			outcome, err := h.db.PinGigahostSetupFirstContact(
				context.Background(), orderID, firstContactFingerprintA)
			if err != nil {
				t.Fatalf("pin: %v", err)
			}
			if outcome != models.FirstContactNotEligible {
				t.Fatalf("pin outcome = %q, want %q", outcome, models.FirstContactNotEligible)
			}
			after := h.load(orderID)
			if after.HostFingerprint != "" || after.HostTrustMode != models.SetupTrustModeNone {
				t.Fatalf("an ineligible row was trusted: identity=%q mode=%q",
					after.HostFingerprint, after.HostTrustMode)
			}
			if after.State != before.State {
				t.Fatalf("the refused pin changed the state from %q to %q", before.State, after.State)
			}
		})
	}
}

// TestFirstContactPinRejectsAMalformedFingerprint proves the store refuses a value it
// could never re-verify, rather than recording trust that the handshake would then
// reject forever.
func TestFirstContactPinRejectsAMalformedFingerprint(t *testing.T) {
	h := newHarness(t)
	h.seedFirstContactJob("ord_fc_malformed", 5301, "198.51.100.31")

	for _, bad := range []string{
		"",
		"SHA256:",
		"MD5:aa:bb:cc",
		"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"SHA256:not-base64!",
	} {
		outcome, err := h.db.PinGigahostSetupFirstContact(context.Background(), "ord_fc_malformed", bad)
		if err == nil {
			t.Fatalf("fingerprint %q was accepted with outcome %q", bad, outcome)
		}
	}
	if stored := h.load("ord_fc_malformed").HostFingerprint; stored != "" {
		t.Fatalf("a malformed fingerprint was stored: %q", stored)
	}
}

// TestFirstContactIneligibleJobsKeepTheManualPause is the negative tracking proof.
//
// A job that cannot prove automatic authority must keep exactly the behaviour it had
// before this existed: the observed identity is displayed as a candidate, the row
// pauses, and the recorded reason says why no prompt was skipped.
func TestFirstContactIneligibleJobsKeepTheManualPause(t *testing.T) {
	cases := []struct {
		name     string
		eligible FirstContactEligibility
		policy   string
		wantText string
	}{
		{
			name:     "manual policy never consults the ownership check",
			policy:   models.SetupTrustPolicyManual,
			eligible: allowAllEligibility,
		},
		{
			name:   "ownership check refuses",
			policy: models.SetupTrustPolicyFirstContact,
			eligible: func(context.Context, models.GigahostSetupIntent) (bool, string) {
				return false, "the order is not a managed purchase"
			},
			wantText: "the order is not a managed purchase",
		},
		{
			name:     "no ownership check wired",
			policy:   models.SetupTrustPolicyFirstContact,
			wantText: "this panel has no configured ownership check for automatic host trust",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.seedOrder("ord_fc_neg", 5401, "198.51.100.41")
			h.seedManagedCredential("ord_fc_neg")
			h.provider.statusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
				return &gigahost.DeployStatusResponse{
					OrderID: "ord_fc_neg", Status: gigahost.StatusReady,
					ServerID: 5401, AssignedIP: "198.51.100.41",
				}, nil
			}
			h.provider.serverFn = func(context.Context) ([]gigahost.ServerInfo, error) {
				return []gigahost.ServerInfo{{ID: 5401, OrderID: "ord_fc_neg", IPv4: "198.51.100.41"}}, nil
			}
			h.approve(&models.GigahostSetupIntent{
				OrderID: "ord_fc_neg", ProviderServerID: 5401, AssignedIP: "198.51.100.41",
				Protocol: models.ProtocolAWG, Port: "51820",
				CredentialMode: models.SetupCredentialManaged,
			})
			if tc.policy == models.SetupTrustPolicyFirstContact {
				h.grantBoundAuthority("ord_fc_neg", 5401)
			}

			h.runOnce(h.firstContactTracker(firstContactFingerprintA, tc.eligible))

			got := h.load("ord_fc_neg")
			if got.State != models.SetupStateAwaitingHostConfirm {
				t.Fatalf("state = %q, want the manual pause %q (step %q)",
					got.State, models.SetupStateAwaitingHostConfirm, got.Step)
			}
			if got.HostFingerprint != "" || got.HostTrustMode != models.SetupTrustModeNone {
				t.Fatalf("an ineligible job was trusted: identity=%q mode=%q",
					got.HostFingerprint, got.HostTrustMode)
			}
			if got.HostCandidateFingerprint != firstContactFingerprintA {
				t.Fatalf("candidate = %q, want the observed %q",
					got.HostCandidateFingerprint, firstContactFingerprintA)
			}
			if tc.wantText != "" && got.LastError != tc.wantText {
				t.Fatalf("recorded reason = %q, want %q", got.LastError, tc.wantText)
			}
			if tc.wantText == "" && got.LastError != "" {
				t.Fatalf("a manual-policy job recorded a reason it never asked for: %q", got.LastError)
			}
		})
	}
}

// TestFirstContactPinFailureDoesNotTrustTheHost proves the persistence-failure
// control: when the identity cannot be recorded, nothing is trusted, the row keeps
// its place, and the recorded failure is retryable rather than terminal.
func TestFirstContactPinFailureDoesNotTrustTheHost(t *testing.T) {
	h := newHarness(t)
	h.seedFirstContactJob("ord_fc_writefail", 5501, "198.51.100.51")

	tracker := New(h.db, Options{
		Resolve: func(context.Context) (ProviderReader, error) { return h.provider, nil },
		ChallengeHost: func(context.Context, models.GigahostSetupIntent) (string, error) {
			return firstContactFingerprintA, nil
		},
		FirstContactEligible:   allowAllEligibility,
		Pinner:                 failingPinner{err: errFirstContactWriteFailed},
		AutomaticEffectAllowed: allowAllEffects,
		Now:                    h.clock.Now,
		Interval:               5 * time.Minute,
		FailureBack:            time.Minute,
		MaxBackoff:             time.Hour,
		Batch:                  10,
		CallTimeout:            5 * time.Second,
	})
	h.runOnce(tracker)

	got := h.load("ord_fc_writefail")
	if got.State != models.SetupStatePending {
		t.Fatalf("state = %q, want %q so the job is retried (step %q)",
			got.State, models.SetupStatePending, got.Step)
	}
	if got.Step != stepHostTrustUnavailable {
		t.Fatalf("step = %q, want %q", got.Step, stepHostTrustUnavailable)
	}
	if got.HostFingerprint != "" || got.HostTrustMode != models.SetupTrustModeNone {
		t.Fatalf("a failed pin still trusted the host: identity=%q mode=%q",
			got.HostFingerprint, got.HostTrustMode)
	}
	if got.ReadFailures != 1 {
		t.Fatalf("read failures = %d, want 1 so the retry backs off", got.ReadFailures)
	}
	if got.NextAttemptAt.IsZero() {
		t.Fatal("a failed pin did not schedule a retry")
	}
}

// errFirstContactWriteFailed stands in for a database that cannot commit the pin. The
// message is the store's own diagnosis, which the recorded step quotes.
var errFirstContactWriteFailed = errors.New("disk I/O error")

// failingPinner is a pin store that cannot write, which is the persistence-failure
// boundary a real database can hit.
type failingPinner struct{ err error }

func (p failingPinner) PinGigahostSetupFirstContact(context.Context, string, string) (string, error) {
	return "", p.err
}

// TestStaleTransitionCannotReplaceThePin is the sequential-writer control.
//
// The tracker commits its decision from a snapshot it read earlier. That snapshot can
// carry an identity from before the pin, or a value another writer produced. Writing
// it must never replace the identity this job already trusts, because the install path
// enforces whatever is stored - so an overwrite would be a trust change nobody
// approved.
func TestStaleTransitionCannotReplaceThePin(t *testing.T) {
	h := newHarness(t)
	h.seedFirstContactJob("ord_fc_stale", 5601, "198.51.100.61")
	h.runOnce(h.firstContactTracker(firstContactFingerprintA, allowAllEligibility))
	if pinned := h.load("ord_fc_stale").HostFingerprint; pinned != firstContactFingerprintA {
		t.Fatalf("precondition: pinned %q, want %q", pinned, firstContactFingerprintA)
	}

	// A stale worker: it holds a snapshot from before the pin, and it believes the
	// address presented a different identity. It then commits an ordinary
	// transition, exactly as a pass does.
	stale := h.load("ord_fc_stale")
	stale.State = models.SetupStateReadyForSetup
	stale.Step = "ready_for_setup"
	stale.HostFingerprint = firstContactFingerprintB
	if _, err := h.db.TransitionGigahostSetupIntent(
		context.Background(), stale, []string{models.SetupStateReadyForSetup}); err != nil {
		t.Fatalf("stale transition: %v", err)
	}

	after := h.load("ord_fc_stale")
	if after.HostFingerprint != firstContactFingerprintA {
		t.Fatalf("a stale writer replaced the pin: identity=%q, want %q",
			after.HostFingerprint, firstContactFingerprintA)
	}
	if after.HostTrustMode != models.SetupTrustModeFirstContact {
		t.Fatalf("a stale writer changed the trust provenance to %q", after.HostTrustMode)
	}
}

// TestConfirmationCannotReplaceAFirstContactPin proves the manual writer is fenced
// off from an automatic pin. An administrator's confirmation is not the authority that
// established this identity, and silently replacing it would be exactly the trust
// change the requirement forbids.
func TestConfirmationCannotReplaceAFirstContactPin(t *testing.T) {
	h := newHarness(t)
	h.seedFirstContactJob("ord_fc_noreplace", 5701, "198.51.100.71")
	h.runOnce(h.firstContactTracker(firstContactFingerprintA, allowAllEligibility))

	// Place the row in the shape a confirmation applies to, without touching the
	// pin: the job is paused for identity and shows a candidate.
	paused := h.load("ord_fc_noreplace")
	paused.State = models.SetupStateAwaitingHostConfirm
	paused.Step = "host_identity_changed"
	paused.HostCandidateFingerprint = firstContactFingerprintB
	if _, err := h.db.TransitionGigahostSetupIntent(
		context.Background(), paused, []string{models.SetupStateReadyForSetup}); err != nil {
		t.Fatalf("place the row in the confirmation shape: %v", err)
	}

	current, changed, err := h.db.ConfirmGigahostSetupHostFingerprint(
		context.Background(), "ord_fc_noreplace", firstContactFingerprintB)
	if err != nil {
		t.Fatalf("confirmation: %v", err)
	}
	if changed {
		t.Fatal("an administrator confirmation replaced an automatically pinned identity")
	}
	if current == nil || current.HostFingerprint != firstContactFingerprintA {
		t.Fatalf("the pin was rewritten: %+v", current)
	}
	if current.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("a refused confirmation moved the job to %q", current.State)
	}
}

// TestTrustBindingGrantRefusesAfterTrustIsDecided proves the authority grant cannot be
// applied retroactively. The binding is what permits a pin, so a row that already has an
// identity, or has already left pending, must not acquire it afterwards.
func TestTrustBindingGrantRefusesAfterTrustIsDecided(t *testing.T) {
	h := newHarness(t)
	h.seedFirstContactJob("ord_fc_latepolicy", 5801, "198.51.100.81")
	h.runOnce(h.firstContactTracker(firstContactFingerprintA, allowAllEligibility))

	ctx := context.Background()
	if _, changed, err := h.db.SetGigahostSetupAutomationBinding(ctx, database.AutomationBinding{
		OrderID: "ord_fc_latepolicy", ProviderServerID: 5801,
		Address: "198.51.100.81", ProviderKeyID: trackerTestProviderKeyID,
	}); err != nil {
		t.Fatalf("binding write: %v", err)
	} else if changed {
		t.Fatal("a binding grant applied to a row whose trust was already decided")
	}

	// An incomplete binding is refused rather than stored: it would be durable authority
	// that names no resource.
	if intent, changed, err := h.db.SetGigahostSetupAutomationBinding(
		ctx, database.AutomationBinding{OrderID: "ord_fc_latepolicy"}); err != nil || changed || intent != nil {
		t.Fatalf("incomplete binding = (%v, %v, %v), want (nil, false, nil)", intent, changed, err)
	}
}
