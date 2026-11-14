package handlers

// Parent side of the provider-outage proof.
//
// The C3a test this file supersedes is kept and re-attributed: it injects a closed SSH port
// while the provider keeps answering "ready", which is a HOST CONTACT failure. A provider
// outage is a different event - the deploy-status read itself fails - and it is the one that
// matters while a VPS is being provisioned or while the provider's API is down.
//
// Two facts are measured across the process boundary rather than inferred:
//
//   - **provider reads and their outcomes**, from a journal file both processes append to.
//     A state label such as "pending" cannot distinguish "the provider said deploying" from
//     "we could not ask", and that distinction is the whole requirement.
//   - **purchase attempts**, recorded by the same stub that refuses them. A failed provider
//     cannot also be the oracle for "nobody tried to buy anything", so the fixture records
//     the attempt instead of relying on the read path.
//
// Long provisioning uses the child's pinned clock: virtual hours, not a real wait.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// procProviderRecoveryTrack is the child mode: one tracking pass against a provider whose
// behaviour is chosen by the environment.
const procProviderRecoveryTrack = "provider_recovery_track"

// newProviderProofEnv builds a disposable environment with its own provider journal.
func newProviderProofEnv(t *testing.T, orderID string) (*processProofEnv, string) {
	t.Helper()
	env, _, _ := newAutomaticProcessEnv(t, orderID)
	providerJournal := filepath.Join(filepath.Dir(env.dbPath), "provider.log")
	env.t.Cleanup(func() {
		// Keep the artifact for post-mortem only while the test directory lives; t.TempDir
		// removes it automatically. Nothing to do beyond documenting the location.
		_ = providerJournal
	})
	return env, providerJournal
}

// runProviderChild runs one provider-recovery child and returns its report.
func (e *processProofEnv) runProviderChild(
	providerJournal, providerMode, policy, clock string,
) (childResult, map[string]string) {
	e.t.Helper()
	extra := []string{
		envProcessProviderJournal + "=" + providerJournal,
		envProcessProviderMode + "=" + providerMode,
		envProcessPolicy + "=" + policy,
	}
	if clock != "" {
		extra = append(extra, envProcessClock+"="+clock)
	}
	result := e.runChildWith(procProviderRecoveryTrack, e.secret, extra...)
	return result, parseChildReport(result.stdout)
}

// TestProviderOutageAcrossVirtualHoursThenFreshProcessRecovery is the corrected A4 proof.
//
// The sequence is the one a real purchase experiences:
//
//	provider down -> job stays pending, no false terminal state, no purchase
//	provider reports "deploying" for >60 virtual minutes -> still pending, still no purchase
//	a fresh process with the provider answering "ready" -> association, grant, pin
//
// The job's identity, mode and options are asserted unchanged at every step, and the
// purchase counter is asserted zero across all three children.
func TestProviderOutageAcrossVirtualHoursThenFreshProcessRecovery(t *testing.T) {
	const orderID = autoProcessOrderID
	env, providerJournal := newProviderProofEnv(t, orderID)

	// The parent creates the job through the production entry and stops. The purchase ledger
	// row already exists with the stamp and the credential and no address, which is the
	// state an outage interrupts.
	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	created := seedAutomaticIntent(t, db, orderID)
	if err := db.Close(); err != nil {
		t.Fatalf("close seeding database: %v", err)
	}
	// Capture the immutable facts before any child runs, so the assertions compare against
	// what the entry actually wrote rather than against a re-derivation.
	wantProtocol := created.Protocol
	wantPort := created.Port
	wantState := created.State

	// Clock instants: one hour in, then two and three hours in, all virtual.
	base := time.Now()
	hour1 := strconv.FormatInt(base.Add(time.Hour).Unix(), 10)
	hour2 := strconv.FormatInt(base.Add(2*time.Hour).Unix(), 10)
	hour3 := strconv.FormatInt(base.Add(3*time.Hour).Unix(), 10)
	// The recovery pass is a NEW process at a later instant. Reusing hour3 would leave the
	// row not yet due, because the previous pass scheduled its next attempt one interval
	// after the clock it believed it was.
	hour4 := strconv.FormatInt(base.Add(4*time.Hour).Unix(), 10)

	// Step 1: the provider is DOWN. The read fails; the job must stay pending.
	downResult, downReport := env.runProviderChild(providerJournal, providerModeDown, "on", hour1)
	requireChildExit(t, downResult, 0, "provider-down child")
	if downReport["state"] != models.SetupStatePending {
		t.Fatalf("after a provider outage: state = %q, want %q (step %q, last error %q)",
			downReport["state"], models.SetupStatePending, downReport["step"], downReport["last_error"])
	}
	if downReport["last_error"] == "" {
		t.Fatal("the outage recorded no reason")
	}
	// No false terminal failure and no false ready.
	if downReport["state"] == models.SetupStateFailed || downReport["state"] == models.SetupStateReady {
		t.Fatalf("an outage produced a terminal claim: %q", downReport["state"])
	}
	// The provider read really failed, measured from the journal.
	if got := providerReadFailuresTotal(providerJournal); got == 0 {
		t.Fatal("no provider read failure was recorded, so the outage was not exercised")
	}
	// And nothing was bought.
	if got := purchaseAttemptsTotal(providerJournal); got != 0 {
		t.Fatalf("a provider outage attempted %d purchases", got)
	}

	// Step 2: the provider answers "deploying" for more than sixty virtual minutes. The job
	// must remain pending, with no grant, no pin and no purchase.
	deploying1, deployingReport1 := env.runProviderChild(providerJournal, providerModePending, "on", hour2)
	requireChildExit(t, deploying1, 0, "deploying child (2h)")
	if deployingReport1["state"] != models.SetupStatePending {
		t.Fatalf("during provisioning: state = %q, want %q (step %q)",
			deployingReport1["state"], models.SetupStatePending, deployingReport1["step"])
	}
	if deployingReport1["grant_order"] != "" || deployingReport1["fingerprint"] != "" {
		t.Fatalf("provisioning granted or pinned prematurely: %v", deployingReport1)
	}
	// A second pass over an hour later, so the virtual window exceeds 60 minutes.
	deploying2, deployingReport2 := env.runProviderChild(providerJournal, providerModePending, "on", hour3)
	requireChildExit(t, deploying2, 0, "deploying child (3h)")
	if deployingReport2["state"] != models.SetupStatePending {
		t.Fatalf("after 3 virtual hours: state = %q, want %q (step %q)",
			deployingReport2["state"], models.SetupStatePending, deployingReport2["step"])
	}
	// Provisioning was answered, not failed: the two outcomes are counted separately.
	if got := providerReadSuccessesTotal(providerJournal); got == 0 {
		t.Fatal("no answered provider read was recorded, so provisioning was not exercised")
	}
	if got := purchaseAttemptsTotal(providerJournal); got != 0 {
		t.Fatalf("provisioning attempted %d purchases", got)
	}
	// The immutable facts survived two more processes.
	midway := readProcessIntent(t, env, orderID)
	assertImmutableIntentFacts(t, midway, wantProtocol, wantPort, wantState)

	// Step 3: a FRESH process with the provider answering "ready" completes the job.
	recovered, recoveredReport := env.runProviderChild(providerJournal, providerModeReady, "on", hour4)
	requireChildExit(t, recovered, 0, "recovery child")
	if recoveredReport["grant_order"] != orderID {
		t.Fatalf("the recovery process did not grant this order: %v", recoveredReport)
	}
	if recoveredReport["grant_server"] != strconv.FormatInt(autoProcessServerID, 10) {
		t.Fatalf("the recovery grant names server %q, want %d", recoveredReport["grant_server"], autoProcessServerID)
	}
	if recoveredReport["fingerprint"] == "" {
		t.Fatalf("the recovery process did not pin an identity (step %q, last error %q)",
			recoveredReport["step"], recoveredReport["last_error"])
	}
	if recoveredReport["assigned_ip"] == "" {
		t.Fatalf("the recovery process did not record the provider's address")
	}

	// The purchase counter is zero across every child: no outage, no provisioning window and
	// no recovery ordered anything.
	if got := purchaseAttemptsTotal(providerJournal); got != 0 {
		t.Fatalf("purchases attempted across all children = %d, want 0", got)
	}

	// The evidence is nonzero, so the sequence above actually exercised an outage and a
	// provisioning window rather than passing because nothing was called at all.
	if got := providerReadFailuresTotal(providerJournal); got == 0 {
		t.Fatal("the sequence recorded no provider failure, so the outage was vacuous")
	}
	if got := providerReadSuccessesTotal(providerJournal); got == 0 {
		t.Fatal("the sequence recorded no answered provider read, so provisioning was vacuous")
	}
	if got := providerReadFailuresTotal(providerJournal) + providerReadSuccessesTotal(providerJournal); got < 3 {
		t.Fatalf("only %d provider reads were recorded across four children", got)
	}

	// The immutable facts survived the whole sequence.
	final := readProcessIntent(t, env, orderID)
	assertImmutableIntentFacts(t, final, wantProtocol, wantPort, wantState)
	if final.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was lost: policy = %q", final.HostTrustPolicy)
	}
	// The same job, not a replacement: the provider server id is the one the grant names.
	if final.HostTrustServerID != autoProcessServerID {
		t.Fatalf("the grant names server %d, want %d", final.HostTrustServerID, autoProcessServerID)
	}
}

// assertImmutableIntentFacts checks the facts a failure must not change.
func assertImmutableIntentFacts(t *testing.T, intent *models.GigahostSetupIntent, protocol, port, _ string) {
	t.Helper()
	if intent.OrderID != autoProcessOrderID {
		t.Fatalf("the job's order id changed to %q", intent.OrderID)
	}
	if intent.Protocol != protocol {
		t.Fatalf("the job's protocol changed from %q to %q", protocol, intent.Protocol)
	}
	if intent.Port != port {
		t.Fatalf("the job's port changed from %q to %q", port, intent.Port)
	}
}

// TestProviderOutageNeverIssuesAPurchase is the purchase-oracle control.
//
// It runs a child whose provider is down and asserts, from the journal, that the only calls
// made were reads. The counter exists because a state label cannot prove the absence of an
// outbound order, and because the stub that fails cannot be its own witness that nobody
// asked it to sell anything.
func TestProviderOutageNeverIssuesAPurchase(t *testing.T) {
	const orderID = autoProcessOrderID
	env, providerJournal := newProviderProofEnv(t, orderID)

	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	seedAutomaticIntent(t, db, orderID)
	if err := db.Close(); err != nil {
		t.Fatalf("close seeding database: %v", err)
	}

	result, report := env.runProviderChild(providerJournal, providerModeDown, "on",
		strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	requireChildExit(t, result, 0, "provider-down child")

	if got := purchaseAttemptsTotal(providerJournal); got != 0 {
		t.Fatalf("purchase attempts during an outage = %d, want 0", got)
	}
	// The outbound call list is exactly the read surface, and nothing else.
	data, readErr := os.ReadFile(providerJournal)
	if readErr != nil {
		t.Fatalf("read the provider journal: %v", readErr)
	}
	for _, line := range splitProviderLines(string(data)) {
		method := firstField(line)
		if method == "" {
			continue
		}
		if method == providerCallPurchase {
			t.Fatalf("an outbound purchase was recorded: %q", line)
		}
		if method != providerCallDeployStatus && method != providerCallServers {
			t.Fatalf("an unexpected provider method was called: %q", line)
		}
	}
	if report["state"] != models.SetupStatePending {
		t.Fatalf("state = %q, want %q", report["state"], models.SetupStatePending)
	}
}

// splitProviderLines splits the provider journal into non-empty lines.
func splitProviderLines(data string) []string {
	out := make([]string, 0, 8)
	current := ""
	for _, r := range data {
		if r == '\n' {
			if current != "" {
				out = append(out, current)
				current = ""
			}
			continue
		}
		current += string(r)
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}

// firstField returns the first whitespace-separated field of a line.
func firstField(line string) string {
	for i, r := range line {
		if r == ' ' {
			return line[:i]
		}
	}
	return line
}

// TestProviderRecoveryControlCompletesNormally is the positive control beside the outage.
//
// Without it, "the outage left the job pending" could be satisfied by a job that can never
// progress. Here the provider answers ready from the first call and the same job completes,
// with a nonzero provider-read count and still zero purchases.
func TestProviderRecoveryControlCompletesNormally(t *testing.T) {
	const orderID = autoProcessOrderID
	env, providerJournal := newProviderProofEnv(t, orderID)

	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	seedAutomaticIntent(t, db, orderID)
	if err := db.Close(); err != nil {
		t.Fatalf("close seeding database: %v", err)
	}

	result, report := env.runProviderChild(providerJournal, providerModeReady, "on",
		strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	requireChildExit(t, result, 0, "ready-provider child")

	if report["grant_order"] != orderID || report["fingerprint"] == "" {
		t.Fatalf("the control did not grant and pin the job: %v", report)
	}
	if got := providerReadSuccessesTotal(providerJournal); got == 0 {
		t.Fatal("the control recorded no answered provider read, so its success proves nothing")
	}
	if got := purchaseAttemptsTotal(providerJournal); got != 0 {
		t.Fatalf("the control attempted %d purchases, want 0", got)
	}
}

// TestProviderOutagePreservesThePurchaseLedgerRow is the ledger-state support check.
//
// The purchase counter is the purchase oracle; this only confirms the durable rows agree
// with it. Exactly one row, still stamped, still carrying the managed credential.
func TestProviderOutagePreservesThePurchaseLedgerRow(t *testing.T) {
	const orderID = autoProcessOrderID
	env, providerJournal := newProviderProofEnv(t, orderID)

	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	seedAutomaticIntent(t, db, orderID)
	if err := db.Close(); err != nil {
		t.Fatalf("close seeding database: %v", err)
	}

	result, _ := env.runProviderChild(providerJournal, providerModeDown, "on",
		strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	requireChildExit(t, result, 0, "provider-down child")

	rows := countProcessOrderRows(t, env, orderID)
	if rows != 1 {
		t.Fatalf("ledger rows after an outage = %d, want exactly 1", rows)
	}
	order, found, orderErr := readProcessOrder(env, orderID)
	if orderErr != nil || !found {
		t.Fatalf("read order: found=%v err=%v", found, orderErr)
	}
	if order.PurchaseOrigin != models.PurchaseOriginPanelPurchase {
		t.Fatalf("an outage changed purchase provenance to %q", order.PurchaseOrigin)
	}
	// The managed credential is still there, so the job can authenticate once the provider
	// recovers.
	db2, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("reopen proof database: %v", err)
	}
	defer func() { _ = db2.Close() }()
	if has, credErr := db2.HasGigahostOrderCredential(context.Background(), orderID); credErr != nil || !has {
		t.Fatalf("the managed credential did not survive the outage: has=%v err=%v", has, credErr)
	}
}
