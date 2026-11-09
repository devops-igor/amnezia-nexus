package main

// End-to-end coverage for the opt-in provider-read proposal: the real command
// against a disposable legacy database and a controlled provider fixture.
//
// No test here reaches a real provider account. Every assertion is about an
// observable effect: rows in the fixture database, audit-row counts, the calls
// the fixture actually received, and the report the operator reads.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
)

// openFixtureDB opens a disposable fixture database for direct inspection.
func openFixtureDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	con, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	return con
}

// providerFixture is a read-only provider stand-in that records what it was
// asked, so a test can prove no write-shaped call was made.
type providerFixture struct {
	mu       sync.Mutex
	methods  []string
	paths    []string
	servers  []map[string]any
	deploy   map[string]deployAnswer
	catalog  string
	failList bool
}

// deployAnswer is one canned deployment-status answer.
type deployAnswer struct {
	status int
	body   string
	delay  time.Duration
}

// newProviderFixture starts the stand-in provider.
func newProviderFixture(t *testing.T) (*providerFixture, *httptest.Server) {
	t.Helper()
	f := &providerFixture{deploy: map[string]deployAnswer{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.methods = append(f.methods, r.Method)
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/servers":
			if f.failList {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"inventory unavailable"}`))
				return
			}
			servers := f.servers
			if servers == nil {
				servers = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"meta": map[string]any{"page": 1, "total_pages": 1, "total": len(servers)},
				"data": servers,
			})
		case "/deploy/servers":
			if f.catalog != "" {
				_, _ = w.Write([]byte(f.catalog))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"tiers":[],"regions":[],"currency":"NOK"}}`))
		case "/deploy/status":
			id := r.URL.Query().Get("ids")
			answer, ok := f.deploy[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"not found"}`))
				return
			}
			if answer.delay > 0 {
				select {
				case <-time.After(answer.delay):
				case <-r.Context().Done():
					return
				}
			}
			w.WriteHeader(answer.status)
			_, _ = w.Write([]byte(answer.body))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"unexpected path"}`))
		}
	}))
	return f, srv
}

// sawNonRead reports whether any call used a method other than GET.
func (f *providerFixture) sawNonRead() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for i, m := range f.methods {
		if m != http.MethodGet {
			out = append(out, m+" "+f.paths[i])
		}
	}
	return out
}

// callsTo counts calls to one path.
func (f *providerFixture) callsTo(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.paths {
		if p == path {
			n++
		}
	}
	return n
}

// legacyLedgerFixture writes a disposable database with the OLD ledger schema
// plus the record shapes the proposal must handle: a live hourly server, a
// cancelled record, a synthetic-id attempt, a waitlist-shaped waiting order and a
// record with no provider identity at all.
func legacyLedgerFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")
	ledgerFixture(t, path)
	con := openFixtureDB(t, path)
	defer func() { _ = con.Close() }()
	for _, stmt := range []string{
		`INSERT INTO gigahost_orders (order_id, server_id, status, plan_id, region_id, hourly_price_nok, created_at, updated_at)
		 VALUES ('20002', 0, 'cancelled', 202, 2, 0.057, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')`,
		`INSERT INTO gigahost_orders (order_id, server_id, status, plan_id, region_id, hourly_price_nok, created_at, updated_at)
		 VALUES ('30003', 0, 'waiting', 202, 2, 0.057, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')`,
		`INSERT INTO gigahost_orders (order_id, server_id, status, plan_id, region_id, hourly_price_nok, created_at, updated_at)
		 VALUES ('', 0, 'pending_order', 202, 2, 0.057, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')`,
	} {
		if _, err := con.Exec(stmt); err != nil {
			t.Fatalf("seed fixture: %v", err)
		}
	}
	return path
}

// providerArgs builds the flag set for a provider run.
func providerArgs(db, url string, extra ...string) []string {
	args := []string{
		"--db", db, "--budget", "100", "--json",
		"--provider-read", "--provider-url", url, "--api-key", fixtureAPIKey,
		"--provider-timeout", "5s",
	}
	return append(args, extra...)
}

// fixtureAPIKey is a syntactically valid placeholder credential, not a real key.
const fixtureAPIKey = "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// catalogFixture is one hourly product with a single monthly amount, so a legacy
// record without a persisted contract is priced exactly as the purchase path
// would price it.
const catalogFixture = `{"data":{"currency":"NOK","tiers":[{"group_id":1,"group_name":"vps","in_stock":true,
	"products":[{"product_id":202,"product_name":"small","type":"vps","allow_hourly":true,
	"price_id":666,"rate_hourly":0.057,"rate_monthly":41,"region_ids":[2],"in_stock":true}]}],
	"regions":[{"region_id":2,"region_name":"oslo"}]}}`

// ledgerCounts returns the orders and audit row counts plus released markers.
// A legacy fixture has no released_at column, in which case nothing can be
// released and the count is reported as zero.
func ledgerCounts(t *testing.T, path string) (orders, audit, released int64) {
	t.Helper()
	con := openFixtureDB(t, path)
	defer func() { _ = con.Close() }()
	if err := con.QueryRow(`SELECT COUNT(*) FROM gigahost_orders`).Scan(&orders); err != nil {
		t.Fatalf("count orders: %v", err)
	}
	if err := con.QueryRow(`SELECT COUNT(*) FROM gigahost_order_audit`).Scan(&audit); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if !columnExists(t, con, "gigahost_orders", "released_at") {
		return orders, audit, 0
	}
	if err := con.QueryRow(`SELECT COUNT(*) FROM gigahost_orders WHERE COALESCE(released_at,'') != ''`).Scan(&released); err != nil {
		t.Fatalf("count released: %v", err)
	}
	return orders, audit, released
}

// columnExists reports whether a table has a column.
func columnExists(t *testing.T, con *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := con.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatalf("inspect %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}

// TestProviderReadProposesOnlyAConclusiveTermination is the positive control: a
// matching provider server reported as terminated is the one observation that
// justifies a proposed release, and a dry run still writes nothing.
func TestProviderReadProposesOnlyAConclusiveTermination(t *testing.T) {
	db := legacyLedgerFixture(t)
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	f, srv := newProviderFixture(t)
	defer srv.Close()
	// Record 1 is the live 'ready' row with order id 10001.
	f.servers = []map[string]any{{
		"id": 7, "order_id": "10001", "status": "terminated", "bw_is_hourly": true,
	}}
	// The catalog prices the legacy rows the way the purchase path would, so the
	// before/after delta is a real amount rather than an unknown.
	f.catalog = catalogFixture

	code, stdout, stderr := runCLI(t, providerArgs(db, srv.URL)...)
	if code == exitFailure || code == exitUsage {
		t.Fatalf("exit = %d, want a completed report; stderr=%q", code, stderr)
	}

	var rep report
	if err := json.Unmarshal([]byte(mustJSON(t, stdout)), &rep); err != nil {
		t.Fatalf("parse report: %v (stdout=%q)", err, stdout)
	}
	if rep.EvidenceSource != "provider_read" {
		t.Fatalf("evidence source = %q, want provider_read", rep.EvidenceSource)
	}
	if len(rep.Released) != 1 || rep.Released[0].OrderID != "10001" {
		t.Fatalf("released = %+v, want exactly the terminated server's row", rep.Released)
	}
	if rep.Released[0].Reason != "provider_terminated" {
		t.Errorf("release reason = %q, want provider_terminated", rep.Released[0].Reason)
	}
	if rep.Released[0].Evidence == "" {
		t.Error("a proposed release must record the evidence it rests on")
	}
	// Before must show what the ledger records today, not the post-change total.
	if rep.CommittedBefore == 0 {
		t.Errorf("committed before = 0: it must show the pre-change total")
	}
	if rep.CommittedAfter >= rep.CommittedBefore {
		t.Errorf("committed after (%v) must be below before (%v) for a release", rep.CommittedAfter, rep.CommittedBefore)
	}
	// Every kept row must name the proof it needs.
	for _, kept := range rep.Retained {
		if kept.ProofNeeded == "" {
			t.Errorf("retained record %d does not name the proof it needs", kept.RecordID)
		}
	}
	if len(rep.Bindings.Rows) == 0 || rep.Bindings.Ledger.Digest == "" {
		t.Fatalf("the report carries no stale-safe bindings: %+v", rep.Bindings)
	}

	// A dry run writes nothing: same bytes, same rows, no new audit history.
	after, err := os.ReadFile(db)
	if err != nil {
		t.Fatalf("re-read fixture: %v", err)
	}
	if string(before) != string(after) {
		t.Error("a provider dry run modified the database file")
	}
	orders, audit, released := ledgerCounts(t, db)
	if orders != 5 || audit != 1 || released != 0 {
		t.Fatalf("ledger after dry run = %d orders, %d audit, %d released; want 5/1/0", orders, audit, released)
	}
	if bad := f.sawNonRead(); len(bad) > 0 {
		t.Fatalf("the provider received non-read calls: %v", bad)
	}
}

// TestProviderReadDoesNotReleaseAmbiguousStates pins the negatives together: a
// cancelled record, a waiting order and a synthetic/id-less attempt must all
// stay counted, and none of them may be proposed for release.
func TestProviderReadDoesNotReleaseAmbiguousStates(t *testing.T) {
	db := legacyLedgerFixture(t)
	f, srv := newProviderFixture(t)
	defer srv.Close()
	// The provider knows order 10001 only, and reports a status the contract does
	// not tie to billing.
	f.servers = []map[string]any{{
		"id": 7, "order_id": "10001", "status": "stopped", "bw_is_hourly": true,
	}}
	f.deploy["10001"] = deployAnswer{status: http.StatusOK, body: `{"order_id":"10001","status":"stopped"}`}

	code, stdout, stderr := runCLI(t, providerArgs(db, srv.URL)...)
	if code == exitFailure || code == exitUsage {
		t.Fatalf("exit = %d, want a completed report; stderr=%q", code, stderr)
	}
	var rep report
	if err := json.Unmarshal([]byte(mustJSON(t, stdout)), &rep); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if len(rep.Released) != 0 {
		t.Fatalf("released %+v, want nothing: none of these states proves no charge", rep.Released)
	}
	byOrder := map[string]string{}
	for _, kept := range rep.Retained {
		byOrder[kept.OrderID] = kept.Reason
	}
	for _, want := range []string{"20002", "30003", "intent_1700000000000000000", ""} {
		reason, ok := byOrder[want]
		if !ok {
			t.Errorf("record with order id %q was not reported as retained: %+v", want, rep.Retained)
			continue
		}
		if reason == "" {
			t.Errorf("record %q has no stable reason token", want)
		}
	}
	if _, audit, released := ledgerCounts(t, db); audit != 1 || released != 0 {
		t.Fatalf("a non-conclusive provider answer wrote state: %d audit rows, %d released", audit, released)
	}
}

// TestProviderReadFailedQueryIsReportedNotTrusted proves a failed read is neither
// absence nor a crash: the report completes, nothing is released, and the status
// is named as unknown.
func TestProviderReadFailedQueryIsReportedNotTrusted(t *testing.T) {
	db := legacyLedgerFixture(t)
	f, srv := newProviderFixture(t)
	defer srv.Close()
	f.deploy["10001"] = deployAnswer{status: http.StatusInternalServerError, body: `{"message":"boom"}`}
	f.catalog = catalogFixture

	code, stdout, stderr := runCLI(t, providerArgs(db, srv.URL)...)
	if code == exitFailure || code == exitUsage {
		t.Fatalf("exit = %d, want a completed report; stderr=%q", code, stderr)
	}
	var rep report
	if err := json.Unmarshal([]byte(mustJSON(t, stdout)), &rep); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if len(rep.Released) != 0 {
		t.Fatalf("a failed provider read released %+v", rep.Released)
	}
	if !containsSubstring(rep.Warnings, "failed read is not evidence of absence") {
		t.Errorf("the report must say a failed read proves nothing; warnings=%v", rep.Warnings)
	}
	if !hasReason(rep.Retained, "provider_unreachable") {
		t.Errorf("a failed read must be reported as an unreachable provider; retained=%+v", rep.Retained)
	}
}

// TestProviderReadTimeoutIsReportedNotTrusted is the same rule for a timeout.
func TestProviderReadTimeoutIsReportedNotTrusted(t *testing.T) {
	db := legacyLedgerFixture(t)
	f, srv := newProviderFixture(t)
	defer srv.Close()
	f.deploy["10001"] = deployAnswer{status: http.StatusOK, body: `{"status":"ready"}`, delay: 2 * time.Second}
	f.catalog = catalogFixture

	code, stdout, stderr := runCLI(t, append(providerArgs(db, srv.URL), "--provider-timeout", "150ms")...)
	if code == exitFailure || code == exitUsage {
		t.Fatalf("exit = %d, want a completed report; stderr=%q", code, stderr)
	}
	var rep report
	if err := json.Unmarshal([]byte(mustJSON(t, stdout)), &rep); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if len(rep.Released) != 0 {
		t.Fatalf("a timed-out provider read released %+v", rep.Released)
	}
	if !hasReason(rep.Retained, "provider_unreachable") {
		t.Errorf("a timeout must be reported as an unreachable provider; retained=%+v", rep.Retained)
	}
}

// TestProviderReadIdentityConflictIsNotAMatch proves a shared plan or a
// different order id cannot establish equivalence: merging two commitments would
// hide spend.
func TestProviderReadIdentityConflictIsNotAMatch(t *testing.T) {
	db := legacyLedgerFixture(t)
	f, srv := newProviderFixture(t)
	defer srv.Close()
	// Same plan id, different provider order id, reported terminated.
	f.servers = []map[string]any{{
		"id": 70, "order_id": "99999", "status": "terminated", "bw_is_hourly": true,
	}}
	f.deploy["10001"] = deployAnswer{status: http.StatusOK, body: `{"order_id":"10001","status":"ready"}`}
	f.catalog = catalogFixture

	code, stdout, stderr := runCLI(t, providerArgs(db, srv.URL)...)
	if code == exitFailure || code == exitUsage {
		t.Fatalf("exit = %d, want a completed report; stderr=%q", code, stderr)
	}
	var rep report
	if err := json.Unmarshal([]byte(mustJSON(t, stdout)), &rep); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if len(rep.Released) != 0 {
		t.Fatalf("a different provider order id was treated as the same VPS: %+v", rep.Released)
	}
	if !hasReason(rep.Retained, "provider_order_live") {
		t.Errorf("the live provider answer must keep the row counted; retained=%+v", rep.Retained)
	}
}

// TestProviderReadInventoryFailureFailsTheRun proves an inventory outage is not
// reported as "no evidence": the operator asked for provider proof and did not
// get it, so the run fails instead of printing a quiet offline-looking report.
func TestProviderReadInventoryFailureFailsTheRun(t *testing.T) {
	db := legacyLedgerFixture(t)
	f, srv := newProviderFixture(t)
	defer srv.Close()
	f.failList = true

	code, stdout, stderr := runCLI(t, providerArgs(db, srv.URL)...)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d on an inventory failure; stderr=%q", code, exitFailure, stderr)
	}
	if !strings.Contains(stderr, "read provider inventory") {
		t.Errorf("stderr must name the failed inventory read, got %q", stderr)
	}
	if stdout != "" {
		t.Errorf("a failed provider pass must not print a plan: %q", stdout)
	}
	if _, audit, released := ledgerCounts(t, db); audit != 1 || released != 0 {
		t.Fatalf("a failed provider pass wrote state: %d audit, %d released", audit, released)
	}
}

// TestProviderReadNeedsACredential proves the opt-in path cannot silently degrade
// into an offline report.
func TestProviderReadNeedsACredential(t *testing.T) {
	db := legacyLedgerFixture(t)
	t.Setenv("GIGAHOST_API_KEY", "")
	code, stdout, stderr := runCLI(t, "--db", db, "--budget", "100", "--provider-read",
		"--provider-url", "http://127.0.0.1:1", "--api-key", "")
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d without a credential", code, exitFailure)
	}
	if !strings.Contains(stderr, "needs a credential") {
		t.Errorf("stderr must explain the missing credential, got %q", stderr)
	}
	if stdout != "" {
		t.Errorf("no plan may be printed without evidence: %q", stdout)
	}
}

// TestProviderReadPricingUsesTheProviderCatalog proves legacy records without a
// persisted contract are priced from the provider catalog, so the proposal uses
// the same amount a purchase decision would.
func TestProviderReadPricingUsesTheProviderCatalog(t *testing.T) {
	db := legacyLedgerFixture(t)
	f, srv := newProviderFixture(t)
	defer srv.Close()
	f.catalog = `{"data":{"currency":"NOK","tiers":[{"group_id":1,"group_name":"vps","in_stock":true,
		"products":[{"product_id":202,"product_name":"small","type":"vps","allow_hourly":true,
		"price_id":666,"rate_hourly":0.057,"rate_monthly":41,"region_ids":[2],"in_stock":true}]}],
		"regions":[{"region_id":2,"region_name":"oslo"}]}}`

	code, stdout, stderr := runCLI(t, providerArgs(db, srv.URL)...)
	if code == exitFailure || code == exitUsage {
		t.Fatalf("exit = %d, want a completed report; stderr=%q", code, stderr)
	}
	var rep report
	if err := json.Unmarshal([]byte(mustJSON(t, stdout)), &rep); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	// Four counted rows at 41 NOK each: the legacy records have no persisted cap,
	// so the catalog's single monthly amount for plan 202 must price them.
	if rep.CommittedBefore < 40.99*4 {
		t.Fatalf("committed before = %v, want at least four catalog-priced reservations", rep.CommittedBefore)
	}
	if rep.IncompleteTotal {
		t.Errorf("the total must be complete once the catalog prices every counted row")
	}
	if f.callsTo("/deploy/servers") != 1 {
		t.Errorf("catalog reads = %d, want exactly one per pass", f.callsTo("/deploy/servers"))
	}
}

// TestProviderReadZeroLookupsIsRefused proves a bound of zero is rejected rather
// than silently producing a pass that claims provider evidence and reads nothing.
func TestProviderReadZeroLookupsIsRefused(t *testing.T) {
	db := legacyLedgerFixture(t)
	code, _, stderr := runCLI(t, "--db", db, "--budget", "100", "--provider-read",
		"--max-order-lookups", "0", "--provider-url", "http://127.0.0.1:1",
		"--api-key", fixtureAPIKey)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "max-order-lookups") {
		t.Errorf("stderr must name the refused flag, got %q", stderr)
	}
}

// TestProviderReadApplyIsRefusedByTheCLI is the property the assignment cares
// about most: this checkpoint cannot write a provider-backed release. Applying
// needs the stale-safe write path that re-checks the observed row inside the
// release transaction, so the combination is refused instead of writing evidence
// that may no longer describe the row.
func TestProviderReadApplyIsRefusedByTheCLI(t *testing.T) {
	db := legacyLedgerFixture(t)
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	code, stdout, stderr := runCLI(t, append(providerArgs(db, "http://127.0.0.1:1"), "--apply")...)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d; stderr=%q", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "--apply with --provider-read is not supported yet") {
		t.Errorf("stderr must explain the refusal, got %q", stderr)
	}
	if stdout != "" {
		t.Errorf("a refused run must not print a plan: %q", stdout)
	}
	after, err := os.ReadFile(db)
	if err != nil {
		t.Fatalf("re-read fixture: %v", err)
	}
	if string(before) != string(after) {
		t.Error("a refused run modified the database file")
	}
}

// TestOfflineRunStillProposesNothing is the unchanged baseline: without the
// opt-in flag the tool never touches the network and proposes no change.
func TestOfflineRunStillProposesNothing(t *testing.T) {
	db := legacyLedgerFixture(t)
	f, srv := newProviderFixture(t)
	defer srv.Close()

	code, stdout, stderr := runCLI(t, "--db", db, "--budget", "100", "--json",
		"--provider-url", srv.URL, "--api-key", fixtureAPIKey)
	if code != exitUnresolved {
		t.Fatalf("exit = %d, want %d (unresolved rows, no provider read); stderr=%q", code, exitUnresolved, stderr)
	}
	var rep report
	if err := json.Unmarshal([]byte(mustJSON(t, stdout)), &rep); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if rep.EvidenceSource != "offline" {
		t.Fatalf("evidence source = %q, want offline", rep.EvidenceSource)
	}
	if len(rep.Released) != 0 {
		t.Fatalf("an offline run proposed %+v", rep.Released)
	}
	if rep.Bindings != nil {
		t.Errorf("an offline run must not claim provider bindings: %+v", rep.Bindings)
	}
	if len(f.methods) != 0 {
		t.Fatalf("an offline run contacted the provider: %v", f.methods)
	}
}

// hasReason reports whether any retained change carries the reason token.
func hasReason(changes []gigahostbudget.ProposedChange, reason string) bool {
	for _, c := range changes {
		if c.Reason == reason {
			return true
		}
	}
	return false
}

// containsSubstring reports whether any entry contains the substring.
func containsSubstring(entries []string, want string) bool {
	for _, e := range entries {
		if strings.Contains(e, want) {
			return true
		}
	}
	return false
}

// mustJSON returns a JSON document from mixed stdout (the report line plus any
// human text) so a test can decode it.
func mustJSON(t *testing.T, stdout string) string {
	t.Helper()
	trimmed := strings.TrimSpace(stdout)
	if strings.HasPrefix(trimmed, "{") {
		return trimmed
	}
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == '{' {
			return trimmed[i:]
		}
	}
	t.Fatalf("no JSON document in output: %q", stdout)
	return ""
}
