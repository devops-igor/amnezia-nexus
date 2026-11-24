package handlers

// The provider inventory reconciliation, on the real handler, the real SQLite
// store and the shipping provider client against a controlled local fixture.
//
// Three properties are pinned here because each one is a way to get this wrong:
//
//	1. absence is recorded durably and survives a restart and a listing reload;
//	2. a failed, timed-out or partial inventory read changes nothing at all;
//	3. a server the provider lists again is corrected instead of staying absent.
//
// Every assertion reads the store back, so it is about durable state rather than
// about a return value.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// inventoryProvider is the controlled local provider the reconciliation reads.
// Each case sets the answer it serves; calls counts how often it was asked, so a
// pass that skipped the read can be distinguished from one that made it.
type inventoryProvider struct {
	mu     sync.Mutex
	body   string
	status int
	stall  bool
	calls  int
}

// set serves the given /servers body and clears any previous failure mode.
func (p *inventoryProvider) set(body string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.body = body
	p.status = 0
	p.stall = false
}

// fail answers every request with the given HTTP error.
func (p *inventoryProvider) fail(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = status
	p.stall = false
}

// hang accepts the request and never answers, which is what a provider that has
// stopped responding looks like from the panel.
func (p *inventoryProvider) hang() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stall = true
}

func (p *inventoryProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func (p *inventoryProvider) handle(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.calls++
	body, status, stall := p.body, p.status, p.stall
	p.mu.Unlock()

	if r.URL.Path != "/servers" {
		http.NotFound(w, r)
		return
	}
	if stall {
		<-r.Context().Done()
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

// inventoryJSON renders the provider's /servers answer for the given provider
// server ids: a complete, self-consistent page.
func inventoryJSON(ids ...int64) string {
	entries := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, map[string]any{"srv_id": id, "status": "active"})
	}
	payload := map[string]any{
		"meta": map[string]any{"page": 1, "total_pages": 1, "total": len(ids)},
		"data": entries,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`)
	}
	return string(encoded)
}

// partialInventoryJSON renders a page that contradicts its own metadata: the
// account total says the inventory holds more servers than the page returned.
func partialInventoryJSON(id int64) string {
	return fmt.Sprintf(
		`{"meta":{"page":1,"total_pages":1,"total":3},"data":[{"srv_id":%d,"status":"active"}]}`, id)
}

// providerProtocols is the protocols blob a Gigahost deployment writes on the
// server row it registers.
func providerProtocols(providerServerID int64) map[string]any {
	return map[string]any{
		"provider":           "gigahost",
		"provider_server_id": providerServerID,
	}
}

// testInventoryAPIKey is a well-formed provider API key: the client validates the
// shape, and this fixture never sends it anywhere but its own local server. It is
// assembled rather than written out so no key-shaped literal sits in the tree.
var testInventoryAPIKey = "flux_live_" + strings.Repeat("a", 64)

// inventoryFixture is one open store, the handler over it, and the provider the
// reconciliation talks to.
type inventoryFixture struct {
	t        *testing.T
	h        *Handlers
	db       *database.DB
	dbPath   string
	provider *inventoryProvider
	server   *httptest.Server
	closed   bool
}

func newInventoryFixture(t *testing.T) *inventoryFixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "inventory_test.db")
	db, err := database.Open(dbPath, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open the test store: %v", err)
	}
	provider := &inventoryProvider{body: inventoryJSON()}
	server := httptest.NewServer(http.HandlerFunc(provider.handle))

	f := &inventoryFixture{
		t:        t,
		db:       db,
		dbPath:   dbPath,
		provider: provider,
		server:   server,
	}
	f.build()
	t.Cleanup(func() {
		server.Close()
		if !f.closed {
			_ = f.db.Close()
		}
	})
	return f
}

// build creates the handler and the provider client over the current store.
func (f *inventoryFixture) build() {
	f.t.Helper()
	cfg := &config.Config{
		AppVersion:  config.AppVersion,
		AppCodename: config.AppCodename,
		SecretKey:   testSecretKey,
	}
	h := NewHandlers(Dependencies{Config: cfg, DB: f.db})
	client, err := gigahost.NewClient(gigahost.Config{BaseURL: f.server.URL, APIKey: testInventoryAPIKey})
	if err != nil {
		f.t.Fatalf("failed to build the provider client: %v", err)
	}
	h.SetGigahostClient(client)
	f.h = h
}

// restart closes the store and reopens it, which is the panel-restart path: the
// reopened handle runs schema initialization again and reads the rows as a new
// process would.
func (f *inventoryFixture) restart() {
	f.t.Helper()
	if !f.closed {
		if err := f.db.Close(); err != nil {
			f.t.Fatalf("failed to close the store: %v", err)
		}
		f.closed = true
	}
	db, err := database.Open(f.dbPath, testSecretKey)
	if err != nil {
		f.t.Fatalf("failed to reopen the store: %v", err)
	}
	f.db = db
	f.closed = false
	f.build()
}

// seedServer registers a server row and returns its id.
func (f *inventoryFixture) seedServer(name string, protocols map[string]any) int64 {
	f.t.Helper()
	id, err := f.db.CreateServer(context.Background(), &models.Server{
		Name:      name,
		Host:      "198.51.100.10",
		SSHUser:   "root",
		SSHPort:   22,
		Protocols: protocols,
	})
	if err != nil {
		f.t.Fatalf("failed to seed server %q: %v", name, err)
	}
	return id
}

// row reads one server back from the store.
func (f *inventoryFixture) row(id int64) models.Server {
	f.t.Helper()
	server, err := f.db.GetServer(context.Background(), id)
	if err != nil || server == nil {
		f.t.Fatalf("failed to read server %d back: server=%v err=%v", id, server, err)
	}
	return *server
}

// listedServers calls the real listing and indexes the response by server id.
func (f *inventoryFixture) listedServers() map[int64]models.ServerItemResponse {
	f.t.Helper()
	body := f.listingBody()

	// The key must exist on every row, not merely decode into a default: an omitted
	// key and a false value are the same struct field but not the same contract, and
	// a later consumer filters on this key.
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		f.t.Fatalf("failed to decode the servers listing: %v", err)
	}
	for i, row := range raw {
		if _, ok := row["provider_absent"]; !ok {
			f.t.Fatalf("servers listing row %d does not carry the provider_absent key: %s", i, body)
		}
	}

	var items []models.ServerItemResponse
	if err := json.Unmarshal(body, &items); err != nil {
		f.t.Fatalf("failed to decode the servers listing: %v", err)
	}
	byID := make(map[int64]models.ServerItemResponse, len(items))
	for _, item := range items {
		byID[item.ID] = item
	}
	return byID
}

// listingBody returns the raw JSON body of the servers listing.
func (f *inventoryFixture) listingBody() []byte {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-1",
		Role:   models.RoleAdmin,
	}))
	rec := httptest.NewRecorder()
	f.h.ListServersHandler(rec, req)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("servers listing returned %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes()
}

func (f *inventoryFixture) reconcile(ctx context.Context) error {
	f.t.Helper()
	return f.h.ReconcileGigahostServerInventory(ctx)
}

func TestReconcileGigahostInventory_RecordsAbsenceDurably(t *testing.T) {
	f := newInventoryFixture(t)
	listed := f.seedServer("Listed", providerProtocols(501))
	gone := f.seedServer("Gone", providerProtocols(502))
	operator := f.seedServer("Operator-added", map[string]any{
		"awg": map[string]any{"installed": true},
	})

	// The provider enumerates the account and lists only 501.
	f.provider.set(inventoryJSON(501))
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}

	goneRow := f.row(gone)
	if !goneRow.ProviderAbsent() {
		t.Fatal("a provider-backed server missing from a successful inventory read was not recorded as absent")
	}
	observedAt, err := time.Parse(time.RFC3339, goneRow.ProviderAbsentAt)
	if err != nil {
		t.Fatalf("the recorded observation is not an RFC3339 timestamp: %q (%v)", goneRow.ProviderAbsentAt, err)
	}
	if age := time.Since(observedAt); age < 0 || age > time.Hour {
		t.Fatalf("the recorded observation is not recent: %s (%v old)", goneRow.ProviderAbsentAt, age)
	}

	// The observation is about existence only: the row itself is untouched.
	if goneRow.Name != "Gone" || goneRow.Host != "198.51.100.10" || goneRow.SSHPort != 22 {
		t.Fatalf("the reconciliation changed the server row: %+v", goneRow)
	}

	if f.row(listed).ProviderAbsent() {
		t.Fatal("a server the inventory still lists was marked absent")
	}
	if f.row(operator).ProviderAbsent() {
		t.Fatal("an operator-added server was judged by the provider's inventory")
	}

	// A repeated pass with the same answer preserves the original observation time
	// instead of refreshing it, so the recorded window is the real one.
	firstObserved := goneRow.ProviderAbsentAt
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("repeated reconciliation pass failed: %v", err)
	}
	if got := f.row(gone).ProviderAbsentAt; got != firstObserved {
		t.Fatalf("a repeated pass rewrote the observation time: %q, want %q", got, firstObserved)
	}
	if calls := f.provider.callCount(); calls != 2 {
		t.Fatalf("expected one inventory read per pass, got %d reads over two passes", calls)
	}

	// The listing carries the state, so a later consumer can filter on it.
	items := f.listedServers()
	if !items[gone].ProviderAbsent {
		t.Fatalf("the servers listing does not report provider_absent for server %d: %+v", gone, items[gone])
	}
	if items[gone].ProviderAbsentSince != firstObserved {
		t.Fatalf("the listing reports provider_absent_since %q, want %q",
			items[gone].ProviderAbsentSince, firstObserved)
	}
	if items[listed].ProviderAbsent || items[operator].ProviderAbsent {
		t.Fatal("the servers listing reports provider_absent for a server that was not recorded absent")
	}

	// A restart reads the state back from the store rather than from anything in
	// memory.
	f.restart()
	if !f.row(gone).ProviderAbsent() {
		t.Fatal("the provider-absent state did not survive a restart")
	}
	if got := f.row(gone).ProviderAbsentAt; got != firstObserved {
		t.Fatalf("the observation time changed across a restart: %q, want %q", got, firstObserved)
	}
	if f.row(listed).ProviderAbsent() {
		t.Fatal("a listed server was marked absent after a restart")
	}
	reloaded := f.listedServers()
	if !reloaded[gone].ProviderAbsent {
		t.Fatal("the servers listing lost the provider-absent state across a restart")
	}
}

func TestReconcileGigahostInventory_FailedOrPartialReadsChangeNothing(t *testing.T) {
	cases := []struct {
		name    string
		arrange func(f *inventoryFixture)
	}{
		{
			name:    "provider answers with an error",
			arrange: func(f *inventoryFixture) { f.provider.fail(http.StatusInternalServerError) },
		},
		{
			name:    "provider stops answering",
			arrange: func(f *inventoryFixture) { f.provider.hang() },
		},
		{
			name: "inventory enumerates the account incompletely",
			arrange: func(f *inventoryFixture) {
				// The page says the account holds three servers; the provider
				// listed one. That is not evidence about the other two.
				f.provider.set(partialInventoryJSON(501))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			listed := f.seedServer("Listed", providerProtocols(501))
			knownAbsent := f.seedServer("Known absent", providerProtocols(502))

			// A previous successful read recorded 502 as gone; this pass must not
			// disturb that either way.
			recorded := time.Now().UTC().Add(-time.Hour)
			if err := f.db.SetServerProviderAbsence(context.Background(), knownAbsent, recorded); err != nil {
				t.Fatalf("failed to seed the recorded absence: %v", err)
			}
			before := f.row(knownAbsent).ProviderAbsentAt

			tc.arrange(f)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			if err := f.reconcile(ctx); err == nil {
				t.Fatal("an unanswered or incomplete inventory read was treated as an answer")
			}

			if got := f.row(knownAbsent).ProviderAbsentAt; got != before {
				t.Fatalf("a failed read changed the recorded absence: %q, want %q", got, before)
			}
			if f.row(listed).ProviderAbsent() {
				t.Fatal("a failed read recorded absence for a server it never judged")
			}

			// The same failed pass, repeated, still changes nothing.
			if err := f.reconcile(ctx); err == nil {
				t.Fatal("a repeated failed read was treated as an answer")
			}
			if got := f.row(knownAbsent).ProviderAbsentAt; got != before {
				t.Fatalf("a repeated failed read changed the recorded absence: %q, want %q", got, before)
			}
			if f.row(listed).ProviderAbsent() {
				t.Fatal("a repeated failed read recorded absence")
			}

			// Control: this fixture and this pass do change state once the provider
			// answers. Without it, "nothing changed" above would be
			// indistinguishable from a pass that never ran.
			f.provider.set(inventoryJSON(599))
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("control pass failed: %v", err)
			}
			if !f.row(listed).ProviderAbsent() {
				t.Fatal("the reconciliation never changes state on this fixture, so its 'nothing changed' assertions prove nothing")
			}
		})
	}
}

func TestReconcileGigahostInventory_CorrectsAServerThatReappears(t *testing.T) {
	f := newInventoryFixture(t)
	gone := f.seedServer("Reappearing", providerProtocols(502))

	// A successful read of an account that holds no servers at all is still an
	// answer: the row it provisioned is absent.
	f.provider.set(inventoryJSON())
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}
	if !f.row(gone).ProviderAbsent() {
		t.Fatal("a server absent from an enumerated empty account was not recorded absent")
	}

	// The provider lists it again.
	f.provider.set(inventoryJSON(502))
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass after the server reappeared failed: %v", err)
	}
	if f.row(gone).ProviderAbsent() {
		t.Fatal("a server the provider lists again stayed marked absent")
	}
	if got := f.row(gone).ProviderAbsentAt; got != "" {
		t.Fatalf("the cleared state kept an observation time: %q", got)
	}
	if items := f.listedServers(); items[gone].ProviderAbsent {
		t.Fatal("the servers listing still reports the corrected server as absent")
	}
}

// The provider server id a row carries survives a JSON round trip through the
// protocols blob, so it can arrive in several shapes. Each shape is a real input
// here, and everything that cannot name a provider server must be refused: a
// truncated or invented id would judge a row by a different server's existence.
func TestProviderBackedServerID(t *testing.T) {
	cases := []struct {
		name      string
		protocols map[string]any
		wantID    int64
		wantOK    bool
	}{
		{"JSON number", map[string]any{"provider": "gigahost", "provider_server_id": float64(7)}, 7, true},
		{"stored integer", map[string]any{"provider": "gigahost", "provider_server_id": int64(7)}, 7, true},
		{"plain int", map[string]any{"provider": "gigahost", "provider_server_id": 7}, 7, true},
		{"decimal text", map[string]any{"provider": "gigahost", "provider_server_id": "7"}, 7, true},
		{"padded text", map[string]any{"provider": "Gigahost", "provider_server_id": " 7 "}, 7, true},
		{"fractional number is not an id", map[string]any{"provider": "gigahost", "provider_server_id": 7.5}, 0, false},
		{"zero is not an id", map[string]any{"provider": "gigahost", "provider_server_id": 0}, 0, false},
		{"negative is not an id", map[string]any{"provider": "gigahost", "provider_server_id": -3}, 0, false},
		{"text that is not a number", map[string]any{"provider": "gigahost", "provider_server_id": "abc"}, 0, false},
		{"missing id", map[string]any{"provider": "gigahost"}, 0, false},
		{"another provider", map[string]any{"provider": "other", "provider_server_id": 7}, 0, false},
		{"no provider recorded", map[string]any{"awg": map[string]any{"installed": true}}, 0, false},
		{"nil protocols", nil, 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := providerBackedServerID(tc.protocols)
			if ok != tc.wantOK {
				t.Fatalf("providerBackedServerID(%v) ok = %v, want %v", tc.protocols, ok, tc.wantOK)
			}
			if id != tc.wantID {
				t.Fatalf("providerBackedServerID(%v) id = %d, want %d", tc.protocols, id, tc.wantID)
			}
		})
	}
}

// An inventory answer that contains an entry the panel cannot identify is not a
// complete answer about the account, and must never become durable evidence that a
// server is gone.
//
// Three shapes reach the panel this way: a null element, an element without a
// server id, and an element whose id the client cannot parse. In each case the
// good entry beside it names a real server, so a filter-the-bad-entries
// implementation would silently conclude that every other row is absent. The
// control beside each case proves the same fixture and pass DO record absence when
// every entry is identified, so the refusal is about identity rather than a pass
// that never runs.
func TestReconcileGigahostInventory_UnidentifiableEntryMarksNothingAbsent(t *testing.T) {
	cases := []struct {
		name      string
		inventory string
	}{
		{
			name:      "null element beside an identified one",
			inventory: `{"meta":{"page":1,"total_pages":1,"total":2},"data":[null,{"srv_id":501,"status":"active"}]}`,
		},
		{
			name:      "element without a server id",
			inventory: `{"meta":{"page":1,"total_pages":1,"total":2},"data":[{"status":"active"},{"srv_id":501,"status":"active"}]}`,
		},
		{
			name:      "element with an unparseable server id",
			inventory: `{"meta":{"page":1,"total_pages":1,"total":2},"data":[{"srv_id":"not-a-number","status":"active"},{"srv_id":501,"status":"active"}]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newInventoryFixture(t)
			listed := f.seedServer("Listed", providerProtocols(501))
			unlisted := f.seedServer("Not listed", providerProtocols(502))

			f.provider.set(tc.inventory)
			if err := f.reconcile(context.Background()); err == nil {
				t.Fatal("an inventory containing an unidentifiable entry was accepted as a complete answer")
			}

			for _, id := range []int64{listed, unlisted} {
				if f.row(id).ProviderAbsent() {
					t.Fatalf("server %d was marked provider-absent from an answer that could not identify every entry", id)
				}
			}

			// Control: the identical fixture, with every entry identified, records the
			// absence of the row it does not list. Without this, the assertions above
			// would also pass if the pass never wrote anything at all.
			f.provider.set(inventoryJSON(501))
			if err := f.reconcile(context.Background()); err != nil {
				t.Fatalf("control pass failed: %v", err)
			}
			if f.row(listed).ProviderAbsent() {
				t.Fatal("the control pass marked a listed server absent")
			}
			if !f.row(unlisted).ProviderAbsent() {
				t.Fatal("the control pass did not mark the unlisted server absent, so the refusal assertions above prove nothing")
			}
		})
	}
}

// The identity gate itself, so the rule is pinned independently of the provider
// transport: an entry without a positive server id refuses the whole answer, while
// a complete answer (including a legitimately empty account) is accepted.
func TestGigahostIdentifiedServerIDs(t *testing.T) {
	identified, err := gigahostIdentifiedServerIDs([]gigahost.ServerInfo{{ID: 501}, {ID: 502}})
	if err != nil {
		t.Fatalf("a fully identified answer was refused: %v", err)
	}
	if len(identified) != 2 {
		t.Fatalf("identified ids = %d, want 2", len(identified))
	}
	for _, id := range []int64{501, 502} {
		if _, ok := identified[id]; !ok {
			t.Fatalf("id %d missing from the identified set", id)
		}
	}

	if _, err := gigahostIdentifiedServerIDs(nil); err != nil {
		t.Fatalf("an enumerated empty account was refused: %v", err)
	}

	for _, entry := range []gigahost.ServerInfo{{ID: 0}, {ID: -7}} {
		if _, err := gigahostIdentifiedServerIDs([]gigahost.ServerInfo{{ID: 501}, entry}); err == nil {
			t.Fatalf("an answer containing entry %+v was accepted", entry)
		}
	}
}
