package handlers

// F989-07: the server-detail endpoint's documented answer is an envelope whose data
// is an ARRAY. The previous reader accepted only an object, so a same-account
// deployment recorded no owner and a server the detail endpoint still reported stayed
// parked.
//
// F989-05 (remainder): a detail read may never conclude absence. Absence has exactly
// one source - the inventory answer - and only when nothing in the pass showed that
// answer does not enumerate the account.
//
// Two reproductions from the review are pinned here: a registration against the real
// HTTP client and SQLite that must record the owner from the array shape, and a
// detail-only reappearance that must unpark the server. Each has a control in the
// same run.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"net/http"
	"net/http/httptest"
	"strings"
)

// isDetailPath reports whether the path is the single-server detail endpoint.
func isDetailPath(path string) bool {
	_, ok := perServerPathID(path)
	return ok
}

// A deployment that completes under a known account must record that owner, from the
// documented array shape as well as the object shape. The provider's own answer for
// the server is the only source; the configured account is never borrowed.
func TestRegistrationRecordsOwnerFromTheDocumentedDetailShapes(t *testing.T) {
	cases := []struct {
		name       string
		array      bool
		detailBody string
		status     int
		wantOwner  string
	}{
		{
			name:      "documented data array",
			array:     true,
			wantOwner: fixtureAccount,
		},
		{
			name:      "object envelope control",
			array:     false,
			wantOwner: fixtureAccount,
		},
		{
			name:      "a detail refusal records unknown, never the configured account",
			status:    http.StatusForbidden,
			wantOwner: "",
		},
		{
			name:       "an answer naming another server records unknown",
			detailBody: `{"meta":{"status":200},"data":[{"srv_id":4242,"cust_id":"acct-north"}]}`,
			wantOwner:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// One store, one handler, one real provider client against a local server.
			path := t.TempDir() + "/owner_test.db"
			db, err := database.Open(path, testSecretKey)
			if err != nil {
				t.Fatalf("failed to open the store: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })

			var detailPath string
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/account":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(accountJSON(fixtureAccount, false)))
				case isDetailPath(r.URL.Path):
					detailPath = r.URL.Path
					if tc.status != 0 {
						w.WriteHeader(tc.status)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					body := tc.detailBody
					if body == "" {
						body = perServerJSON(9001, fixtureAccount, tc.array)
					}
					_, _ = w.Write([]byte(body))
				default:
					http.NotFound(w, r)
				}
			}))
			defer provider.Close()

			client, err := gigahost.NewClient(gigahost.Config{BaseURL: provider.URL, APIKey: "flux_live_" + strings.Repeat("a", 64)})
			if err != nil {
				t.Fatalf("failed to build the provider client: %v", err)
			}

			cfg := &config.Config{AppVersion: config.AppVersion, AppCodename: config.AppCodename, SecretKey: testSecretKey}
			h := NewHandlers(Dependencies{Config: cfg, DB: db})
			h.SetGigahostClient(client)

			fingerprint := ssh.FingerprintSHA256(newHandshakeSigner(t).PublicKey())
			req := GigahostDeployRequest{ServerName: "registered", SSHPort: 22, SSHPassword: "fixture-only"}

			// The composition both registration paths use.
			owner := h.gigahostServerAccount(context.Background(), client, 9001)
			server, err := h.registerDeployServer(context.Background(), req, nil, 0, 9001, "198.51.100.9", fingerprint, owner)
			if err != nil {
				t.Fatalf("registration failed: %v", err)
			}
			if detailPath != "/servers/9001" {
				t.Fatalf("detail read went to %q, want /servers/9001", detailPath)
			}
			if server.ProviderAccountID != tc.wantOwner {
				t.Fatalf("registered owner = %q, want %q", server.ProviderAccountID, tc.wantOwner)
			}
			stored, err := db.GetServer(context.Background(), server.ID)
			if err != nil || stored == nil {
				t.Fatalf("failed to read the registered row: %v", err)
			}
			if stored.ProviderAccountID != tc.wantOwner {
				t.Fatalf("stored owner = %q, want %q", stored.ProviderAccountID, tc.wantOwner)
			}
		})
	}
}

// A server the detail endpoint still reports must be unparked even when the listing
// does not mention it: the documented array answer is positive evidence that the
// server exists.
func TestReconcileGigahostInventory_UnparksDetailOnlyReappearance(t *testing.T) {
	f := newInventoryFixture(t)
	returned := f.seedServer("Returned", providerProtocols(501))
	control := f.seedServer("Listed control", providerProtocols(502))

	// The row was marked absent by an earlier pass.
	if err := f.db.SetServerProviderAbsence(context.Background(), returned, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("failed to seed the mark: %v", err)
	}

	// The listing still omits 501 (the key is scope-limited to 502), while the detail
	// endpoint reports 501 in the documented array shape.
	f.provider.set(inventoryJSON(502))
	f.provider.setDetailArray(true)
	f.provider.answerPerServer(501, http.StatusOK)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}

	if f.row(returned).ProviderAbsent() {
		t.Fatal("a server the detail endpoint reports stayed parked")
	}
	if f.row(control).ProviderAbsent() {
		t.Fatal("a listed server was marked absent")
	}
	if items := f.listedServers(); items[returned].ProviderAbsent {
		t.Fatal("the servers listing still reports the returned server as absent")
	}

	// Control in the same run: the same fixture with the detail endpoint answering
	// "not reported" leaves the mark alone, so the unpark above is about the answer.
	if err := f.db.SetServerProviderAbsence(context.Background(), returned, time.Now().UTC()); err != nil {
		t.Fatalf("failed to re-mark: %v", err)
	}
	f.provider.answerPerServer(501, http.StatusNotFound)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("control pass failed: %v", err)
	}
	if !f.row(returned).ProviderAbsent() {
		t.Fatal("a detail answer that names no server cleared a mark, so the unpark assertion proves nothing")
	}
}

// No detail read may conclude absence. While this key's visibility is demonstrably
// narrower than the account, the pass records no absence at all - including for a row
// whose detail read says "not reported" - and it records absence again once nothing
// contradicts the listing.
func TestReconcileGigahostInventory_DetailReadNeverConcludesAbsence(t *testing.T) {
	f := newInventoryFixture(t)
	inScope := f.seedServer("In scope", providerProtocols(501))
	refused := f.seedServer("Outside this key", providerProtocols(502))
	gone := f.seedServer("Deleted", providerProtocols(503))

	// A filtered listing of a three-server account, an explicit refusal for the
	// out-of-scope server, and a "not reported" answer for the deleted one.
	f.provider.set(inventoryJSON(501))
	f.provider.setAccountServers(3)
	f.provider.answerPerServer(502, http.StatusForbidden)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}

	if f.row(inScope).ProviderAbsent() {
		t.Fatal("a listed server was marked absent")
	}
	if f.row(refused).ProviderAbsent() {
		t.Fatal("a server outside the key's visibility was marked absent")
	}
	if f.row(gone).ProviderAbsent() {
		t.Fatal("a detail 404 recorded absence while the key's visibility was narrower than the account")
	}

	// Control in the same run: the account summary now reports one server, which is what
	// the listing enumerated, so the answer is certified complete and both omitted
	// servers are recorded absent. The detail answers are unchanged between the passes.
	f.provider.setAccountServers(1)
	f.provider.answerPerServer(502, http.StatusNotFound)
	f.confirm(context.Background())
	if !f.row(refused).ProviderAbsent() {
		t.Fatal("the control pass did not record an absent server, so the refusal above proves nothing")
	}
	if !f.row(gone).ProviderAbsent() {
		t.Fatal("the control pass did not record the second absent server")
	}
	if f.row(inScope).ProviderAbsent() {
		t.Fatal("the control pass marked a listed server absent")
	}
}

// A detail answer the client cannot parse changes nothing: it is not "present", and it
// is not "absent".
func TestReconcileGigahostInventory_UnparseableDetailChangesNothing(t *testing.T) {
	f := newInventoryFixture(t)
	marked := f.seedServer("Marked", providerProtocols(501))
	if err := f.db.SetServerProviderAbsence(context.Background(), marked, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("failed to seed the mark: %v", err)
	}
	recorded := f.row(marked).ProviderAbsentAt

	f.provider.set(inventoryJSON())
	f.provider.answerPerServer(501, http.StatusOK)
	// A 200 whose body is not a server in any documented shape.
	f.provider.setDetailBody(`{"meta":{"status":200},"data":[]}`)
	if err := f.reconcile(context.Background()); err != nil {
		t.Fatalf("reconciliation pass failed: %v", err)
	}
	if got := f.row(marked).ProviderAbsentAt; got != recorded {
		t.Fatalf("an unparseable detail answer changed the mark: %q, want %q", got, recorded)
	}
}
