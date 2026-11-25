package gigahost

// The provider documents the account identifier as a JSON number on GET /account
// (`"cust_id": 12345`) and sends the same identifier as text inside /servers
// entries (`"cust_id":"19998"`). Both shapes must decode to the same opaque value:
// treating the documented one as "no account" turns a healthy account into an
// unknown one and silently disables every consumer of the identity.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetAccount_AcceptsDocumentedIdentifierShapes(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantCustID string
		wantID     string
	}{
		{
			name:       "numeric cust_id, the documented GET /account shape",
			body:       `{"meta":{"status":200},"data":{"cust_id":12345,"cust_name":"Acme AS","balance":100}}`,
			wantCustID: "12345",
			wantID:     "12345",
		},
		{
			name:       "text cust_id",
			body:       `{"meta":{"status":200},"data":{"cust_id":"12345","cust_name":"Acme AS"}}`,
			wantCustID: "12345",
			wantID:     "12345",
		},
		{
			name:       "numeric id without cust_id",
			body:       `{"meta":{"status":200},"data":{"id":7777,"cust_name":"Acme AS"}}`,
			wantCustID: "",
			wantID:     "7777",
		},
		{
			name:       "both identifiers",
			body:       `{"meta":{"status":200},"data":{"id":1,"cust_id":12345}}`,
			wantCustID: "12345",
			wantID:     "1",
		},
		{
			name:       "padded text is trimmed to the identifier",
			body:       `{"meta":{"status":200},"data":{"cust_id":"  12345  "}}`,
			wantCustID: "12345",
			wantID:     "12345",
		},
		{
			name:       "large numeric id keeps every digit",
			body:       `{"meta":{"status":200},"data":{"cust_id":9007199254740993}}`,
			wantCustID: "9007199254740993",
			wantID:     "9007199254740993",
		},
		{
			name:       "null identifier names no account and is not an error",
			body:       `{"meta":{"status":200},"data":{"cust_id":null,"cust_name":"Acme AS"}}`,
			wantCustID: "",
			wantID:     "",
		},
		{
			name:       "wrapped account envelope",
			body:       `{"meta":{"status":200},"account":{"cust_id":12345,"cust_name":"Acme AS"}}`,
			wantCustID: "12345",
			wantID:     "12345",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			account, err := accountFromBody(t, tc.body)
			if err != nil {
				t.Fatalf("documented shape refused: %v", err)
			}
			if account.CustID != tc.wantCustID {
				t.Fatalf("cust_id = %q, want %q", account.CustID, tc.wantCustID)
			}
			if account.ID != tc.wantID {
				t.Fatalf("id = %q, want %q", account.ID, tc.wantID)
			}
		})
	}
}

// An identifier the client cannot read must be an error, not an empty account:
// "we could not read the identifier" and "this account has no servers" must never
// look the same to a caller.
func TestGetAccount_UnreadableIdentifierIsAnError(t *testing.T) {
	for _, body := range []string{
		`{"meta":{"status":200},"data":{"cust_id":true,"cust_name":"Acme AS"}}`,
		`{"meta":{"status":200},"data":{"cust_id":1.5,"cust_name":"Acme AS"}}`,
		`{"meta":{"status":200},"data":{"cust_id":{"id":1},"cust_name":"Acme AS"}}`,
	} {
		if _, err := accountFromBody(t, body); err == nil {
			t.Fatalf("unreadable identifier in %s was accepted as an account", body)
		}
	}
}

// The per-server answer is the authority for ownership, and it carries the same
// identifier shape.
func TestGetServer_CarriesTheOwningAccountAndDistinguishesRefusal(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantCustID string
		wantErr    error
	}{
		{
			name:       "numeric cust_id",
			status:     http.StatusOK,
			body:       `{"meta":{"status":200},"data":{"srv_id":3523,"cust_id":19998}}`,
			wantCustID: "19998",
		},
		{
			name:       "text cust_id",
			status:     http.StatusOK,
			body:       `{"meta":{"status":200},"data":{"srv_id":"3523","cust_id":"19998"}}`,
			wantCustID: "19998",
		},
		{
			name:    "a server outside the key's visibility is a refusal, not absence",
			status:  http.StatusForbidden,
			body:    `{"meta":{"status":403},"data":[]}`,
			wantErr: ErrUnauthorized,
		},
		{
			name:    "a server the provider does not have is not found",
			status:  http.StatusNotFound,
			body:    `{"meta":{"status":404},"data":[]}`,
			wantErr: ErrNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/servers/3523" {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("a", 64)})
			if err != nil {
				t.Fatal(err)
			}
			info, err := client.GetServer(context.Background(), 3523)
			if tc.wantErr != nil {
				if err == nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("GetServer error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := info.CustID.String(); got != tc.wantCustID {
				t.Fatalf("server cust_id = %q, want %q", got, tc.wantCustID)
			}
		})
	}
}

// accountFromBody serves one body for GET /account and returns the decoded account.
func accountFromBody(t *testing.T, body string) (*AccountInfo, error) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatalf("failed to build the client: %v", err)
	}
	return client.GetAccount(context.Background())
}

// A per-server answer that names no server, or a request for an impossible id, is
// refused rather than returned as an empty server: an answer without an id would
// make "the provider says nothing" look like "the server exists".
func TestGetServer_RefusesAnswersWithoutAServer(t *testing.T) {
	cases := []struct {
		name string
		id   int64
		body string
	}{
		{name: "null data", id: 3523, body: `{"meta":{"status":200},"data":null}`},
		{name: "answer without a server id", id: 3523, body: `{"meta":{"status":200},"data":{"cust_id":19998}}`},
		{name: "unparseable answer", id: 3523, body: `not-json`},
		{name: "impossible server id", id: 0, body: `{"data":{"srv_id":1}}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("a", 64)})
			if err != nil {
				t.Fatal(err)
			}
			if info, err := client.GetServer(context.Background(), tc.id); err == nil {
				t.Fatalf("answer %q was accepted as server %+v", tc.body, info)
			}
		})
	}

	// Control: a bare server object, which the endpoint may also answer with, is a
	// usable answer and carries the account.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"srv_id":3523,"cust_id":"19998"}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	info, err := client.GetServer(context.Background(), 3523)
	if err != nil {
		t.Fatalf("bare server object refused: %v", err)
	}
	if info.CustID.String() != "19998" {
		t.Fatalf("bare object cust_id = %q, want 19998", info.CustID.String())
	}
}

// The credential's own scope is the certificate's authority input, so its decode is
// pinned here: the documented permissions object with servers.all true and no ids is
// the only shape that states "this key may enumerate the whole account". Everything
// else either states a restriction or states nothing.
func TestAccountInfo_EnumeratesWholeAccount(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		accountWide bool
		stated      bool
	}{
		{
			name:        "documented all-access servers permission",
			body:        `{"data":{"cust_id":12345,"permissions":{"servers":{"mode":"r","all":true}}}}`,
			accountWide: true,
			stated:      true,
		},
		{
			name:   "restricted to ids",
			body:   `{"data":{"cust_id":12345,"permissions":{"servers":{"mode":"r","all":false,"ids":[501,502]}}}}`,
			stated: true,
		},
		{
			name:   "all:false without ids",
			body:   `{"data":{"cust_id":12345,"permissions":{"servers":{"mode":"rw","all":false}}}}`,
			stated: true,
		},
		{
			name:   "servers permission without an all flag",
			body:   `{"data":{"cust_id":12345,"permissions":{"servers":{"mode":"r"}}}}`,
			stated: false,
		},
		{
			name:   "no permissions object (the documented GET /account shape)",
			body:   `{"data":{"cust_id":12345,"cust_name":"Acme AS","sshkeys":[],"orders":[]}}`,
			stated: false,
		},
		{
			name:   "permissions without a servers category",
			body:   `{"data":{"cust_id":12345,"permissions":{"dns":{"mode":"r","all":true}}}}`,
			stated: false,
		},
		{
			name:   "a contradiction is read as restricted",
			body:   `{"data":{"cust_id":12345,"permissions":{"servers":{"mode":"r","all":true,"ids":[501]}}}}`,
			stated: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			account, err := accountFromBody(t, tc.body)
			if err != nil {
				t.Fatalf("payload refused: %v", err)
			}
			accountWide, stated := account.EnumeratesWholeAccount()
			if accountWide != tc.accountWide || stated != tc.stated {
				t.Fatalf("EnumeratesWholeAccount = (%v, %v), want (%v, %v)", accountWide, stated, tc.accountWide, tc.stated)
			}
		})
	}
}
