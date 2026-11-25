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
