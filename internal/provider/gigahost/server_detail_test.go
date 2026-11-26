package gigahost

// The single-server answer decides both existence and ownership, so every documented
// shape is accepted strictly and everything else is refused. The provider documents
// the data ARRAY (docs.gigahost.no/api/servers, Get Server Details); the object
// envelope and a bare object unambiguously name one server too, so both are accepted.

import (
	"strings"
	"testing"
)

func TestDecodeServerDetail_DocumentedShapes(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantID   int64
		wantCust string
	}{
		{
			name:     "documented data array",
			body:     `{"meta":{"status":200},"data":[{"srv_id":3523,"cust_id":19998,"srv_name":"web01"}]}`,
			wantID:   3523,
			wantCust: "19998",
		},
		{
			name:     "object envelope",
			body:     `{"meta":{"status":200},"data":{"srv_id":3523,"cust_id":"19998"}}`,
			wantID:   3523,
			wantCust: "19998",
		},
		{
			name:     "bare object",
			body:     `{"srv_id":3523,"cust_id":"19998"}`,
			wantID:   3523,
			wantCust: "19998",
		},
		{
			name:     "array entry matched among several",
			body:     `{"data":[{"srv_id":4,"cust_id":"1"},{"srv_id":3523,"cust_id":"19998"}]}`,
			wantID:   3523,
			wantCust: "19998",
		},
		{
			name:     "numeric account identifier in the array",
			body:     `{"data":[{"srv_id":3523,"cust_id":19998}]}`,
			wantID:   3523,
			wantCust: "19998",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, err := decodeServerDetail([]byte(tc.body), 3523)
			if err != nil {
				t.Fatalf("documented shape refused: %v", err)
			}
			if server.ID != tc.wantID {
				t.Fatalf("server id = %d, want %d", server.ID, tc.wantID)
			}
			if got := server.CustID.String(); got != tc.wantCust {
				t.Fatalf("cust_id = %q, want %q", got, tc.wantCust)
			}
		})
	}
}

// A shape that carries no server - or a server other than the one asked for - is
// refused. Treating any of these as "the server exists" would record an owner that
// is not the server's, or unpark a server that is gone.
func TestDecodeServerDetail_RefusesShapesWithoutTheRequestedServer(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "empty data array", body: `{"meta":{"status":200},"data":[]}`},
		{name: "null data", body: `{"meta":{"status":200},"data":null}`},
		{name: "data of another JSON type", body: `{"meta":{"status":200},"data":"3523"}`},
		{name: "array entry without a server id", body: `{"data":[{"cust_id":"19998"}]}`},
		{name: "array with one unusable entry beside a good one", body: `{"data":[{"srv_id":3523},{"srv_id":0}]}`},
		{name: "array naming a different server", body: `{"data":[{"srv_id":4242,"cust_id":"19998"}]}`},
		{name: "the same server named twice", body: `{"data":[{"srv_id":3523},{"srv_id":3523}]}`},
		{name: "object naming a different server", body: `{"data":{"srv_id":4242}}`},
		{name: "object without a server id", body: `{"data":{"cust_id":"19998"}}`},
		{name: "bare object naming a different server", body: `{"srv_id":4242}`},
		{name: "payload is not an object", body: `[{"srv_id":3523}]`},
		{name: "payload is not JSON", body: `not-json`},
		{name: "empty payload", body: ``},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, err := decodeServerDetail([]byte(tc.body), 3523)
			if err == nil {
				t.Fatalf("answer was accepted as server %+v", server)
			}
			// The reason must name the problem, not just fail: an operator has to be
			// able to tell a malformed answer from a missing server.
			if strings.TrimSpace(err.Error()) == "" {
				t.Fatal("refusal carried no reason")
			}
		})
	}

	if _, err := decodeServerDetail([]byte(`{"srv_id":3523}`), 0); err == nil {
		t.Fatal("an impossible server id was requested")
	}
}
