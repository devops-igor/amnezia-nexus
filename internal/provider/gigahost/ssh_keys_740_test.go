package gigahost_test

// Provider-level contract tests for the account SSH key endpoints, against the
// documented shapes in the public API reference:
//
//	GET  /account        -> data.sshkeys[] {key_id, cust_id, key_name, key_added, key_data}
//	POST /account/sshkey -> 200, no id in the reply
//	POST /deploy/servers -> ssh_keys is an array of numeric ids
//
// No live or authenticated provider call is made: these are local HTTP fixtures.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// fixturePublicKeyA/B are valid OpenSSH public key lines built from real base64
// blobs, so the material comparison is exercised against well-formed input rather
// than a placeholder that a strict base64 decoder rejects.
var (
	fixtureKeyBlobA   = base64.StdEncoding.EncodeToString([]byte("fixture-key-material-A-0123456789"))
	fixtureKeyBlobB   = base64.StdEncoding.EncodeToString([]byte("fixture-key-material-B-0123456789"))
	fixturePublicKeyA = "ssh-ed25519 " + fixtureKeyBlobA + " nexus-managed"
	fixturePublicKeyB = "ssh-ed25519 " + fixtureKeyBlobB + " partner"
)

func keyTestClient(t *testing.T, handler http.HandlerFunc) gigahost.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := gigahost.NewClient(gigahost.Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client
}

// accountWithKeys is the documented GET /account body shape for the key list.
func accountWithKeys(keys string) string {
	return `{"meta":{"status":200,"status_message":"200 OK"},"data":{"cust_id":"1111","cust_name":"Example AS","sshkeys":[` + keys + `]}}`
}

func TestListSSHKeys_DocumentedShape(t *testing.T) {
	var calls atomic.Int32
	client := keyTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/account" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testAPIKey {
			t.Errorf("unexpected authorization header %q", got)
		}
		_, _ = w.Write([]byte(accountWithKeys(
			`{"key_id":"1","cust_id":"1111","key_name":"laptop","key_added":"1700000000","key_data":"` + fixturePublicKeyA + `"},` +
				`{"key_id":"12","cust_id":"1111","key_name":"partner","key_added":"1700000001","key_data":"` + fixturePublicKeyB + `"}`)))
	})

	keys, err := client.ListSSHKeys(context.Background())
	if err != nil {
		t.Fatalf("ListSSHKeys: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("expected exactly 1 GET /account call, got %d", calls.Load())
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].KeyName != "laptop" || keys[1].KeyName != "partner" {
		t.Errorf("unexpected key names: %+v", keys)
	}
	if id, err := keys[1].ID(); err != nil || id != 12 {
		t.Errorf("expected documented string key_id \"12\" to parse as 12, got %d / %v", id, err)
	}
}

func TestListSSHKeys_ErrorsAreReportedNotAbsent(t *testing.T) {
	client := keyTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"meta":{"status":500,"message":"upstream failure"}}`))
	})
	keys, err := client.ListSSHKeys(context.Background())
	if err == nil {
		t.Fatalf("expected an error, got keys=%+v", keys)
	}
	if !strings.Contains(err.Error(), "ssh keys") {
		t.Errorf("expected the failure to name the key read, got %v", err)
	}
}

func TestRegisterSSHKey_SendsDocumentedBody(t *testing.T) {
	var body map[string]string
	var method, path string
	client := keyTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		// The documented reply carries no key id; only the status is meaningful.
		_, _ = w.Write([]byte(`{"meta":{"status":200,"status_message":"200 OK"},"data":[]}`))
	})

	if err := client.RegisterSSHKey(context.Background(), "nexus-abc", fixturePublicKeyA); err != nil {
		t.Fatalf("RegisterSSHKey: %v", err)
	}
	if method != http.MethodPost || path != "/account/sshkey" {
		t.Errorf("expected POST /account/sshkey, got %s %s", method, path)
	}
	if body["name"] != "nexus-abc" {
		t.Errorf("expected documented name field, got %q", body["name"])
	}
	if body["data"] != fixturePublicKeyA {
		t.Errorf("expected the full public key line in data, got %q", body["data"])
	}
}

func TestRegisterSSHKey_AmbiguityClassification(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		ambiguous  bool
		wantReject bool
	}{
		{name: "invalid name is a decision", status: http.StatusBadRequest, body: `{"meta":{"status":400,"message":"Invalid name. Use 1-64 letters, digits, spaces or - _ . @"}}`, ambiguous: false, wantReject: true},
		{name: "invalid key is a decision", status: http.StatusBadRequest, body: `{"meta":{"status":400,"message":"SSH-key invalid."}}`, ambiguous: false, wantReject: true},
		{name: "unauthorized is a decision", status: http.StatusUnauthorized, body: `{"meta":{"status":401,"message":"nope"}}`, ambiguous: false, wantReject: true},
		{name: "server error is ambiguous", status: http.StatusInternalServerError, body: `{"meta":{"status":500}}`, ambiguous: true},
		{name: "gateway timeout is ambiguous", status: http.StatusGatewayTimeout, body: `{}`, ambiguous: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := keyTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			err := client.RegisterSSHKey(context.Background(), "nexus-abc", fixturePublicKeyA)
			if err == nil {
				t.Fatalf("expected an error for status %d", tc.status)
			}
			ambiguous := gigahost.IsRegistrationAmbiguous(err)
			if ambiguous != tc.ambiguous {
				t.Errorf("IsRegistrationAmbiguous = %t, want %t (err: %v)", ambiguous, tc.ambiguous, err)
			}
			if tc.wantReject && ambiguous {
				t.Errorf("a provider decision must never be treated as an ambiguous outcome: %v", err)
			}
		})
	}
}

func TestRegistrationAmbiguity_NilIsNotAmbiguous(t *testing.T) {
	if gigahost.IsRegistrationAmbiguous(nil) {
		t.Error("a successful registration must not be ambiguous")
	}
}

func TestManagedKeyName_DocumentedAlphabetAndStable(t *testing.T) {
	first, err := gigahost.ManagedKeyName(fixturePublicKeyA)
	if err != nil {
		t.Fatalf("ManagedKeyName: %v", err)
	}
	second, err := gigahost.ManagedKeyName("  " + fixturePublicKeyA + "  ")
	if err != nil {
		t.Fatalf("ManagedKeyName (whitespace): %v", err)
	}
	if first != second {
		t.Errorf("same key material must yield the same label, got %q and %q", first, second)
	}
	if other, err := gigahost.ManagedKeyName(fixturePublicKeyB); err != nil || other == first {
		t.Errorf("different key material must yield a different label: %q vs %q (err %v)", first, other, err)
	}
	if len(first) > 64 {
		t.Errorf("label must fit the documented 1-64 character limit, got %d", len(first))
	}
	for _, c := range first {
		allowed := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '@' || c == ' '
		if !allowed {
			t.Errorf("label %q contains %q outside the documented alphabet", first, c)
		}
	}

	if _, err := gigahost.ManagedKeyName("not-a-key"); err == nil {
		t.Error("a non-key line must not produce a label")
	}
}

func TestNormalizeAuthorizedKey_ComparesMaterialNotComment(t *testing.T) {
	withComment := "ssh-ed25519 " + fixtureKeyBlobA + " nexus-managed"
	noComment := "ssh-ed25519 " + fixtureKeyBlobA
	renamed := "ssh-ed25519 " + fixtureKeyBlobA + " someone-else@host"

	if !gigahost.AuthorizedKeyMatches(withComment, noComment) {
		t.Error("the same material must match regardless of the trailing comment")
	}
	if !gigahost.AuthorizedKeyMatches(withComment, renamed) {
		t.Error("the same material must match a different comment")
	}
	if gigahost.AuthorizedKeyMatches(withComment, fixturePublicKeyB) {
		t.Error("different key material must not match")
	}

	for _, bad := range []string{"", "ssh-ed25519", "not-a-key AAAA", "ssh-ed25519 !!!not-base64!!!"} {
		if _, err := gigahost.NormalizeAuthorizedKey(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

func TestFindSSHKeyByMaterial_FindsExactEntry(t *testing.T) {
	keys := []gigahost.SSHKeyInfo{
		{KeyID: "1", KeyName: "laptop", KeyData: fixturePublicKeyB},
		{KeyID: "7", KeyName: "nexus", KeyData: fixturePublicKeyA},
	}
	match, ok := gigahost.FindSSHKeyByMaterial(keys, fixturePublicKeyA)
	if !ok || match.KeyID != "7" {
		t.Errorf("expected key id 7, got %+v (found=%t)", match, ok)
	}
	if _, ok := gigahost.FindSSHKeyByMaterial(keys, "ssh-ed25519 "+base64.StdEncoding.EncodeToString([]byte("absent-key-material"))); ok {
		t.Error("absent material must not match")
	}
}

// TestOrderRequest_SSHKeysSerialization proves the order body carries the numeric
// ids under the documented field name, and that an order without keys is
// unchanged from before this existed.
func TestOrderRequest_SSHKeysSerialization(t *testing.T) {
	withKeys, err := json.Marshal(gigahost.OrderRequest{
		PID: 101, PriceID: 555, RegionID: 1, OSID: 12,
		BillingPeriod: gigahost.BillingPeriodHourly, Quantity: 1,
		SSHKeys: []int64{12, 15},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(withKeys, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, present := decoded["ssh_keys"]
	if !present {
		t.Fatalf("expected ssh_keys in the order body, got %s", withKeys)
	}
	ids, ok := raw.([]any)
	if !ok || len(ids) != 2 {
		t.Fatalf("expected a numeric array under ssh_keys, got %v", raw)
	}
	for i, want := range []float64{12, 15} {
		if ids[i] != want {
			t.Errorf("ssh_keys[%d] = %v, want %v (numbers, not strings)", i, ids[i], want)
		}
	}

	withoutKeys, err := json.Marshal(gigahost.OrderRequest{
		PID: 101, PriceID: 555, RegionID: 1, OSID: 12,
		BillingPeriod: gigahost.BillingPeriodHourly, Quantity: 1,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(withoutKeys), "ssh_keys") {
		t.Errorf("an order with no managed key must not gain an ssh_keys field: %s", withoutKeys)
	}
}

// TestOrderServer_SendsRegisteredKeyID is the wire-level proof: the id read from
// the account is what the order request carries.
func TestOrderServer_SendsRegisteredKeyID(t *testing.T) {
	var posted map[string]any
	client := keyTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/servers" {
			_, _ = w.Write([]byte(`{"meta":{"status":200,"page":1,"total_pages":1,"total":0},"data":[]}`))
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
			t.Errorf("failed to decode order body: %v", err)
		}
		_, _ = w.Write([]byte(`{"meta":{"status":200},"data":{"success":true,"order_ids":[10001],"rate_hourly":0.14,"currency":"NOK"}}`))
	})

	resp, err := client.OrderServerSafe(context.Background(), gigahost.OrderRequest{
		PID: 101, PriceID: 555, RegionID: 1, OSID: 12,
		BillingPeriod: gigahost.BillingPeriodHourly, Quantity: 1,
		SSHKeys: []int64{7},
	})
	if err != nil {
		t.Fatalf("OrderServerSafe: %v", err)
	}
	if resp.OrderID != "10001" {
		t.Errorf("expected order id 10001, got %q", resp.OrderID)
	}
	ids, ok := posted["ssh_keys"].([]any)
	if !ok || len(ids) != 1 || ids[0] != float64(7) {
		t.Errorf("expected ssh_keys [7] in the order body, got %v", posted["ssh_keys"])
	}
}
