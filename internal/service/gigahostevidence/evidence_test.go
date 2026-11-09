package gigahostevidence

// Behavioral coverage for the one provider-evidence collector, driven through
// controlled HTTP fixtures: no test here talks to a real provider account.
//
// The assertions that matter most are the negative ones. A collector that turns
// an omission, a timeout or a locally invented identifier into "the provider says
// it is gone" is the defect this package exists to prevent, so each of those is
// pinned separately.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
)

// fixtureAPIKey is a syntactically valid test credential. It is an obvious
// placeholder, not a real key.
const fixtureAPIKey = "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fixtureServer answers the three GETs the collector uses. Each handler is
// injected per test so a test can decide exactly what the provider "said".
type fixtureServer struct {
	servers map[string]any
	status  map[string]any
	deploy  map[string]http.HandlerFunc
	calls   map[string]int
}

// newFixture starts a provider fixture.
func newFixture(t *testing.T) (*fixtureServer, *httptest.Server) {
	t.Helper()
	f := &fixtureServer{calls: map[string]int{}, deploy: map[string]http.HandlerFunc{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/servers":
			f.calls["servers"]++
			if f.servers == nil {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(f.servers)
		case r.URL.Path == "/deploy/servers":
			f.calls["catalog"]++
			if f.status == nil {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"tiers":[],"regions":[],"currency":"NOK"}}`))
				return
			}
			_ = json.NewEncoder(w).Encode(f.status)
		case r.URL.Path == "/deploy/status":
			id := r.URL.Query().Get("ids")
			f.calls["deploy:"+id]++
			if h, ok := f.deploy[id]; ok {
				h(w, r)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"unexpected path"}`))
		}
	}))
	return f, srv
}

// client builds a client against the fixture.
func (f *fixtureServer) client(t *testing.T, srv *httptest.Server) gigahost.Client {
	t.Helper()
	c, err := gigahost.NewClient(gigahost.Config{BaseURL: srv.URL, APIKey: fixtureAPIKey})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c
}

// ledgerRow builds a ledger row.
func ledgerRow(id int64, orderID string, serverID int64, status string) models.GigahostOrder {
	return models.GigahostOrder{
		ID: id, OrderID: orderID, ServerID: serverID, Status: status,
		PlanID: 202, RegionID: 2, HourlyPriceNOK: 0.057, MonthlyCapNOK: 41, Currency: "NOK",
	}
}

// TestCollectConclusiveTerminationIsReleaseEvidence pins the one positive case.
func TestCollectConclusiveTerminationIsReleaseEvidence(t *testing.T) {
	f, srv := newFixture(t)
	defer srv.Close()
	f.servers = map[string]any{
		"meta": map[string]any{"page": 1, "total_pages": 1, "total": 1},
		"data": []map[string]any{{
			"id": 7, "order_id": "10001", "status": "terminated", "bw_is_hourly": true,
		}},
	}

	orders := []models.GigahostOrder{ledgerRow(1, "10001", 7, "ready")}
	res := Collect(context.Background(), f.client(t, srv), serversFrom(t, f, srv), orders,
		Limits{MaxOrderLookups: 5})

	obs, ok := res.Observations[1]
	if !ok {
		t.Fatal("the live ledger row was not observed")
	}
	if !obs.Evidence.ServerFound || obs.Evidence.ServerStatus != "terminated" {
		t.Fatalf("evidence = %+v, want the matching server reported as terminated", obs.Evidence)
	}
	if obs.Expect.ID != 1 || obs.Expect.Status != "ready" {
		t.Fatalf("observation is not bound to the row it was made against: %+v", obs.Expect)
	}
}

// TestCollectOmissionIsNotAbsence pins contract fact E1: the deployment status
// endpoint also omits canceled orders and deleted servers, so a not-found answer
// must be recorded as an omission and never as proof.
func TestCollectOmissionIsNotAbsence(t *testing.T) {
	f, srv := newFixture(t)
	defer srv.Close()

	orders := []models.GigahostOrder{ledgerRow(1, "10001", 0, "ready")}
	res := Collect(context.Background(), f.client(t, srv), nil, orders, Limits{MaxOrderLookups: 5})

	obs := res.Observations[1]
	if !obs.Evidence.OrderOmittedFromDeployStatus {
		t.Fatalf("a 404 was not recorded as an omission: %+v", obs.Evidence)
	}
	if obs.Evidence.ProviderOrderFound || obs.Evidence.OrderQueryFailed {
		t.Fatalf("an omission must not be reported as a found order or a failure: %+v", obs.Evidence)
	}
}

// TestCollectFailedQueryIsNotAbsence pins the timeout/communication case.
func TestCollectFailedQueryIsNotAbsence(t *testing.T) {
	f, srv := newFixture(t)
	defer srv.Close()
	f.deploy["10001"] = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"upstream unavailable"}`))
	}

	orders := []models.GigahostOrder{ledgerRow(1, "10001", 0, "ready")}
	res := Collect(context.Background(), f.client(t, srv), nil, orders, Limits{MaxOrderLookups: 5})

	obs := res.Observations[1]
	if !obs.Evidence.OrderQueryFailed {
		t.Fatalf("a 500 was not recorded as a failed query: %+v", obs.Evidence)
	}
	if obs.Evidence.ProviderOrderFound || obs.Evidence.OrderOmittedFromDeployStatus {
		t.Fatalf("a failure must not be reported as an answer: %+v", obs.Evidence)
	}
}

// TestCollectNeverQueriesASyntheticID pins the rule that a locally invented
// identifier is not asked about at all: any answer would be meaningless.
func TestCollectNeverQueriesASyntheticID(t *testing.T) {
	f, srv := newFixture(t)
	defer srv.Close()

	orders := []models.GigahostOrder{
		ledgerRow(1, "intent_1700000000000000000", 0, "unknown"),
		ledgerRow(2, "unknown_abc", 0, "unknown"),
	}
	res := Collect(context.Background(), f.client(t, srv), nil, orders, Limits{MaxOrderLookups: 5})

	if res.OrderLookups != 0 {
		t.Fatalf("order lookups = %d, want 0 for synthetic ids", res.OrderLookups)
	}
	for _, id := range []int64{1, 2} {
		obs, ok := res.Observations[id]
		if !ok {
			t.Fatalf("record %d was not reported", id)
		}
		if obs.Evidence != (gigahostbudget.Evidence{}) {
			t.Fatalf("record %d carries evidence for an id the provider never issued: %+v", id, obs.Evidence)
		}
	}
	for key := range f.calls {
		if len(key) > 7 && key[:7] == "deploy:" {
			t.Fatalf("a synthetic id was queried at the provider: %s", key)
		}
	}
}

// TestCollectBoundsOrderLookups proves the per-run bound is real, so an operator
// run cannot turn into a provider hammering loop.
func TestCollectBoundsOrderLookups(t *testing.T) {
	f, srv := newFixture(t)
	defer srv.Close()
	var orders []models.GigahostOrder
	for i := int64(1); i <= 5; i++ {
		orders = append(orders, ledgerRow(i, orderIDFor(i), 0, "ready"))
	}

	res := Collect(context.Background(), f.client(t, srv), nil, orders, Limits{MaxOrderLookups: 2})
	if res.OrderLookups != 2 {
		t.Fatalf("order lookups = %d, want the bound of 2", res.OrderLookups)
	}
	queried := 0
	for key := range f.calls {
		if len(key) > 7 && key[:7] == "deploy:" {
			queried++
		}
	}
	if queried != 2 {
		t.Fatalf("the fixture saw %d order lookups, want 2", queried)
	}
	if len(res.Observations) != 5 {
		t.Fatalf("observed %d rows, want every row reported once", len(res.Observations))
	}
}

// TestCollectSkipsTerminalUnreleasedRows proves a row that already ended the
// attempt is not queried, while a RELEASED row still is: its marker is a past
// decision and the provider may have made the obligation live again.
func TestCollectSkipsTerminalUnreleasedRows(t *testing.T) {
	f, srv := newFixture(t)
	defer srv.Close()

	terminal := ledgerRow(1, "10001", 0, "failed")
	released := ledgerRow(2, "20002", 0, "ready")
	released.ReleasedAt = "2026-11-01T00:00:00Z"
	released.ReleaseReason = "provider_terminated"

	orders := []models.GigahostOrder{terminal, released}
	res := Collect(context.Background(), f.client(t, srv), nil, orders, Limits{MaxOrderLookups: 5})

	if _, seen := res.Observations[1]; seen {
		t.Error("a terminal unreleased row was queried; nothing can be released or revived there")
	}
	if _, seen := res.Observations[2]; !seen {
		t.Error("a released row must still be observed: a live provider answer has to be able to override the stale marker")
	}
	if res.OrderLookups != 1 {
		t.Fatalf("order lookups = %d, want exactly the released row", res.OrderLookups)
	}
}

// TestCollectWithoutAClientObservesNothing pins that a nil client cannot be read
// as a provider statement.
func TestCollectWithoutAClientObservesNothing(t *testing.T) {
	res := Collect(context.Background(), nil, nil,
		[]models.GigahostOrder{ledgerRow(1, "10001", 0, "ready")}, Limits{MaxOrderLookups: 5})
	if len(res.Observations) != 0 {
		t.Fatalf("observations = %+v, want none without a client", res.Observations)
	}
	if res.OrderLookups != 0 {
		t.Fatalf("order lookups = %d, want 0", res.OrderLookups)
	}
}

// TestCollectInventoryAnswersWithoutAnOrderLookup proves the inventory read is
// enough to classify a row, so a bounded run does not need a status call.
func TestCollectInventoryAnswersWithoutAnOrderLookup(t *testing.T) {
	f, srv := newFixture(t)
	defer srv.Close()
	f.servers = map[string]any{
		"meta": map[string]any{"page": 1, "total_pages": 1, "total": 1},
		"data": []map[string]any{{
			"id": 9, "order_id": "30003", "status": "deleted", "bw_is_hourly": true,
		}},
	}
	orders := []models.GigahostOrder{ledgerRow(1, "30003", 0, "ready")}
	res := Collect(context.Background(), f.client(t, srv), serversFrom(t, f, srv), orders,
		Limits{MaxOrderLookups: 0})

	obs := res.Observations[1]
	if !obs.Evidence.ServerFound || obs.Evidence.ServerStatus != "deleted" {
		t.Fatalf("evidence = %+v, want the matching inventory row", obs.Evidence)
	}
	if res.OrderLookups != 0 {
		t.Fatalf("order lookups = %d, want 0 when the bound is 0", res.OrderLookups)
	}
}

// TestCollectReportsATimeoutAsAFailure is the communication-failure case end to
// end: a request that cannot complete must never become evidence of absence.
func TestCollectReportsATimeoutAsAFailure(t *testing.T) {
	f, srv := newFixture(t)
	defer srv.Close()
	f.deploy["10001"] = func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	orders := []models.GigahostOrder{ledgerRow(1, "10001", 0, "ready")}
	res := Collect(ctx, f.client(t, srv), nil, orders, Limits{MaxOrderLookups: 5})

	if !res.Observations[1].Evidence.OrderQueryFailed {
		t.Fatalf("a cancelled request was not reported as a failed query: %+v", res.Observations[1].Evidence)
	}
}

// TestPlansConvertsCatalogRowsWithItsSingleMonthlyAmount pins the catalog
// conversion: the shared resolver receives the price identity the provider
// returned, so a legacy record can be priced the way the purchase path prices it.
func TestPlansConvertsCatalogRowsWithItsSingleMonthlyAmount(t *testing.T) {
	plans := Plans([]gigahost.HourlyPlan{{
		ProductID: 202, PriceID: 666, Currency: "NOK", HourlyRateNOK: 0.057, MonthlyCeiling: 41,
	}})
	if len(plans) != 1 {
		t.Fatalf("plans = %+v, want one row", plans)
	}
	got := plans[0]
	if got.ProductID != 202 || got.PriceID != 666 || got.Currency != "NOK" ||
		got.HourlyRateNOK != 0.057 || got.MonthlyCeiling != 41 {
		t.Fatalf("plan = %+v, want the provider's own price identity", got)
	}
	if plans := Plans(nil); len(plans) != 0 {
		t.Fatalf("an empty catalog must produce no plans, got %+v", plans)
	}
}

// TestServersConvertsInventoryIdentities pins the inventory conversion, including
// the hourly flag the budget decision depends on.
func TestServersConvertsInventoryIdentities(t *testing.T) {
	hourly := true
	servers := Servers([]gigahost.ServerInfo{{
		ID: 7, OrderID: "10001", PID: 202, Status: "ready", BwIsHourly: &hourly,
	}})
	if len(servers) != 1 || servers[0].ID != 7 || servers[0].OrderID != "10001" ||
		servers[0].PlanID != 202 || servers[0].Status != "ready" || !servers[0].Hourly {
		t.Fatalf("server = %+v, want the provider's own identity with hourly billing", servers)
	}
}

// serversFrom reads the fixture inventory through the real client, so these tests
// exercise the client's own decoding rather than fabricated structs.
func serversFrom(t *testing.T, f *fixtureServer, srv *httptest.Server) []gigahost.ServerInfo {
	t.Helper()
	servers, err := f.client(t, srv).GetServers(context.Background())
	if err != nil {
		t.Fatalf("read fixture inventory: %v", err)
	}
	return servers
}

// orderIDFor builds a distinct queryable order id for one record.
func orderIDFor(i int64) string {
	return "ord_" + itoa(i)
}

// itoa formats a small positive integer.
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
