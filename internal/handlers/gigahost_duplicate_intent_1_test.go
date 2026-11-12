package handlers

// Deterministic regression for the duplicate-intent serialization gap.
//
// The CI counterexample (run 42576536602, job 129025413181, source c41f15f) showed
// five concurrent identical orders producing two provider purchases. The cause:
// the "no unresolved prior order" decision and the durable intent row that makes
// that decision visible to later checks were two separate critical sections, so a
// second request could pass the check in the window between the first request
// finishing its check and its intent row committing.
//
// Widening the window correctly matters. Blocking inside the provider call does
// NOT reproduce the defect, because by then the intent row is already committed and
// a second request is legitimately refused - that test passes on broken code and is
// therefore worthless as an oracle. The seam used here holds an attempt immediately
// BEFORE its intent row is written, which is the exact interval the defect lives in.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// intentWindowGate holds the FIRST attempt inside the duplicate-check-to-intent
// window and counts provider purchases. Later attempts are counted but never
// blocked: an attempt that reaches the window at all has already passed the
// duplicate check, which is exactly the observation the oracle needs.
type intentWindowGate struct {
	gigahost.Client

	intentEntered chan struct{} // first attempt is inside the window
	intentRelease chan struct{} // test allows the first intent write to proceed
	intentReached atomic.Int32  // how many attempts reached the window
	orders        atomic.Int32
	once          sync.Once
}

func newIntentWindowGate(inner gigahost.Client) *intentWindowGate {
	return &intentWindowGate{
		Client:        inner,
		intentEntered: make(chan struct{}),
		intentRelease: make(chan struct{}),
	}
}

// holdBeforeIntent is installed as the intent hook. Only the first caller parks;
// every caller increments the "reached the window" counter first.
func (g *intentWindowGate) holdBeforeIntent() {
	g.intentReached.Add(1)
	g.once.Do(func() {
		close(g.intentEntered)
		<-g.intentRelease
	})
}

func (g *intentWindowGate) OrderServerSafe(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	g.orders.Add(1)
	return g.Client.OrderServerSafe(ctx, req)
}

// intentWindowProvider offers two orderable plans so "different plan" is a
// genuinely different logical purchase, not a validation failure.
func intentWindowProvider() gigahost.Client {
	return &mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 5000, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			first := fixtureHourlyPlan()
			second := fixtureHourlyPlan()
			second.ProductID = 102
			second.PriceID = 556
			second.Name = "Cloud 4"
			return []gigahost.HourlyPlan{first, second}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusDeploying}, nil
		},
		orderServerSafeFn: func(_ context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			return &gigahost.OrderResponse{
				OrderID: fmt.Sprintf("ord_%d_%d", req.PID, req.RegionID),
				Status:  gigahost.StatusPending,
				Message: "Deploying VPS",
			}, nil
		},
	}
}

func submitConcurrentOrder(h *Handlers, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	// Deliberately no UserID: the per-admin admission token cannot mask the
	// purchase-level defect, which is what the CI fixture exercised.
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)
	return w
}

const (
	windowBodyA = `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`
	windowBodyB = `{"pid":102,"price_id":556,"region_id":1,"os_id":12}`
)

// TestDuplicateIntent_SecondIdenticalOrderRefusedInsideIntentWindow drives a second
// identical order while the first is provably between its duplicate check and its
// intent commit. On unrepaired source the second attempt finds no durable intent and
// purchases too; after the repair it must be refused.
func TestDuplicateIntent_SecondIdenticalOrderRefusedInsideIntentWindow(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	gate := newIntentWindowGate(intentWindowProvider())
	h.SetGigahostClient(gate)
	h.gigahostIntentHook = gate.holdBeforeIntent

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- submitConcurrentOrder(h, windowBodyA) }()

	select {
	case <-gate.intentEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first attempt never entered the intent window")
	}

	// Second identical attempt, concurrently: it must NOT complete on its own while
	// the first holds the window. Whether it is blocked at the gate (repaired) or
	// running through to the intent write (unrepaired) is exactly what differs.
	secondDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { secondDone <- submitConcurrentOrder(h, windowBodyA) }()

	select {
	case second := <-secondDone:
		// Unrepaired source: the second attempt got all the way through while the
		// first was still inside the window. Record it; the assertions below judge.
		t.Logf("second attempt completed inside the window with %d (defect path)", second.Code)
	case <-time.After(300 * time.Millisecond):
		// Repaired source: it is parked behind the gate's critical section.
	}

	// Let the first attempt finish its intent write and purchase.
	close(gate.intentRelease)

	first := <-firstDone
	var second *httptest.ResponseRecorder
	select {
	case second = <-secondDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the second attempt never returned after the first completed")
	}

	if first.Code != http.StatusOK {
		t.Errorf("first order = %d, want 200 (body: %s)", first.Code, first.Body.String())
	}
	if second.Code != http.StatusAccepted {
		t.Errorf("second identical order = %d, want 202 duplicate refusal (body: %s)",
			second.Code, second.Body.String())
	}
	if got := gate.orders.Load(); got != 1 {
		t.Errorf("provider purchases = %d, want exactly 1", got)
	}
	if got := gate.intentReached.Load(); got != 1 {
		t.Errorf("attempts that passed the duplicate check and reached the intent window = %d, want 1", got)
	}
}

// TestDuplicateIntent_DifferentPlanAllowedInsideIntentWindow is the negative control
// for over-serialization: a genuinely different logical order must not be refused as
// a duplicate of the in-flight one.
func TestDuplicateIntent_DifferentPlanAllowedInsideIntentWindow(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	gate := newIntentWindowGate(intentWindowProvider())
	h.SetGigahostClient(gate)
	h.gigahostIntentHook = gate.holdBeforeIntent

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- submitConcurrentOrder(h, windowBodyA) }()

	select {
	case <-gate.intentEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first attempt never entered the intent window")
	}

	otherDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { otherDone <- submitConcurrentOrder(h, windowBodyB) }()

	// A different plan may be parked behind the same critical section; what it must
	// never be is refused as a duplicate. Release the first attempt, then judge.
	close(gate.intentRelease)

	first := <-firstDone
	var other *httptest.ResponseRecorder
	select {
	case other = <-otherDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the different-plan order never returned after the first completed")
	}

	if first.Code != http.StatusOK {
		t.Errorf("first order = %d, want 200 (body: %s)", first.Code, first.Body.String())
	}
	if other.Code != http.StatusOK {
		t.Errorf("different-plan order = %d, want 200 (a different logical order must not be treated as a duplicate; body: %s)",
			other.Code, other.Body.String())
	}
	if got := gate.orders.Load(); got != 2 {
		t.Errorf("provider purchases for two different logical orders = %d, want 2", got)
	}
}
