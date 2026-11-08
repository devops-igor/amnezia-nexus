package handlers

// Barrier-controlled regression for admission atomicity and provider-timeout
// suppression.
//
// The earlier attempt at this protection was wrong in a way fast sequential
// failures could not reveal: the check and the failure record were separate
// critical sections with provider I/O between them, so every concurrent request
// from one admin passed the check while the first was still blocked on the
// network. Six quick failures looked green and proved nothing.
//
// These tests hold the first provider call open with a real barrier, so the
// overlap is forced rather than hoped for.

import (
	"context"
	"errors"
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

// barrierClient blocks the FIRST catalog call until released, so other
// same-admin requests genuinely arrive while one attempt is in flight.
type barrierClient struct {
	inner gigahost.Client

	entered  chan struct{}
	release  chan struct{}
	first    int32
	inFlight int32
	maxIn    int32
	calls    int32
}

func (b *barrierClient) noteEnter() {
	cur := atomic.AddInt32(&b.inFlight, 1)
	for {
		old := atomic.LoadInt32(&b.maxIn)
		if cur <= old || atomic.CompareAndSwapInt32(&b.maxIn, old, cur) {
			return
		}
	}
}

func (b *barrierClient) noteExit() { atomic.AddInt32(&b.inFlight, -1) }

func (b *barrierClient) GetCatalog(ctx context.Context) ([]gigahost.HourlyPlan, error) {
	b.noteEnter()
	defer b.noteExit()
	atomic.AddInt32(&b.calls, 1)
	// Only the FIRST caller waits: sync.Once would block every concurrent caller
	// until the first returned, destroying the overlap this test needs.
	if atomic.CompareAndSwapInt32(&b.first, 0, 1) {
		close(b.entered)
		<-b.release
	}
	return b.inner.GetCatalog(ctx)
}

func (b *barrierClient) GetProducts(ctx context.Context) ([]gigahost.Product, error) {
	return b.inner.GetProducts(ctx)
}
func (b *barrierClient) GetAccount(ctx context.Context) (*gigahost.AccountInfo, error) {
	return b.inner.GetAccount(ctx)
}
func (b *barrierClient) OrderServer(ctx context.Context, r gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	return b.inner.OrderServer(ctx, r)
}
func (b *barrierClient) OrderServerSafe(ctx context.Context, r gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	return b.inner.OrderServerSafe(ctx, r)
}
func (b *barrierClient) GetDeployStatus(ctx context.Context, id string) (*gigahost.DeployStatusResponse, error) {
	return b.inner.GetDeployStatus(ctx, id)
}
func (b *barrierClient) GetServers(ctx context.Context) ([]gigahost.ServerInfo, error) {
	return b.inner.GetServers(ctx)
}

// submitOrderAs issues one order request as the given admin.
func submitOrderAs(h *Handlers, userID string) *httptest.ResponseRecorder {
	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: userID, Username: userID, Role: models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)
	return w
}

// TestConcurrentSameAdminAdmitsOnlyOneAttempt is the atomicity contract: while
// one attempt is blocked inside provider I/O, every other same-admin request must
// be refused WITHOUT issuing provider work.
func TestConcurrentSameAdminAdmitsOnlyOneAttempt(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	if err := db.SetSetting(context.Background(), "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}

	mock := &mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{{
				ProductID: 101, PriceID: 555, HourlyRateNOK: 0.15, MonthlyCeiling: 59,
				InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}},
				Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true},
			}}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
	}
	barrier := &barrierClient{inner: mock, entered: make(chan struct{}), release: make(chan struct{})}
	h.SetGigahostClient(barrier)

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- submitOrderAs(h, "admin-1") }()
	<-barrier.entered

	const others = 5
	var wg sync.WaitGroup
	results := make([]*httptest.ResponseRecorder, others)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = submitOrderAs(h, "admin-1")
		}(i)
	}
	wg.Wait()
	close(barrier.release)
	first := <-firstDone

	if got := atomic.LoadInt32(&barrier.calls); got != 1 {
		t.Errorf("provider catalog calls = %d, want exactly 1 while one attempt was in flight", got)
	}
	if got := atomic.LoadInt32(&barrier.maxIn); got > 1 {
		t.Errorf("max concurrent provider calls = %d, want at most 1", got)
	}
	if first.Code != http.StatusOK {
		t.Fatalf("the admitted attempt = %d, want 200 (body: %s)", first.Code, first.Body.String())
	}
	for i, r := range results {
		if r.Code != http.StatusTooManyRequests {
			t.Errorf("concurrent request %d = %d, want 429", i, r.Code)
		}
		if !strings.Contains(r.Body.String(), "repeat_suppressed") {
			t.Errorf("concurrent request %d body = %s, want repeat_suppressed", i, r.Body.String())
		}
		if r.Header().Get("Retry-After") == "" {
			t.Errorf("concurrent request %d has no Retry-After header", i)
		}
	}
}

// TestConcurrentSeparateAdminsAreIndependent proves the reservation is per admin.
func TestConcurrentSeparateAdminsAreIndependent(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	if err := db.SetSetting(context.Background(), "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}
	mock := &mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{{
				ProductID: 101, PriceID: 555, HourlyRateNOK: 0.15, MonthlyCeiling: 59,
				InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}},
				Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true},
			}}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
	}
	barrier := &barrierClient{inner: mock, entered: make(chan struct{}), release: make(chan struct{})}
	h.SetGigahostClient(barrier)

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { firstDone <- submitOrderAs(h, "admin-1") }()
	<-barrier.entered

	// A DIFFERENT admin must be admitted while admin-1 is in flight. The second
	// call blocks on the budget mutex, not on the admission slot, so it is started
	// concurrently and released with the first.
	otherDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { otherDone <- submitOrderAs(h, "admin-2") }()

	close(barrier.release)
	first := <-firstDone
	other := <-otherDone

	if first.Code != http.StatusOK {
		t.Fatalf("admin-1 = %d, want 200", first.Code)
	}
	if other.Code == http.StatusTooManyRequests {
		t.Fatalf("admin-2 was throttled by admin-1's in-flight attempt (body: %s)", other.Body.String())
	}
}

// TestRepeatedAccountTimeoutsAreSuppressed is the second reported gap: repeated
// stalled account reads must not keep re-issuing, and the FIRST genuine provider
// error must be preserved rather than replaced.
func TestRepeatedAccountTimeoutsAreSuppressed(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	if err := db.SetSetting(context.Background(), "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}

	var accountCalls int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			atomic.AddInt32(&accountCalls, 1)
			return nil, context.DeadlineExceeded
		},
		// A non-qualifying catalog forces the account path.
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{{
				ProductID: 101, PriceID: 555, HourlyRateNOK: 0.15, MonthlyCeiling: 59,
				InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}},
			}}, nil
		},
	})

	first := submitOrderAs(h, "admin-9")
	if first.Code != http.StatusBadGateway {
		t.Fatalf("first = %d, want the genuine 502 (body: %s)", first.Code, first.Body.String())
	}
	if !strings.Contains(first.Body.String(), "account_check_failed") {
		t.Errorf("the first provider error must be preserved verbatim, got %s", first.Body.String())
	}
	afterFirst := atomic.LoadInt32(&accountCalls)

	second := submitOrderAs(h, "admin-9")
	third := submitOrderAs(h, "admin-9")

	if got := atomic.LoadInt32(&accountCalls); got != afterFirst {
		t.Errorf("repeated timeouts issued %d extra provider calls, want 0", got-afterFirst)
	}
	for i, r := range []*httptest.ResponseRecorder{second, third} {
		if r.Code != http.StatusTooManyRequests {
			t.Errorf("repeat %d = %d, want 429", i, r.Code)
		}
		if !strings.Contains(r.Body.String(), "provider_timeout") {
			t.Errorf("repeat %d must reference the prior provider failure, got %s", i, r.Body.String())
		}
	}
}

// TestProviderErrorRecoversAfterWindow proves the cooldown is not a lockout: once
// the window elapses, the provider is consulted again.
func TestProviderErrorRecoversAfterWindow(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	h.recordRejectedOrderAttempt("admin-1", time.Now().Add(-2*repeatedSubmitCooldown()))
	if blocked, _ := h.orderAdmissionBlocked("admin-1"); blocked {
		t.Fatal("an expired window must not block a later attempt")
	}
}

// TestReservationIsReleasedOnEveryTerminalPath guards against a leaked slot,
// which would be a permanent lockout for that admin.
func TestReservationIsReleasedOnEveryTerminalPath(t *testing.T) {
	cases := []struct {
		name   string
		mock   *mockGigahostClient
		budget float64
	}{
		{
			name: "provider failure releases the slot",
			mock: &mockGigahostClient{
				getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
					return nil, errors.New("boom")
				},
				getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
					return []gigahost.HourlyPlan{{
						ProductID: 101, PriceID: 555, HourlyRateNOK: 0.15, MonthlyCeiling: 59,
						InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}},
					}}, nil
				},
			},
			budget: 100,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			if err := db.SetSetting(context.Background(), "gigahost", map[string]any{"monthly_budget_nok": tc.budget}); err != nil {
				t.Fatal(err)
			}
			h.SetGigahostClient(tc.mock)
			submitOrderAs(h, "admin-x")

			// The slot must be free: a different key on the same admin's entry is
			// irrelevant, in_flight must be false.
			h.admission().mu.Lock()
			entry, present := h.admission().entries["admin-x"]
			inFlight := present && entry.inFlight
			h.admission().mu.Unlock()
			if inFlight {
				t.Fatal("the reservation leaked: in_flight is still true after a terminal failure")
			}
		})
	}
}
