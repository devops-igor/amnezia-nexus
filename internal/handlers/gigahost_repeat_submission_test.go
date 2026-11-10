package handlers

// Repeated-submission protection (finding: repeated rejected deploy attempts).
//
// A rejected order attempt costs provider reads (catalog, then inventory). When
// the rejection is persistent - a plan the catalog does not carry, or a
// provider that keeps failing - an admin clicking again, or a scripted retry,
// re-issues the whole read sequence against a provider that is already the
// suspect. This is a bounded, per-admin admission cooldown on that expensive
// pre-provider path.
//
// What it must NOT do, asserted here:
//   - never cache a positive eligibility/price decision (no purchase fast-path)
//   - never retry a purchase
//   - never create a permanent lockout
//   - never couple unrelated admins
//   - never hide a genuine provider error behind a cooldown message

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

// orderCounters counts provider work done for one attempt.
type orderCounters struct {
	catalog int32
	servers int32
	account int32
	posts   int32
}

// orderAttempt is what one order request observed.
type orderAttempt struct {
	code       int
	body       string
	posts      int32
	reads      int32
	retryAfter string
	suppressed bool
}

// repeatedSubmitHarness drives the real handler with per-attempt provider counts.
type repeatedSubmitHarness struct {
	t      *testing.T
	h      *Handlers
	counts orderCounters
}

func newRepeatedSubmitHarness(t *testing.T) *repeatedSubmitHarness {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	return &repeatedSubmitHarness{t: t, h: h}
}

// install wires a mock client whose reads are counted into the harness counters.
//
// The catalog carries either a plan the submitted request never selects
// (reject=true: a persistent, non-financial rejection) or exactly the requested
// plan (reject=false: the order succeeds). Both qualify eligibility from the
// catalog, so the account path is not exercised here.
func (rs *repeatedSubmitHarness) install(reject bool) {
	plan := gigahost.HourlyPlan{
		ProductID: 101, PriceID: 555, Currency: "NOK", HourlyRateNOK: 0.15,
		MonthlyCeiling: 108, InStock: true,
		Regions:     []gigahost.Region{{ID: 1, Available: true}},
		Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true},
	}
	if reject {
		plan.ProductID = 909
		plan.PriceID = 999
	}
	catalog := []gigahost.HourlyPlan{plan}
	servers := []gigahost.ServerInfo{}

	rs.h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			atomic.AddInt32(&rs.counts.account, 1)
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			atomic.AddInt32(&rs.counts.catalog, 1)
			return catalog, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			atomic.AddInt32(&rs.counts.servers, 1)
			return servers, nil
		},
		getDeployStatusFn: func(_ context.Context, id string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: id, Status: gigahost.StatusReady}, nil
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(&rs.counts.posts, 1)
			return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
		},
	})
}

// submit places one order as the given admin and reports the delta it caused.
func (rs *repeatedSubmitHarness) submit(userID string) orderAttempt {
	rs.t.Helper()
	before := orderCounters{
		catalog: atomic.LoadInt32(&rs.counts.catalog),
		servers: atomic.LoadInt32(&rs.counts.servers),
		account: atomic.LoadInt32(&rs.counts.account),
		posts:   atomic.LoadInt32(&rs.counts.posts),
	}

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: userID, Username: userID, Role: models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	rs.h.GigahostOrderHandler(w, req)

	reads := (atomic.LoadInt32(&rs.counts.catalog) - before.catalog) +
		(atomic.LoadInt32(&rs.counts.servers) - before.servers) +
		(atomic.LoadInt32(&rs.counts.account) - before.account)
	return orderAttempt{
		code:       w.Code,
		body:       w.Body.String(),
		posts:      atomic.LoadInt32(&rs.counts.posts) - before.posts,
		reads:      reads,
		retryAfter: w.Header().Get("Retry-After"),
		suppressed: strings.Contains(w.Body.String(), "repeat_suppressed"),
	}
}

// TestRepeatedSubmission_RejectedAttemptsDoNotReissueProviderReads is the core
// regression: a persistent rejection must not spend provider reads on every
// click.
func TestRepeatedSubmission_RejectedAttemptsDoNotReissueProviderReads(t *testing.T) {
	rs := newRepeatedSubmitHarness(t)
	rs.install(true)

	first := rs.submit("admin-1")
	if first.code != http.StatusBadRequest || !strings.Contains(first.body, "invalid_plan") {
		t.Fatalf("first attempt = %d %s, want 400 invalid_plan", first.code, first.body)
	}
	if first.suppressed {
		t.Fatal("the first attempt must reach the provider, not be suppressed")
	}
	if first.reads == 0 {
		t.Fatal("expected the first attempt to read the provider")
	}
	if first.posts != 0 {
		t.Fatalf("rejected attempt dispatched %d orders, want 0", first.posts)
	}

	// Immediate repeats must be suppressed before any provider work.
	for i := 0; i < 3; i++ {
		repeat := rs.submit("admin-1")
		if !repeat.suppressed {
			t.Fatalf("repeat %d was not suppressed (code=%d body=%s)", i, repeat.code, repeat.body)
		}
		if repeat.reads != 0 || repeat.posts != 0 {
			t.Fatalf("suppressed repeat %d still did provider work: reads=%d posts=%d",
				i, repeat.reads, repeat.posts)
		}
		if repeat.code != http.StatusTooManyRequests {
			t.Errorf("suppressed repeat %d = %d, want 429", i, repeat.code)
		}
		if repeat.retryAfter == "" {
			t.Errorf("suppressed repeat %d has no Retry-After header", i)
		}
		if strings.Contains(repeat.body, "budget") {
			t.Errorf("suppression text still mentions a budget: %s", repeat.body)
		}
	}
}

// TestRepeatedSubmission_RecoversAfterWindow proves no permanent lockout.
func TestRepeatedSubmission_RecoversAfterWindow(t *testing.T) {
	rs := newRepeatedSubmitHarness(t)
	rs.install(true)

	cooldown := repeatedSubmitCooldown()
	if cooldown <= 0 {
		t.Fatalf("cooldown = %v, want a positive bounded duration", cooldown)
	}
	// A rejection recorded before the window must not block.
	rs.h.recordRejectedOrderAttempt("admin-1", time.Now().Add(-2*cooldown))
	if blocked, _ := rs.h.orderAdmissionBlocked("admin-1"); blocked {
		t.Fatal("an expired window must not block a later attempt")
	}
	// And through the handler, that attempt reaches the provider again.
	attempt := rs.submit("admin-1")
	if attempt.suppressed {
		t.Fatal("an expired window suppressed a real attempt")
	}
	if attempt.reads == 0 {
		t.Fatal("expected the recovered attempt to reach the provider")
	}
}

// TestRepeatedSubmission_ConcurrentSubmitsAdmitAtMostOne: parallel submits from
// one admin must not all reach the provider.
func TestRepeatedSubmission_ConcurrentSubmitsAdmitAtMostOne(t *testing.T) {
	rs := newRepeatedSubmitHarness(t)
	rs.install(true)

	// Prime the cooldown so the concurrent burst is entirely in-window.
	first := rs.submit("admin-concurrent")
	if first.suppressed {
		t.Fatal("the priming attempt must not be suppressed")
	}

	const attempts = 6
	results := make([]orderAttempt, attempts)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = rs.submit("admin-concurrent")
		}(i)
	}
	close(start)
	wg.Wait()

	admits := 0
	for _, r := range results {
		if !r.suppressed {
			admits++
		}
	}
	if admits > 1 {
		t.Fatalf("%d concurrent submits were admitted past the cooldown, want at most 1", admits)
	}
	for _, r := range results {
		if r.posts != 0 {
			t.Fatalf("a concurrent submit dispatched a provider order")
		}
	}
}

// TestRepeatedSubmission_SeparateAdminsUnaffected proves no cross-admin coupling.
func TestRepeatedSubmission_SeparateAdminsUnaffected(t *testing.T) {
	rs := newRepeatedSubmitHarness(t)
	rs.install(true)
	rs.h.recordRejectedOrderAttempt("admin-1", time.Now())

	if blocked, _ := rs.h.orderAdmissionBlocked("admin-1"); !blocked {
		t.Fatal("admin-1 should be cooling down")
	}
	if blocked, _ := rs.h.orderAdmissionBlocked("admin-2"); blocked {
		t.Fatal("admin-2 must not be affected by admin-1's rejection")
	}

	// admin-2 still does real work.
	attempt := rs.submit("admin-2")
	if attempt.suppressed {
		t.Fatal("admin-2 was suppressed by another admin's cooldown")
	}
	if attempt.reads == 0 {
		t.Fatal("admin-2's attempt did no provider work")
	}
}

// TestRepeatedSubmission_SuccessClearsCooldown proves a successful order is never
// gated by a stale rejection, and no positive decision is cached.
func TestRepeatedSubmission_SuccessClearsCooldown(t *testing.T) {
	rs := newRepeatedSubmitHarness(t)
	rs.install(false)

	rs.h.recordRejectedOrderAttempt("admin-1", time.Now())
	rs.h.clearOrderAdmission("admin-1")
	if blocked, _ := rs.h.orderAdmissionBlocked("admin-1"); blocked {
		t.Fatal("a cleared entry must not block")
	}

	attempt := rs.submit("admin-1")
	if attempt.suppressed {
		t.Fatal("a cleared cooldown suppressed a legitimate attempt")
	}
	if attempt.code != http.StatusOK || attempt.posts != 1 {
		t.Fatalf("expected a successful order, got %d (posts=%d body=%s)", attempt.code, attempt.posts, attempt.body)
	}
}

// TestRepeatedSubmission_CooldownIsBounded guards the policy constants so a later
// edit cannot silently turn a short cooldown into a lockout.
func TestRepeatedSubmission_CooldownIsBounded(t *testing.T) {
	d := repeatedSubmitCooldown()
	if d <= 0 {
		t.Fatalf("cooldown = %v, want positive", d)
	}
	if d > 2*time.Minute {
		t.Fatalf("cooldown = %v, want a bounded retry hint (<= 2m), not a lockout", d)
	}
}

// TestRepeatedSubmission_ProviderErrorIsNotHidden proves a genuine provider
// failure is still reported as itself, not as a cooldown.
func TestRepeatedSubmission_ProviderErrorIsNotHidden(t *testing.T) {
	rs := newRepeatedSubmitHarness(t)
	rs.install(false)

	// Non-qualifying catalog forces the account path, which times out.
	rs.h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return nil, context.DeadlineExceeded
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{{
				ProductID: 101, PriceID: 555, HourlyRateNOK: 0.15, MonthlyCeiling: 59,
				InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}},
			}}, nil
		},
	})
	attempt := rs.submit("admin-1")
	if attempt.suppressed {
		t.Fatal("a provider failure must not be reported as a cooldown")
	}
	if attempt.code != http.StatusBadGateway || !strings.Contains(attempt.body, "account_check_failed") {
		t.Fatalf("provider failure = %d %s, want 502 account_check_failed", attempt.code, attempt.body)
	}
}

// TestRepeatedSubmission_TableIsBoundedAndSelfPruning covers the eviction paths:
// the in-memory table must not grow without bound, must drop expired entries
// first, and must still work when every entry is fresh.
func TestRepeatedSubmission_TableIsBoundedAndSelfPruning(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	// Fill to the cap with FRESH entries: the table is full but nothing is
	// expired, so an insert must evict to stay bounded.
	for i := 0; i < maxAdmissionEntries; i++ {
		h.recordRejectedOrderAttempt("fresh-"+string(rune('a'+i%26))+string(rune('a'+i/26)), time.Now())
	}
	table := h.admission()
	table.mu.Lock()
	sizeAfterFreshFill := len(table.entries)
	table.mu.Unlock()
	if sizeAfterFreshFill > maxAdmissionEntries {
		t.Fatalf("table grew to %d entries, cap is %d", sizeAfterFreshFill, maxAdmissionEntries)
	}

	// Now make everything expired and insert: expired entries are purged first.
	table.mu.Lock()
	keys := make([]string, 0, len(table.entries))
	for key := range table.entries {
		keys = append(keys, key)
	}
	table.mu.Unlock()
	for _, key := range keys {
		h.recordRejectedOrderAttempt(key, time.Now().Add(-2*repeatedSubmitCooldown()))
	}
	h.recordRejectedOrderAttempt("after-expiry", time.Now())
	table.mu.Lock()
	size := len(table.entries)
	_, hasNew := table.entries["after-expiry"]
	table.mu.Unlock()
	if !hasNew {
		t.Fatal("the new entry must be recorded")
	}
	if size > maxAdmissionEntries {
		t.Fatalf("table grew to %d entries after purge, cap is %d", size, maxAdmissionEntries)
	}

	// An empty user id is never recorded and never blocked.
	h.recordRejectedOrderAttempt("", time.Now())
	if blocked, _ := h.orderAdmissionBlocked(""); blocked {
		t.Fatal("an empty identity must never be throttled")
	}
}

// TestRepeatedSubmission_FailureClassification covers every cooldown label. A
// provider timeout MUST arm the window: repeated stalled account reads were
// unlimited before the correction.
func TestRepeatedSubmission_FailureClassification(t *testing.T) {
	if got := failureKindFor(http.StatusBadRequest, errors.New("invalid_plan: plan 999 not found")); got != failureRequest {
		t.Errorf("400 = %q, want %q", got, failureRequest)
	}
	if got := failureKindFor(http.StatusPaymentRequired, gigahost.ErrInsufficientCredit); got != failureCredit {
		t.Errorf("402 = %q, want %q", got, failureCredit)
	}
	// The corrected case: a provider timeout arms the cooldown.
	if got := failureKindFor(http.StatusBadGateway, context.DeadlineExceeded); got != failureProviderTimeout {
		t.Errorf("502 deadline = %q, want %q", got, failureProviderTimeout)
	}
	if got := failureKindFor(http.StatusBadGateway, errors.New("failed to fetch catalog: boom")); got != failureProviderError {
		t.Errorf("502 error = %q, want %q", got, failureProviderError)
	}
	if got := failureKindFor(http.StatusOK, nil); got != "" {
		t.Errorf("success must not arm a cooldown, got %q", got)
	}
}
