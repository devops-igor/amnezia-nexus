package handlers

// Behavioral controls for the display-side Gigahost catalog cache (#771).
//
// Every case drives the REAL handler and the REAL cache with a fake provider that
// counts its calls, so the assertions are about provider request counts and
// response state rather than about the cache's internals:
//
//   - cold load            : exactly one plan read and one image read
//   - warm load            : zero further provider reads, fresh state
//   - expired load         : exactly one further refresh, fresh state again
//   - concurrent load      : one refresh shared by every caller
//   - failed refresh       : retained complete snapshot, explicit stale state
//   - failed with nothing  : the endpoint's existing error contract, no cache
//   - account isolation    : two credentials never share a snapshot
//   - order-path immunity  : the purchase path never reads this cache
//
// The provider is never a real network: the fake client is the documented
// gigahost.Client, so "one call" is a count on the seam the handler actually uses.

import (
	"context"
	"encoding/json"
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

// catalogCountingProvider is a fake provider that counts the two catalog reads the
// display path performs.
type catalogCountingProvider struct {
	planCalls atomic.Int32
	osCalls   atomic.Int32

	mu        sync.Mutex
	plans     []gigahost.HourlyPlan
	images    []gigahost.OperatingSystem
	planErr   error
	osErr     error
	planDelay time.Duration
}

func (p *catalogCountingProvider) GetCatalog(context.Context) ([]gigahost.HourlyPlan, error) {
	p.planCalls.Add(1)
	if p.planDelay > 0 {
		time.Sleep(p.planDelay)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.planErr != nil {
		return nil, p.planErr
	}
	return append([]gigahost.HourlyPlan(nil), p.plans...), nil
}

func (p *catalogCountingProvider) GetOperatingSystems(context.Context) ([]gigahost.OperatingSystem, error) {
	p.osCalls.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.osErr != nil {
		return nil, p.osErr
	}
	return append([]gigahost.OperatingSystem(nil), p.images...), nil
}

// set swaps the provider answer between refreshes.
func (p *catalogCountingProvider) set(plans []gigahost.HourlyPlan, images []gigahost.OperatingSystem, planErr, osErr error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.plans, p.images, p.planErr, p.osErr = plans, images, planErr, osErr
}

// The remaining methods only need to satisfy gigahost.Client; the display path
// and the purchase path used in these tests never reach them.
func (p *catalogCountingProvider) GetProducts(context.Context) ([]gigahost.Product, error) {
	return nil, errors.New("unused: GetProducts")
}

func (p *catalogCountingProvider) GetAccount(context.Context) (*gigahost.AccountInfo, error) {
	return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
}

func (p *catalogCountingProvider) ListSSHKeys(context.Context) ([]gigahost.SSHKeyInfo, error) {
	return nil, nil
}

func (p *catalogCountingProvider) RegisterSSHKey(context.Context, string, string) error { return nil }

func (p *catalogCountingProvider) OrderServer(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	return nil, errors.New("unused: OrderServer")
}

func (p *catalogCountingProvider) OrderServerSafe(_ context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	// Counted by the caller that replaces this method; the default refuses so an
	// unexpectedly reached purchase is loud instead of silent.
	return nil, errors.New("unexpected purchase")
}

func (p *catalogCountingProvider) GetDeployStatus(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
	return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusPending}, nil
}

func (p *catalogCountingProvider) GetServers(context.Context) ([]gigahost.ServerInfo, error) {
	return []gigahost.ServerInfo{}, nil
}

// catalogBody is the fields these tests assert on.
type catalogBody struct {
	Status    string                `json:"status"`
	Error     string                `json:"error"`
	State     string                `json:"state"`
	Stale     bool                  `json:"stale"`
	Count     int                   `json:"count"`
	OSCount   int                   `json:"os_count"`
	Plans     []gigahost.HourlyPlan `json:"plans"`
	FetchedAt string                `json:"fetched_at"`
	TTL       int64                 `json:"ttl_seconds"`
}

// getCatalog issues one admin catalog request through the real handler.
func getCatalog(t *testing.T, h *Handlers, headerKey string) (*httptest.ResponseRecorder, catalogBody) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
	if headerKey != "" {
		req.Header.Set("X-Gigahost-API-Key", headerKey)
	}
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-cache",
		Role:   models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.GigahostCatalogHandler(w, req)
	var body catalogBody
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

// newCacheHarness builds a handler with a counting provider and a controllable
// clock, so expiry is a test decision rather than a sleep.
func newCacheHarness(t *testing.T) (*Handlers, *catalogCountingProvider, *fakeClock) {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	provider := &catalogCountingProvider{
		plans:  []gigahost.HourlyPlan{fixtureHourlyPlan()},
		images: fixtureOperatingSystems(),
	}
	// The client is injected, so the cache scope is the single injected identity
	// and these cases measure freshness/coalescing rather than account keys.
	h.SetGigahostClient(provider)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h.catalogCache().now = clock.Now
	return h, provider, clock
}

// fakeClock is the cache's time source in tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestCatalogCache_ColdLoadReadsProviderOnce proves the first load is a real
// provider read that produces one complete snapshot: plans AND images.
func TestCatalogCache_ColdLoadReadsProviderOnce(t *testing.T) {
	h, provider, _ := newCacheHarness(t)

	w, body := getCatalog(t, h, "")
	if w.Code != http.StatusOK {
		t.Fatalf("cold load status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if got := provider.planCalls.Load(); got != 1 {
		t.Errorf("cold plan reads = %d, want 1", got)
	}
	if got := provider.osCalls.Load(); got != 1 {
		t.Errorf("cold image reads = %d, want 1", got)
	}
	if body.State != "fresh" || body.Stale {
		t.Errorf("cold state = %q stale=%v, want fresh/false", body.State, body.Stale)
	}
	if body.Count != 1 || body.OSCount != len(fixtureOperatingSystems()) {
		t.Errorf("cold snapshot = %d plans / %d images, want 1 / %d",
			body.Count, body.OSCount, len(fixtureOperatingSystems()))
	}
	if body.FetchedAt == "" || body.TTL != int64(gigahostCatalogTTL/time.Second) {
		t.Errorf("cold freshness metadata = fetched_at %q ttl %d, want a timestamp and %v",
			body.FetchedAt, body.TTL, gigahostCatalogTTL)
	}
}

// TestCatalogCache_WarmLoadSkipsProvider proves a repeat load inside the
// freshness window performs no provider read at all.
func TestCatalogCache_WarmLoadSkipsProvider(t *testing.T) {
	h, provider, clock := newCacheHarness(t)

	getCatalog(t, h, "")
	clock.advance(gigahostCatalogTTL / 2)
	w, body := getCatalog(t, h, "")

	if w.Code != http.StatusOK {
		t.Fatalf("warm load status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if got := provider.planCalls.Load(); got != 1 {
		t.Errorf("warm plan reads = %d, want the cold read only (1)", got)
	}
	if got := provider.osCalls.Load(); got != 1 {
		t.Errorf("warm image reads = %d, want the cold read only (1)", got)
	}
	if body.State != "fresh" || body.Stale {
		t.Errorf("warm state = %q stale=%v, want fresh/false", body.State, body.Stale)
	}
	if body.Count != 1 {
		t.Errorf("warm snapshot plans = %d, want the retained 1", body.Count)
	}
}

// TestCatalogCache_ExpiredLoadRefreshesOnce proves expiry triggers exactly one
// further refresh and that the refreshed answer is the one served.
func TestCatalogCache_ExpiredLoadRefreshesOnce(t *testing.T) {
	h, provider, clock := newCacheHarness(t)

	getCatalog(t, h, "")
	// The provider now publishes a different plan, so "served the new answer" is
	// observable in the response body as well as in the call count.
	second := fixtureHourlyPlan()
	second.ProductID = 202
	second.PriceID = 777
	provider.set([]gigahost.HourlyPlan{second}, fixtureOperatingSystems(), nil, nil)

	clock.advance(gigahostCatalogTTL + time.Second)
	w, body := getCatalog(t, h, "")

	if w.Code != http.StatusOK {
		t.Fatalf("expired load status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if got := provider.planCalls.Load(); got != 2 {
		t.Errorf("expired plan reads = %d, want 2 (cold + one refresh)", got)
	}
	if got := provider.osCalls.Load(); got != 2 {
		t.Errorf("expired image reads = %d, want 2 (cold + one refresh)", got)
	}
	if body.State != "fresh" || body.Stale {
		t.Errorf("expired refresh state = %q stale=%v, want fresh/false", body.State, body.Stale)
	}
	if len(body.Plans) != 1 || body.Plans[0].ProductID != 202 {
		t.Errorf("refreshed snapshot = %+v, want the provider's new plan 202", body.Plans)
	}
}

// TestCatalogCache_ConcurrentLoadsShareOneRefresh proves N simultaneous expired
// loads produce one provider refresh, not N.
func TestCatalogCache_ConcurrentLoadsShareOneRefresh(t *testing.T) {
	h, provider, clock := newCacheHarness(t)

	// Cold load first, then expire, so every concurrent caller is a genuine
	// refresh candidate rather than a warm hit.
	getCatalog(t, h, "")
	clock.advance(gigahostCatalogTTL + time.Second)
	// Hold the provider read open until the test releases it, so every caller has
	// a chance to arrive and queue behind it: without coalescing they would each
	// perform their own read.
	release := make(chan struct{})
	var arrived atomic.Int32

	const callers = 8
	gate := &catalogGatedProvider{catalogCountingProvider: provider, release: release, arrived: &arrived}
	h.SetGigahostClient(gate)

	results := make(chan int, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, _ := getCatalog(t, h, "")
			results <- w.Code
		}()
	}

	// Wait until the first provider read is inside the gate, give the other
	// callers a bounded moment to queue behind it, then let the read finish.
	waitFor(t, func() bool { return arrived.Load() >= 1 })
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)

	for code := range results {
		if code != http.StatusOK {
			t.Errorf("concurrent caller status = %d, want 200", code)
		}
	}
	// Cold read plus exactly one shared refresh.
	if got := provider.planCalls.Load(); got != 2 {
		t.Errorf("concurrent plan reads = %d, want 2 (cold + one shared refresh)", got)
	}
}

// catalogGatedProvider blocks the first catalog read until the test releases it, so
// the coalescing window is deterministic instead of a race.
type catalogGatedProvider struct {
	*catalogCountingProvider
	release   chan struct{}
	arrived   *atomic.Int32
	firstOnce sync.Once
}

func (g *catalogGatedProvider) GetCatalog(ctx context.Context) ([]gigahost.HourlyPlan, error) {
	g.firstOnce.Do(func() {
		g.arrived.Add(1)
		<-g.release
	})
	return g.catalogCountingProvider.GetCatalog(ctx)
}

// GetOperatingSystems forwards so the embedded counter stays authoritative.
func (g *catalogGatedProvider) GetOperatingSystems(ctx context.Context) ([]gigahost.OperatingSystem, error) {
	return g.catalogCountingProvider.GetOperatingSystems(ctx)
}

// waitFor polls cond for a bounded moment, failing the test on timeout.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached within the bounded wait")
}

// TestCatalogCache_FailedRefreshServesRetainedSnapshotStale proves a failed
// refresh preserves the complete previous snapshot and labels it stale, and that
// the failure backoff bounds further provider calls.
func TestCatalogCache_FailedRefreshServesRetainedSnapshotStale(t *testing.T) {
	h, provider, clock := newCacheHarness(t)

	_, cold := getCatalog(t, h, "")
	if cold.Count != 1 {
		t.Fatalf("cold snapshot plans = %d, want 1", cold.Count)
	}

	// The provider stops working. The image half fails, which is the malformed/
	// partial case: plans were read but the answer is not publishable.
	provider.set(nil, nil, nil, errors.New("provider unreachable"))

	clock.advance(gigahostCatalogTTL + time.Second)
	w, body := getCatalog(t, h, "")

	if w.Code != http.StatusOK {
		t.Fatalf("failed refresh status = %d, want 200 with a stale snapshot (body: %s)",
			w.Code, w.Body.String())
	}
	if !body.Stale || body.State != "stale" {
		t.Errorf("failed refresh state = %q stale=%v, want stale/true", body.State, body.Stale)
	}
	// The COMPLETE snapshot survived: the plan list is still there with its
	// narrowed image options, not a partial answer.
	if body.Count != 1 || len(body.Plans) != 1 {
		t.Fatalf("retained snapshot plans = %d (plans %d), want the previous 1",
			body.Count, len(body.Plans))
	}
	if len(body.Plans[0].OSOptions) == 0 {
		t.Error("retained snapshot lost the plan's image options; a partial answer must never be published")
	}
	if body.OSCount != len(fixtureOperatingSystems()) {
		t.Errorf("retained snapshot images = %d, want %d", body.OSCount, len(fixtureOperatingSystems()))
	}

	// Inside the backoff window the provider is not asked again.
	failedReads := provider.planCalls.Load()
	clock.advance(gigahostCatalogFailureBackoff / 2)
	_, again := getCatalog(t, h, "")
	if got := provider.planCalls.Load(); got != failedReads {
		t.Errorf("provider plan reads inside the failure backoff = %d, want %d (no new read)", got, failedReads)
	}
	if !again.Stale || again.Count != 1 {
		t.Errorf("backoff read = %q stale=%v plans=%d, want the stale complete snapshot",
			again.State, again.Stale, again.Count)
	}
}

// TestCatalogCache_FailedColdRefreshKeepsErrorContract proves that with nothing
// retained a failure still maps to the endpoint's existing error contract rather
// than inventing an empty catalog.
func TestCatalogCache_FailedColdRefreshKeepsErrorContract(t *testing.T) {
	cases := []struct {
		name       string
		planErr    error
		osErr      error
		wantStatus int
		wantCode   string
	}{
		{"unauthorized", gigahost.ErrUnauthorized, nil, http.StatusBadGateway, "upstream_auth_failed"},
		{"rate limited", gigahost.ErrRateLimited, nil, http.StatusTooManyRequests, "rate_limited"},
		{"image half unreadable", nil, gigahost.ErrUnauthorized, http.StatusBadGateway, "upstream_auth_failed"},
		{"generic failure", nil, errors.New("malformed provider body"), http.StatusBadGateway, "upstream_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, provider, _ := newCacheHarness(t)
			provider.set(nil, nil, tc.planErr, tc.osErr)

			w, body := getCatalog(t, h, "")
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if body.Error != tc.wantCode {
				t.Errorf("error code = %q, want %q", body.Error, tc.wantCode)
			}
			if body.Count != 0 || len(body.Plans) != 0 {
				t.Errorf("failed cold read published %d plans; nothing may be invented", body.Count)
			}
		})
	}
}

// TestCatalogCache_AccountsNeverShareSnapshots proves account isolation in the
// two halves that together produce it, because neither half alone would:
//
//  1. The handler hands the cache a scope derived from the credential it actually
//     resolved, so two accounts cannot collapse onto one scope. This drives the
//     real resolver.
//  2. The cache keeps those scopes apart, so one account's snapshot is never
//     served to another. This drives the real cache with the scopes from (1).
func TestCatalogCache_AccountsNeverShareSnapshots(t *testing.T) {
	const keyA = "flux_live_" + "aa00000000000000000000000000000000000000000000000000000000000001"
	const keyB = "flux_live_" + "bb00000000000000000000000000000000000000000000000000000000000002"

	// --- 1. the handler's scope input is per-account ---
	h, _, _ := setupTestHandlers(t)
	scopeFor := func(headerKey string) string {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
		req.Header.Set("X-Gigahost-API-Key", headerKey)
		resolved, err := h.resolveGigahostClient(req.Context(), req)
		if err != nil {
			t.Fatalf("resolving client for a header credential: %v", err)
		}
		if resolved.credential != headerKey {
			t.Fatalf("resolved credential is not the request credential; two accounts would share a scope")
		}
		return catalogScopeKey(resolved.credential)
	}
	if got := scopeFor(keyA); got == scopeFor(keyB) {
		t.Fatal("two different credentials produced one cache scope; accounts would cross-serve")
	}
	// An injected client is one identity, and its scope is never a digest that a
	// credential could collide with.
	h.SetGigahostClient(&catalogCountingProvider{})
	injected, err := h.resolveGigahostClient(context.Background(), nil)
	if err != nil {
		t.Fatalf("resolving the injected client: %v", err)
	}
	if injected.credential != "" || catalogScopeKey(injected.credential) != gigahostCatalogInjectedScope {
		t.Errorf("injected client scope = %q, want the fixed %q", catalogScopeKey(injected.credential), gigahostCatalogInjectedScope)
	}

	// --- 2. the cache keeps those scopes apart ---
	planA := fixtureHourlyPlan()
	planA.ProductID = 303
	planA.PriceID = 888
	planB := fixtureHourlyPlan()
	planB.ProductID = 404
	planB.PriceID = 999

	var readsA, readsB atomic.Int32
	cache := h.catalogCache()
	fetchA := func(context.Context) (*catalogSnapshot, error) {
		readsA.Add(1)
		return &catalogSnapshot{plans: []gigahost.HourlyPlan{planA}, images: fixtureOperatingSystems()}, nil
	}
	fetchB := func(context.Context) (*catalogSnapshot, error) {
		readsB.Add(1)
		return &catalogSnapshot{plans: []gigahost.HourlyPlan{planB}, images: fixtureOperatingSystems()}, nil
	}

	// The scopes come from the same derivation the handler uses above.
	readA, err := cache.load(context.Background(), catalogScopeKey(keyA), fetchA)
	if err != nil {
		t.Fatalf("account A load: %v", err)
	}
	readB, err := cache.load(context.Background(), catalogScopeKey(keyB), fetchB)
	if err != nil {
		t.Fatalf("account B load: %v", err)
	}
	if got := readA.snapshot.plans[0].ProductID; got != 303 {
		t.Errorf("account A plan = %d, want its own 303", got)
	}
	if got := readB.snapshot.plans[0].ProductID; got != 404 {
		t.Errorf("account B plan = %d, want its own 404 (not account A's snapshot)", got)
	}

	// Warm reads must not cross-serve either, and must not re-read the provider.
	warmA, err := cache.load(context.Background(), catalogScopeKey(keyA), fetchA)
	if err != nil {
		t.Fatalf("account A warm load: %v", err)
	}
	warmB, err := cache.load(context.Background(), catalogScopeKey(keyB), fetchB)
	if err != nil {
		t.Fatalf("account B warm load: %v", err)
	}
	if warmA.snapshot.plans[0].ProductID != 303 || warmB.snapshot.plans[0].ProductID != 404 {
		t.Errorf("warm reads crossed accounts: A=%d B=%d, want 303/404",
			warmA.snapshot.plans[0].ProductID, warmB.snapshot.plans[0].ProductID)
	}
	if readsA.Load() != 1 || readsB.Load() != 1 {
		t.Errorf("per-account refreshes = A%d B%d, want 1/1", readsA.Load(), readsB.Load())
	}
}

// TestCatalogCache_ScopeKeyIsStableAndCredentialFree proves the cache key is
// stable for one credential, different for another, and never contains the
// credential itself.
func TestCatalogCache_ScopeKeyIsStableAndCredentialFree(t *testing.T) {
	const keyA = "flux_live_" + "aa00000000000000000000000000000000000000000000000000000000000001"
	const keyB = "flux_live_" + "bb00000000000000000000000000000000000000000000000000000000000002"

	scopeA := catalogScopeKey(keyA)
	if scopeA != catalogScopeKey(keyA) {
		t.Error("scope key is not stable for the same credential")
	}
	if scopeA == catalogScopeKey(keyB) {
		t.Error("different credentials share a scope key; accounts would cross-serve")
	}
	for _, secret := range []string{keyA, keyB, "flux_live_", strings.TrimPrefix(keyA, "flux_live_")} {
		if strings.Contains(scopeA, secret) || strings.Contains(catalogScopeKey(keyB), secret) {
			t.Errorf("scope key exposes credential material %q", secret)
		}
	}
	if len(scopeA) != 64 {
		t.Errorf("scope key length = %d, want a 64-character digest", len(scopeA))
	}
	// An injected client has no credential of its own; the scope must be a fixed
	// label rather than an empty key that could collide with a digest.
	if catalogScopeKey("") != gigahostCatalogInjectedScope {
		t.Errorf("empty credential scope = %q, want %q", catalogScopeKey(""), gigahostCatalogInjectedScope)
	}
}

// TestCatalogCache_OrderPathNeverUsesCache is the authority control: a purchase
// must read the live provider catalog and revalidate the selection, so a stale
// cached snapshot can never authorize an order.
func TestCatalogCache_OrderPathNeverUsesCache(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	var planReads, imageReads, purchases atomic.Int32
	provider := &mockGigahostClient{
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			planReads.Add(1)
			live := fixtureHourlyPlan()
			// The live provider no longer sells this plan.
			live.InStock = false
			return []gigahost.HourlyPlan{live}, nil
		},
		getOSFn: func(context.Context) ([]gigahost.OperatingSystem, error) {
			imageReads.Add(1)
			return fixtureOperatingSystems(), nil
		},
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusPending}, nil
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			purchases.Add(1)
			return &gigahost.OrderResponse{OrderID: "ord_cache_guard", Status: gigahost.StatusPending}, nil
		},
	}
	h.SetGigahostClient(provider)

	// Warm the display cache with a snapshot that is FRESH and SELECTABLE: the
	// plan is in stock and carries its narrowed image options exactly as a real
	// production refresh would publish them. If the order path consulted this
	// cache, the order below would pass every selection check and buy.
	selectable := fixtureHourlyPlan()
	selectable.OSOptions = selectable.InstallableImages(fixtureOperatingSystems())
	h.catalogCache().publish(gigahostCatalogInjectedScope, &catalogSnapshot{
		plans:  []gigahost.HourlyPlan{selectable},
		images: fixtureOperatingSystems(),
	}, time.Now())

	// The order is refused because the LIVE catalog says out of stock, proving
	// the order path did not consult the still-fresh cached snapshot.
	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-order-path",
		Role:   models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("order status = %d, want 400 from the LIVE out-of-stock catalog (body: %s)",
			w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "out of stock") {
		t.Errorf("body = %s, want an out-of-stock refusal from the live catalog", w.Body.String())
	}
	if got := purchases.Load(); got != 0 {
		t.Errorf("provider purchases = %d, want 0", got)
	}
	if planReads.Load() == 0 {
		t.Error("order path performed no live provider catalog read; it must not reuse the display cache")
	}

	// Positive control on the SAME wiring: a live in-stock catalog still buys.
	provider.getCatalogFn = func(context.Context) ([]gigahost.HourlyPlan, error) {
		planReads.Add(1)
		return []gigahost.HourlyPlan{fixtureHourlyPlan()}, nil
	}
	body = `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`
	req = httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-order-path-ok",
		Role:   models.RoleAdmin,
	}))
	w = httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("positive control status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if got := purchases.Load(); got != 1 {
		t.Errorf("positive control purchases = %d, want exactly 1", got)
	}
}

// TestCatalogCache_SetClientInvalidatesSnapshots proves a replaced provider
// client cannot be served an answer retained for the previous one.
func TestCatalogCache_SetClientInvalidatesSnapshots(t *testing.T) {
	h, provider, _ := newCacheHarness(t)
	getCatalog(t, h, "")
	if provider.planCalls.Load() != 1 {
		t.Fatalf("cold plan reads = %d, want 1", provider.planCalls.Load())
	}

	replacement := &catalogCountingProvider{
		plans:  []gigahost.HourlyPlan{fixtureHourlyPlan()},
		images: fixtureOperatingSystems(),
	}
	h.SetGigahostClient(replacement)
	getCatalog(t, h, "")

	if got := replacement.planCalls.Load(); got != 1 {
		t.Errorf("replaced client plan reads = %d, want 1 (the snapshot must not outlive its client)", got)
	}
}

// TestCatalogCache_RetainsRenewedSnapshotWithoutASecondRead covers the in-slot
// re-check: a caller that queued behind a refresh which has since completed must
// observe the renewed snapshot instead of performing a second provider read.
func TestCatalogCache_RetainsRenewedSnapshotWithoutASecondRead(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	cache := h.catalogCache()

	var reads atomic.Int32
	var leadStarted, leadRelease = make(chan struct{}), make(chan struct{})
	fetch := func(context.Context) (*catalogSnapshot, error) {
		// The first read parks so a second caller can enter the same slot.
		if reads.Add(1) == 1 {
			close(leadStarted)
			<-leadRelease
		}
		plan := fixtureHourlyPlan()
		return &catalogSnapshot{plans: []gigahost.HourlyPlan{plan}, images: fixtureOperatingSystems()}, nil
	}

	firstDone := make(chan catalogRead, 1)
	go func() { firstDone <- mustCatalogLoad(t, cache, gigahostCatalogInjectedScope, fetch) }()
	<-leadStarted

	// The second caller joins the in-flight refresh rather than starting one.
	secondDone := make(chan catalogRead, 1)
	go func() { secondDone <- mustCatalogLoad(t, cache, gigahostCatalogInjectedScope, fetch) }()
	time.Sleep(50 * time.Millisecond)
	close(leadRelease)

	first, second := <-firstDone, <-secondDone
	if got := reads.Load(); got != 1 {
		t.Errorf("provider reads = %d, want 1 shared read", got)
	}
	if first.snapshot == nil || second.snapshot == nil {
		t.Fatal("both callers must receive the shared snapshot")
	}
	if second.snapshot.plans[0].ProductID != fixtureHourlyPlan().ProductID {
		t.Errorf("joined caller received plan %d, want the shared %d",
			second.snapshot.plans[0].ProductID, fixtureHourlyPlan().ProductID)
	}

	// A third load is served from the retained snapshot: no further provider read.
	third := mustCatalogLoad(t, cache, gigahostCatalogInjectedScope, fetch)
	if got := reads.Load(); got != 1 {
		t.Errorf("provider reads after the retained load = %d, want 1", got)
	}
	if third.snapshot == nil || third.snapshot.plans[0].ProductID != fixtureHourlyPlan().ProductID {
		t.Error("retained load did not serve the published snapshot")
	}
}

// mustCatalogLoad is one catalog load that fails the test on error.
func mustCatalogLoad(t *testing.T, cache *gigahostCatalogCache, scope string, fetch catalogFetcher) catalogRead {
	t.Helper()
	read, err := cache.load(context.Background(), scope, fetch)
	if err != nil {
		t.Errorf("catalog load: %v", err)
	}
	return read
}

// TestCatalogCache_EvictionKeepsTheTableBounded proves the retained-scope bound
// holds and that evicting one scope does not disturb the others.
func TestCatalogCache_EvictionKeepsTheTableBounded(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	cache := h.catalogCache()

	// Fill past the bound. Each scope gets a distinct plan so a wrongly served
	// snapshot is visible rather than merely a count.
	scopeAt := func(i int) string { return catalogScopeKey("scope-" + string(rune('a'+i%26)) + "-" + itoaTest(i)) }
	for i := 0; i <= gigahostCatalogMaxScopes; i++ {
		plan := fixtureHourlyPlan()
		plan.ProductID = 1000 + i
		core := func(context.Context) (*catalogSnapshot, error) {
			return &catalogSnapshot{plans: []gigahost.HourlyPlan{plan}, images: fixtureOperatingSystems()}, nil
		}
		mustCatalogLoad(t, cache, scopeAt(i), core)
	}

	cache.mu.Lock()
	size := len(cache.entries)
	cache.mu.Unlock()
	if size > gigahostCatalogMaxScopes {
		t.Errorf("retained scopes = %d, want at most %d", size, gigahostCatalogMaxScopes)
	}

	// The most recently used scope survived eviction: it is served without a read.
	survivor := scopeAt(gigahostCatalogMaxScopes)
	var reread atomic.Int32
	read := mustCatalogLoad(t, cache, survivor, func(context.Context) (*catalogSnapshot, error) {
		reread.Add(1)
		return &catalogSnapshot{plans: []gigahost.HourlyPlan{fixtureHourlyPlan()}, images: fixtureOperatingSystems()}, nil
	})
	// The written answer is the survivor's own plan, not the refetch fixture.
	if want := 1000 + gigahostCatalogMaxScopes; read.snapshot.plans[0].ProductID != want {
		t.Errorf("surviving scope served plan %d, want %d (least recently used was evicted)",
			read.snapshot.plans[0].ProductID, want)
	}
	if reread.Load() != 0 {
		t.Errorf("surviving scope re-read the provider %d times, want 0", reread.Load())
	}
}

// itoaTest avoids importing strconv into this file for one test helper.
func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

// TestCatalogCache_SlotRecheckPreventsDoubleRefresh covers the race the in-slot
// re-check exists for.
//
// A caller can observe an expired snapshot, and by the time it opens a slot
// another caller has already finished a refresh. singleflight would treat that as
// a NEW slot, so without the re-check the second caller performs a redundant
// provider read. This test drives that exact order: peek stale, let a refresh
// complete, then call refresh and require that it serves the renewed snapshot with
// no additional provider read.
func TestCatalogCache_SlotRecheckPreventsDoubleRefresh(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	cache := h.catalogCache()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }

	var reads atomic.Int32
	fetch := func(context.Context) (*catalogSnapshot, error) {
		reads.Add(1)
		plan := fixtureHourlyPlan()
		return &catalogSnapshot{plans: []gigahost.HourlyPlan{plan}, images: fixtureOperatingSystems()}, nil
	}

	// Populate, then let the snapshot expire.
	mustCatalogLoad(t, cache, gigahostCatalogInjectedScope, fetch)
	now = now.Add(gigahostCatalogTTL + time.Second)

	// Another caller refreshes first and publishes a renewed snapshot.
	renewed := fixtureHourlyPlan()
	renewed.ProductID = 909
	renewed.PriceID = 1001
	cache.publish(gigahostCatalogInjectedScope, &catalogSnapshot{
		plans:  []gigahost.HourlyPlan{renewed},
		images: fixtureOperatingSystems(),
	}, now)
	readsBefore := reads.Load()

	// The late caller enters the slot after that refresh and must not re-read.
	read, err := cache.refresh(context.Background(), gigahostCatalogInjectedScope, fetch)
	if err != nil {
		t.Fatalf("late refresh: %v", err)
	}
	if got := reads.Load(); got != readsBefore {
		t.Errorf("provider reads = %d, want %d (the slot re-check must serve the renewed snapshot)",
			got, readsBefore)
	}
	if read.snapshot == nil || read.snapshot.plans[0].ProductID != 909 {
		t.Errorf("late caller served plan %v, want the renewed 909", read.snapshot.plans[0].ProductID)
	}
	if read.stale {
		t.Error("late caller marked a renewed snapshot stale")
	}
}
