package handlers

// Injected-client replacement isolation.
//
// An injected provider client has no credential, so every injected client shares
// one cache scope. That is correct while the client is stable, and wrong the moment
// it is replaced: a request served by the new client must never be able to join, or
// receive the result of, a refresh that a superseded client started.
//
// Two independent defects are covered here:
//
//  1. Scope identity. A refresh in flight for the old client owns the scope key, so
//     the replacement client's request can attach to it through singleflight and be
//     handed the old client's answer. Even if it does not attach, the old refresh
//     can publish after the replacement, contaminating the retained snapshot.
//
//  2. Cache initialization. The replacement path reads the lazily initialized cache
//     pointer directly instead of going through its sync.Once accessor, which is an
//     unsynchronized read of a field another goroutine writes.
//
// These tests drive the real handler, the real cache and distinguishable fake
// providers, so "which client answered" is observable in the response body and in
// per-client call counts rather than inferred from internals.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// gatedInjectedClient is a fake provider with one distinguishable plan whose
// catalog read can be held open, so a replacement can be driven deterministically
// against a provably in-flight refresh.
type gatedInjectedClient struct {
	*mockGigahostClient

	plan      gigahost.HourlyPlan
	calls     atomic.Int32
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
}

func newGatedInjectedClient(planID, priceID int) *gatedInjectedClient {
	plan := fixtureHourlyPlan()
	plan.ProductID = planID
	plan.PriceID = priceID
	plan.Name = "plan-" + itoaTest(planID)
	return &gatedInjectedClient{
		mockGigahostClient: &mockGigahostClient{},
		plan:               plan,
		entered:            make(chan struct{}),
		release:            make(chan struct{}),
	}
}

// GetCatalog counts one read, signals the first entry, and holds while the test
// keeps release open.
func (g *gatedInjectedClient) GetCatalog(ctx context.Context) ([]gigahost.HourlyPlan, error) {
	g.calls.Add(1)
	g.enterOnce.Do(func() { close(g.entered) })
	select {
	case <-g.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []gigahost.HourlyPlan{g.plan}, nil
}

// releaseNow lets a held read complete.
func (g *gatedInjectedClient) releaseNow() { close(g.release) }

// ungatedInjectedClient answers immediately.
type ungatedInjectedClient struct {
	*mockGigahostClient
	plan  gigahost.HourlyPlan
	calls atomic.Int32
}

func newUngatedInjectedClient(planID, priceID int) *ungatedInjectedClient {
	plan := fixtureHourlyPlan()
	plan.ProductID = planID
	plan.PriceID = priceID
	plan.Name = "plan-" + itoaTest(planID)
	return &ungatedInjectedClient{mockGigahostClient: &mockGigahostClient{}, plan: plan}
}

func (u *ungatedInjectedClient) GetCatalog(context.Context) ([]gigahost.HourlyPlan, error) {
	u.calls.Add(1)
	return []gigahost.HourlyPlan{u.plan}, nil
}

// TestCatalogCache_ReplacementDoesNotInheritInFlightRefresh is the counterexample:
// an in-flight refresh from client A must not be joined by, or published over,
// client B.
func TestCatalogCache_ReplacementDoesNotInheritInFlightRefresh(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h.catalogCache().now = clock.Now

	clientA := newGatedInjectedClient(101, 555)
	h.SetGigahostClient(clientA)

	// 1. Client A's refresh starts and is provably inside the provider read.
	type result struct {
		code int
		body catalogBody
		raw  string
	}
	doneA := make(chan result, 1)
	go func() {
		w, body := getCatalog(t, h, "")
		doneA <- result{code: w.Code, body: body, raw: w.Body.String()}
	}()
	select {
	case <-clientA.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("client A's refresh never entered the provider read")
	}

	// 2. Client B replaces A while A is blocked.
	clientB := newUngatedInjectedClient(202, 777)
	h.SetGigahostClient(clientB)

	// 3. Client B asks for the catalog while A is still blocked. B must be served
	//    by B's own provider, not by A's in-flight refresh.
	wB, bodyB := getCatalog(t, h, "")
	if wB.Code != http.StatusOK {
		t.Fatalf("client B request status = %d, want 200 (body: %s)", wB.Code, wB.Body.String())
	}
	if bodyB.Count != 1 || bodyB.Plans[0].ProductID != 202 {
		t.Fatalf("client B received plan %+v, want its own 202: a superseded refresh was served to the replacement client",
			bodyB.Plans)
	}
	if got := clientB.calls.Load(); got != 1 {
		t.Errorf("client B provider reads = %d, want 1 (it must perform its own read, not join A's)", got)
	}
	if got := clientA.calls.Load(); got != 1 {
		t.Errorf("client A provider reads = %d, want 1 (B must not trigger additional reads on A)", got)
	}

	// 4. A completes late. Its answer must not overwrite B's snapshot.
	clientA.releaseNow()
	select {
	case late := <-doneA:
		// A's own request may fail or serve whatever it legitimately fetched; what
		// matters is that it must not have republished over B.
		_ = late
	case <-time.After(10 * time.Second):
		t.Fatal("client A's refresh never completed after release")
	}

	// 5. A warm read must still be B's snapshot: no stale republish contamination.
	_, warm := getCatalog(t, h, "")
	if warm.Count != 1 || warm.Plans[0].ProductID != 202 {
		t.Errorf("warm read after A completed = plan %+v, want B's 202: the superseded refresh republished its snapshot",
			warm.Plans)
	}
	if warm.Stale {
		t.Errorf("warm read is stale (%q), want B's fresh snapshot", warm.State)
	}
	if got := clientA.calls.Load(); got != 1 {
		t.Errorf("client A provider reads after completion = %d, want 1", got)
	}
}

// TestCatalogCache_SameGenerationStillCoalesces proves the replacement fence does
// not defeat coalescing: two concurrent loads for one unchanged client still share
// a single provider read.
func TestCatalogCache_SameGenerationStillCoalesces(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	h.catalogCache().now = func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) }

	client := newGatedInjectedClient(101, 555)
	// The first read parks; peers must join it rather than start their own.
	h.SetGigahostClient(client)

	const callers = 6
	var wg sync.WaitGroup
	codes := make(chan int, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, _ := getCatalog(t, h, "")
			codes <- w.Code
		}()
	}

	select {
	case <-client.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no refresh entered the provider read")
	}
	// Give the peers a bounded moment to queue behind the in-flight read.
	time.Sleep(100 * time.Millisecond)
	client.releaseNow()
	wg.Wait()
	close(codes)

	for code := range codes {
		if code != http.StatusOK {
			t.Errorf("coalesced caller status = %d, want 200", code)
		}
	}
	if got := client.calls.Load(); got != 1 {
		t.Errorf("provider reads = %d, want 1: same-generation callers must still coalesce", got)
	}
}

// TestCatalogCache_ReplacementDuringCacheInitialization exercises the second defect:
// the replacement path must not read the lazily initialized cache pointer without
// synchronization. Run under -race, an unsynchronized read of a concurrently
// written field is reported as a data race.
func TestCatalogCache_ReplacementDuringCacheInitialization(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	// Warm the provider so replacement is the only thing happening concurrently.
	var wg sync.WaitGroup
	const rounds = 200
	wg.Add(2 * rounds)

	for i := 0; i < rounds; i++ {
		go func() {
			defer wg.Done()
			// This path goes through the cache accessor.
			_, _ = getCatalog(t, h, "")
		}()
		go func(n int) {
			defer wg.Done()
			// This path replaces the client, which must invalidate through the same
			// synchronized accessor.
			h.SetGigahostClient(newUngatedInjectedClient(300+n, 900+n))
		}(i)
	}
	wg.Wait()

	// The cache must still be usable and consistent afterwards.
	w, body := getCatalog(t, h, "")
	if w.Code != http.StatusOK {
		t.Fatalf("final catalog request status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if body.Count != 1 {
		t.Errorf("final catalog count = %d, want 1", body.Count)
	}
}

// TestCatalogCache_SupersededFailureDoesNotPoisonReplacement proves the other half of
// the generation fence: a superseded client's failure must not arm a backoff on, or
// otherwise disturb, the replacement's own fresh snapshot.
//
// Without the fence, A's late failure calls fail() on the shared scope and records a
// backoff there. B's next request would then be served the backoff instead of doing
// its own read - a replaced client inheriting a failure it never had.
func TestCatalogCache_SupersededFailureDoesNotPoisonReplacement(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h.catalogCache().now = clock.Now

	failing := &failingGatedClient{
		mockGigahostClient: &mockGigahostClient{},
		entered:            make(chan struct{}),
		release:            make(chan struct{}),
	}
	h.SetGigahostClient(failing)

	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		_, _ = getCatalog(t, h, "")
	}()
	select {
	case <-failing.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("client A never entered the provider read")
	}

	// B replaces A while A is blocked, then B immediately reads successfully.
	clientB := newUngatedInjectedClient(404, 1004)
	h.SetGigahostClient(clientB)
	wB, bodyB := getCatalog(t, h, "")
	if wB.Code != http.StatusOK || bodyB.Count != 1 || bodyB.Plans[0].ProductID != 404 {
		t.Fatalf("client B first read = %d %+v, want its own 404", wB.Code, bodyB.Plans)
	}
	if bodyB.Stale {
		t.Errorf("client B's own successful read is marked stale (%q)", bodyB.State)
	}

	// A now completes with a failure. It must not disturb B.
	failing.releaseNow()
	select {
	case <-doneA:
	case <-time.After(10 * time.Second):
		t.Fatal("client A never completed")
	}

	_, warm := getCatalog(t, h, "")
	if warm.Count != 1 || warm.Plans[0].ProductID != 404 {
		t.Errorf("warm read after A failed = %+v, want B's 404: a superseded failure overwrote the replacement snapshot",
			warm.Plans)
	}
	if warm.Stale || warm.State != "fresh" {
		t.Errorf("warm read after A failed = %q stale=%v, want B's fresh snapshot",
			warm.State, warm.Stale)
	}
	// B must not have been re-read: its snapshot is still inside the freshness window.
	if got := clientB.calls.Load(); got != 1 {
		t.Errorf("client B provider reads = %d, want 1: the superseded failure suppressed or forced a replacement read", got)
	}

	// The decisive case: once B's snapshot EXPIRES, A's superseded failure must not
	// be sitting in the backoff slot suppressing B's refresh. Without the generation
	// fence, A's late failure arms a backoff on the shared scope and B is served the
	// expired snapshot as stale instead of being allowed to read again.
	clock.advance(gigahostCatalogTTL + time.Second)
	_, afterExpiry := getCatalog(t, h, "")
	if afterExpiry.Stale {
		t.Errorf("B's refresh after expiry is stale (%q): a superseded failure armed the replacement's backoff",
			afterExpiry.State)
	}
	if got := clientB.calls.Load(); got != 2 {
		t.Errorf("client B provider reads = %d, want 2: the superseded failure suppressed B's own refresh", got)
	}
}

// failingGatedClient holds its catalog read open and then fails, modeling a
// superseded client whose request completes late and badly.
type failingGatedClient struct {
	*mockGigahostClient
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
}

func (f *failingGatedClient) GetCatalog(ctx context.Context) ([]gigahost.HourlyPlan, error) {
	f.enterOnce.Do(func() { close(f.entered) })
	select {
	case <-f.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, errors.New("superseded provider read failed")
}

func (f *failingGatedClient) releaseNow() { close(f.release) }

// flakyInjectedClient answers with one distinguishable plan, but can be switched to
// fail, so a replacement's own provider can be unavailable exactly when it is first
// asked.
type flakyInjectedClient struct {
	*mockGigahostClient
	plan   gigahost.HourlyPlan
	calls  atomic.Int32
	broken atomic.Bool
}

func newFlakyInjectedClient(planID, priceID int) *flakyInjectedClient {
	plan := fixtureHourlyPlan()
	plan.ProductID = planID
	plan.PriceID = priceID
	plan.Name = "plan-" + itoaTest(planID)
	return &flakyInjectedClient{mockGigahostClient: &mockGigahostClient{}, plan: plan}
}

func (f *flakyInjectedClient) GetCatalog(context.Context) ([]gigahost.HourlyPlan, error) {
	f.calls.Add(1)
	if f.broken.Load() {
		return nil, errors.New("replacement provider is unavailable")
	}
	return []gigahost.HourlyPlan{f.plan}, nil
}

// TestCatalogCache_LateSuccessBeforeReplacementFirstRead is the decisive case: the
// superseded client finishes successfully AFTER being replaced and BEFORE the
// replacement has ever read.
//
// A refresh in flight for client A must not publish into the retired scope. The
// table is empty at that moment, so "is a newer entry present?" cannot be the
// retirement test; retirement has to be a property of the cache itself.
func TestCatalogCache_LateSuccessBeforeReplacementFirstRead(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h.catalogCache().now = clock.Now

	clientA := newGatedInjectedClient(101, 555)
	h.SetGigahostClient(clientA)

	// 1. Client A's read starts and is provably inside the provider read.
	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		_, _ = getCatalog(t, h, "")
	}()
	select {
	case <-clientA.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("client A never entered the provider read")
	}

	// 2. B replaces A while A is still blocked; the setter has returned.
	clientB := newUngatedInjectedClient(202, 777)
	h.SetGigahostClient(clientB)

	// 3. A completes successfully before B has made any request at all.
	clientA.releaseNow()
	select {
	case <-doneA:
	case <-time.After(10 * time.Second):
		t.Fatal("client A never completed after release")
	}

	// 4. B's FIRST request must be answered by B, from B's own read.
	w, body := getCatalog(t, h, "")
	if w.Code != http.StatusOK {
		t.Fatalf("client B first read status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if body.Count != 1 || body.Plans[0].ProductID != 202 {
		t.Fatalf("client B first read = %+v, want its own plan 202: a superseded success was published as the replacement's catalog",
			body.Plans)
	}
	if body.State != "fresh" || body.Stale {
		t.Errorf("client B first read state = %q stale=%v, want fresh/false", body.State, body.Stale)
	}
	if got := clientB.calls.Load(); got != 1 {
		t.Errorf("client B provider reads = %d, want 1 (it must perform its own read)", got)
	}

	// 5. B's next read is warm: B's snapshot, still no extra provider read.
	_, warm := getCatalog(t, h, "")
	if warm.Count != 1 || warm.Plans[0].ProductID != 202 {
		t.Errorf("client B warm read = %+v, want its own plan 202", warm.Plans)
	}
	if warm.State != "fresh" {
		t.Errorf("client B warm read state = %q, want fresh", warm.State)
	}
	if got := clientB.calls.Load(); got != 1 {
		t.Errorf("client B provider reads after the warm read = %d, want 1", got)
	}
	if got := clientA.calls.Load(); got != 1 {
		t.Errorf("client A provider reads = %d, want 1", got)
	}
}

// TestCatalogCache_ReplacementFailureDoesNotServePredecessorSnapshot is the
// adjacent sequential schedule: the replacement's provider is unavailable, so the
// previous account's retained catalog must not be served as its fallback.
//
// An unavailable replacement is a real provider state, and serving the predecessor's
// plans as "stale" would present another account's prices and images as this
// account's own last known answer.
func TestCatalogCache_ReplacementFailureDoesNotServePredecessorSnapshot(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h.catalogCache().now = clock.Now

	// 1. Client A reads successfully: its snapshot is retained and fresh.
	clientA := newUngatedInjectedClient(303, 808)
	h.SetGigahostClient(clientA)
	wA, bodyA := getCatalog(t, h, "")
	if wA.Code != http.StatusOK || bodyA.Count != 1 || bodyA.Plans[0].ProductID != 303 {
		t.Fatalf("client A first read = %d %+v, want its own 303", wA.Code, bodyA.Plans)
	}

	// 2. B replaces A, and B's provider is down.
	clientB := newFlakyInjectedClient(404, 1004)
	clientB.broken.Store(true)
	h.SetGigahostClient(clientB)

	wB, _ := getCatalog(t, h, "")
	if wB.Code != http.StatusBadGateway {
		t.Fatalf("client B read status = %d, want 502 (body: %s): the replacement was served the previous client's snapshot instead of reporting the provider failure",
			wB.Code, wB.Body.String())
	}
	if strings.Contains(wB.Body.String(), "303") {
		t.Errorf("client B failure body leaked the previous client's catalog: %s", wB.Body.String())
	}

	// 3. The provider recovers. B's OWN read now serves B's catalog fresh, and the
	//    failure backoff suppressed the provider calls made inside its window.
	clientB.broken.Store(false)
	clock.advance(gigahostCatalogFailureBackoff + time.Second)
	_, recovered := getCatalog(t, h, "")
	if recovered.Count != 1 || recovered.Plans[0].ProductID != 404 {
		t.Errorf("client B recovered read = %+v, want its own 404", recovered.Plans)
	}
	if recovered.State != "fresh" {
		t.Errorf("client B recovered read state = %q, want fresh", recovered.State)
	}
	if got := clientB.calls.Load(); got != 2 {
		t.Errorf("client B provider reads = %d, want 2 (the failed read, then one recovery read after the backoff)", got)
	}

	// 4. B's snapshot is now retained: a warm read must not read the provider again.
	_, warm := getCatalog(t, h, "")
	if warm.Count != 1 || warm.Plans[0].ProductID != 404 {
		t.Errorf("client B warm read = %+v, want its own 404", warm.Plans)
	}
	if got := clientB.calls.Load(); got != 2 {
		t.Errorf("client B provider reads after the warm read = %d, want 2", got)
	}
}

// TestCatalogCache_SupersededFailureCannotSeedReplacementBackoff is the case where
// the generation fence is load-bearing.
//
// A is blocked, B replaces A, and A then fails BEFORE B has ever read. A's failure
// would create the scope's entry with a backoff; without the generation check in
// load(), B's very first request would be answered from that backoff - a brand new
// client refused a provider read because the client it replaced had failed.
func TestCatalogCache_SupersededFailureCannotSeedReplacementBackoff(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h.catalogCache().now = clock.Now

	failing := &failingGatedClient{
		mockGigahostClient: &mockGigahostClient{},
		entered:            make(chan struct{}),
		release:            make(chan struct{}),
	}
	h.SetGigahostClient(failing)

	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		_, _ = getCatalog(t, h, "")
	}()
	select {
	case <-failing.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("client A never entered the provider read")
	}

	// B replaces A and, crucially, has not read anything yet.
	clientB := newUngatedInjectedClient(505, 1005)
	h.SetGigahostClient(clientB)

	// A now fails late, seeding the shared scope from the superseded generation.
	failing.releaseNow()
	select {
	case <-doneA:
	case <-time.After(10 * time.Second):
		t.Fatal("client A never completed")
	}

	// B's FIRST read must be a real provider read, not A's recorded backoff.
	w, body := getCatalog(t, h, "")
	if w.Code != http.StatusOK {
		t.Fatalf("client B first read status = %d, want 200 (body: %s): a superseded failure refused the replacement",
			w.Code, w.Body.String())
	}
	if body.Count != 1 || body.Plans[0].ProductID != 505 {
		t.Errorf("client B first read = %+v, want its own 505", body.Plans)
	}
	if body.Stale {
		t.Errorf("client B first read is stale (%q): it inherited a superseded failure", body.State)
	}
	if got := clientB.calls.Load(); got != 1 {
		t.Errorf("client B provider reads = %d, want 1: a superseded failure suppressed the replacement's own read", got)
	}
}
