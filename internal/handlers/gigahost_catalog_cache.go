package handlers

// Server-side catalog cache for the Gigahost ordering page.
//
// The ordering page used to re-read the whole provider catalog (products plus
// one image read per distribution) on every load. This cache keeps one complete
// answer per provider account for a bounded freshness window.
//
// Four properties are load-bearing and each has an explicit control here:
//
//  1. SCOPE. An answer belongs to exactly one provider account. The map key is a
//     digest of the resolved credential, never the credential itself; the digest
//     is an in-process map key only and is never written to a response, a log
//     record, the database or an artifact. One account's snapshot therefore
//     cannot be served to another, and the key cannot be replayed.
//
//  2. COMPLETENESS. A snapshot is the plan list AND the image catalog they were
//     narrowed against, captured together. A refresh that fails half way
//     publishes nothing, so a partial or malformed answer never replaces a
//     complete one.
//
//  3. FRESHNESS. Fresh snapshots are served without any provider read. Expired
//     ones are refreshed; concurrent refreshes of the same scope are coalesced
//     into one provider read. A failed refresh keeps the previous complete
//     snapshot and serves it as explicitly stale, and the failure arms a short
//     backoff so an unavailable provider is not re-asked on every page load.
//
//  4. AUTHORITY. Nothing here authorizes a purchase. This cache is read only by
//     GigahostCatalogHandler, the display endpoint. The order path keeps reading
//     the live provider catalog and revalidating price, stock, placement and
//     operating system before it sends a paid request.
//
// FRESHNESS POLICY (the documented contract for this cache):
//
//	fresh window     60s   a snapshot inside this window is served with no
//	                       provider read; the window is short because display
//	                       cannot detect a change the provider made
//	failure backoff  15s   after a failed refresh the provider is not asked
//	                       again for that scope, so an outage cannot turn every
//	                       page load into a provider call
//	refresh timeout  30s   matches the provider client's request timeout, so a
//	                       stalled read cannot hold the refresh slot open
//	retained scopes   64   one per provider account; the least recently used is
//	                       evicted at the bound
//
// Freshness is reported to the caller rather than assumed: the response carries
// state ("fresh"|"stale"), stale, fetched_at, age_seconds and ttl_seconds, so the
// portal can say why a snapshot is old instead of implying it is current.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

const (
	// gigahostCatalogTTL is how long one complete provider answer is served
	// without a new provider read. Short on purpose: the snapshot carries prices
	// and stock that an operator reads as current, and the purchase path - not
	// this window - is what actually guards a purchase.
	gigahostCatalogTTL = 60 * time.Second

	// gigahostCatalogFailureBackoff is how long a failed refresh suppresses the
	// next provider read for the same scope. It bounds provider calls while the
	// provider is unavailable, including a provider that stalls.
	gigahostCatalogFailureBackoff = 15 * time.Second

	// gigahostCatalogFetchTimeout bounds one refresh. It matches the provider
	// client's own request timeout, so a stalled read cannot hold the refresh
	// slot open.
	gigahostCatalogFetchTimeout = 30 * time.Second

	// gigahostCatalogMaxScopes bounds the in-memory table. Each entry is one
	// account's last answer, so the bound is per configured account, not per
	// request.
	gigahostCatalogMaxScopes = 64

	// gigahostCatalogInjectedScope is the scope of an explicitly injected
	// provider client. Such a client carries no credential of its own, so it is
	// one provider account identity for this handler instance; replacing it
	// invalidates the cache.
	gigahostCatalogInjectedScope = "injected"
)

// errCatalogSnapshotMissing reports a refresh that reported neither a failure nor
// an answer. It is a defensive value: the only production fetcher either returns
// a complete snapshot or an error.
var errCatalogSnapshotMissing = errors.New("gigahost catalog refresh produced no snapshot")

// catalogSnapshot is one complete catalog answer.
//
// The slices are immutable once published: concurrent readers only encode them.
type catalogSnapshot struct {
	plans      []gigahost.HourlyPlan
	images     []gigahost.OperatingSystem
	capturedAt time.Time
}

// gigahostCatalogEntry is the retained state of one account scope.
type gigahostCatalogEntry struct {
	snapshot *catalogSnapshot
	// generation is the provider-client generation that produced snapshot (or, for
	// a failure-only entry, the generation the failure belongs to). A write from an
	// older generation is refused, so a superseded client cannot publish over its
	// replacement.
	generation uint64
	failedAt   time.Time
	lastErr    error
	lastUsed   time.Time
}

// catalogRead is one answer for the handler: the snapshot, whether it is being
// served as stale, and the freshness policy it was measured against.
type catalogRead struct {
	snapshot *catalogSnapshot
	stale    bool
	age      time.Duration
	ttl      time.Duration
}

// catalogFetcher performs one complete provider catalog read. Both halves must
// succeed for the snapshot to be publishable.
type catalogFetcher func(context.Context) (*catalogSnapshot, error)

// catalogRefreshOutcome is what one coalesced refresh produced. The provider
// failure is a value rather than the singleflight error so every caller that
// joined the refresh observes the same answer, including a shared failure.
type catalogRefreshOutcome struct {
	snapshot *catalogSnapshot
	stale    bool
	err      error
}

// gigahostCatalogCache is the bounded per-account snapshot cache.
//
// mu guards the table only. No provider I/O and no other handler lock is ever
// taken while it is held; a refresh runs outside it, coalesced by group.
type gigahostCatalogCache struct {
	mu      sync.Mutex
	entries map[string]*gigahostCatalogEntry
	group   singleflight.Group
	now     func() time.Time
}

// newGigahostCatalogCache builds an empty cache on the wall clock.
func newGigahostCatalogCache() *gigahostCatalogCache {
	return &gigahostCatalogCache{
		entries: make(map[string]*gigahostCatalogEntry),
		now:     time.Now,
	}
}

// catalogCache returns the lazily created catalog cache.
//
// Every reader and writer of the cache pointer goes through this accessor. The
// replacement path must not read catalogCacheState directly: the field is written
// inside the Once above, so an unsynchronized read races that initialization.
func (h *Handlers) catalogCache() *gigahostCatalogCache {
	h.catalogCacheOnce.Do(func() {
		h.catalogCacheState = newGigahostCatalogCache()
	})
	return h.catalogCacheState
}

// catalogGeneration reports the current injected-client generation.
//
// It increments every time the provider client is replaced. The value is only ever
// compared for equality, so a wrapped counter is still correct.
func (h *Handlers) catalogGeneration() uint64 {
	h.catalogGenMu.Lock()
	defer h.catalogGenMu.Unlock()
	return h.catalogGen
}

// bumpCatalogGeneration invalidates the retained cache and returns the new
// generation.
//
// It goes through the synchronized accessor so it cannot race lazy initialization,
// and it advances the generation so that a refresh still in flight for the previous
// client can neither be joined by the replacement nor publish over it.
func (h *Handlers) bumpCatalogGeneration() uint64 {
	h.catalogGenMu.Lock()
	h.catalogGen++
	generation := h.catalogGen
	h.catalogGenMu.Unlock()

	h.catalogCache().invalidateAll()
	return generation
}

// catalogScopeKey is the cache scope of one provider account.
//
// An empty credential means an injected client, which has no account of its own.
// Otherwise the scope is a domain-separated SHA-256 digest: one-way, stable for
// the life of the process, and never exposed. This is not a password hash and is
// never persisted - it exists to keep two accounts' answers apart in memory.
func catalogScopeKey(credential string) string {
	if credential == "" {
		return gigahostCatalogInjectedScope
	}
	digest := sha256.Sum256([]byte("gigahost-catalog\x00" + credential))
	return hex.EncodeToString(digest[:])
}

// fresh reports whether the entry can be served without a provider read.
func (e gigahostCatalogEntry) fresh(now time.Time) bool {
	return e.snapshot != nil && now.Sub(e.snapshot.capturedAt) < gigahostCatalogTTL
}

// blocked reports whether a failed refresh is recent enough that the provider
// must not be asked again yet.
func (e gigahostCatalogEntry) blocked(now time.Time) bool {
	return !e.failedAt.IsZero() && now.Sub(e.failedAt) < gigahostCatalogFailureBackoff
}

// peek returns a copy of the scope's entry and records the access. Caller must
// not hold the lock.
func (c *gigahostCatalogCache) peek(scope string, now time.Time) gigahostCatalogEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, present := c.entries[scope]
	if !present {
		return gigahostCatalogEntry{}
	}
	entry.lastUsed = now
	return *entry
}

// load answers one catalog request, reading the provider only when the retained
// answer is from an earlier freshness window.
//
// generation identifies the provider-client generation the caller resolved. A
// refresh started under one generation is never joined by a call from another, so a
// replaced client cannot inherit an in-flight answer, and a superseded refresh
// cannot publish over the replacement's snapshot.
func (c *gigahostCatalogCache) load(ctx context.Context, scope string, generation uint64, fetch catalogFetcher) (catalogRead, error) {
	now := c.now()
	entry := c.peek(scope, now)
	// Retained state written by a superseded client is not this caller's answer.
	// Without this, a replacement client would be served the previous client's
	// snapshot - or, worse, its recorded failure backoff - simply because both
	// injected clients share one scope.
	if entry.generation < generation {
		entry = gigahostCatalogEntry{}
	}
	if entry.fresh(now) {
		return newCatalogRead(entry.snapshot, false, now), nil
	}
	// An expired snapshot whose refresh just failed is still the best complete
	// answer available, and it is labeled stale rather than presented as fresh.
	if entry.snapshot != nil && entry.blocked(now) {
		return newCatalogRead(entry.snapshot, true, now), nil
	}
	// With no snapshot at all there is nothing to serve; the recorded failure is
	// returned instead of re-asking the provider inside its backoff window.
	if entry.snapshot == nil && entry.lastErr != nil && entry.blocked(now) {
		return catalogRead{}, entry.lastErr
	}
	return c.refresh(ctx, scope, generation, fetch)
}

// refresh performs one provider read for the scope, coalescing concurrent callers
// that resolved the SAME client generation so they share a single read.
//
// The generation is part of the coalescing key on purpose. Two callers holding
// different clients must never share a read: the flight's `fetch` closure belongs to
// whichever client led it, so a joiner from another generation would be served an
// answer fetched for a client it is not using. Because the replacement also bumps
// the generation, a caller that arrives after `SetGigahostClient` starts its own
// read instead of attaching to the superseded one.
func (c *gigahostCatalogCache) refresh(ctx context.Context, scope string, generation uint64, fetch catalogFetcher) (catalogRead, error) {
	ch := c.group.DoChan(refreshKey(scope, generation), func() (any, error) {
		// A caller that queued behind the slot holder may already have been
		// overtaken by it, so the cache is re-checked inside the slot. The retained
		// entry is read ONCE: a second read could observe an entry a concurrent
		// client replacement has since cleared, and would then publish a nil answer.
		if now := c.now(); c.peek(scope, now).fresh(now) {
			return c.recordRetained(scope, generation, now), nil
		}
		// The leader's request may be abandoned while peers wait on it: the
		// shared read is detached from that one caller and bounded on its own.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gigahostCatalogFetchTimeout)
		defer cancel()
		snapshot, fetchErr := fetch(fetchCtx)
		return c.record(scope, generation, snapshot, fetchErr, c.now()), nil
	})

	// A caller whose own request was canceled stops waiting; the shared read
	// still completes for the peers that remain.
	select {
	case <-ctx.Done():
		return catalogRead{}, ctx.Err()
	case result := <-ch:
		outcome, ok := result.Val.(*catalogRefreshOutcome)
		if !ok {
			return catalogRead{}, errCatalogSnapshotMissing
		}
		if outcome.err != nil {
			return catalogRead{}, outcome.err
		}
		if outcome.snapshot == nil {
			// Defensive: an outcome without an answer is not servable.
			return catalogRead{}, errCatalogSnapshotMissing
		}
		return newCatalogRead(outcome.snapshot, outcome.stale, c.now()), nil
	}
}

// refreshKey is the coalescing identity of one refresh: the account scope plus the
// client generation that is asking.
func refreshKey(scope string, generation uint64) string {
	return scope + "\x00" + strconv.FormatUint(generation, 10)
}

// recordRetained answers from the entry observed to be fresh inside the refresh
// slot.
//
// The snapshot is read exactly once by the caller. If a concurrent client
// replacement cleared it in the meantime, this reports the missing snapshot as a
// failure rather than handing back a nil pointer, so a request never dereferences
// an empty answer.
func (c *gigahostCatalogCache) recordRetained(scope string, generation uint64, now time.Time) *catalogRefreshOutcome {
	snapshot := c.peek(scope, now).snapshot
	if snapshot == nil {
		return &catalogRefreshOutcome{err: errCatalogSnapshotMissing}
	}
	return &catalogRefreshOutcome{snapshot: snapshot}
}

// record stores one refresh outcome and decides what that refresh serves.
//
// A failed, partial or malformed refresh never displaces a complete snapshot: the
// failure arms the backoff and the previous snapshot is served as stale. With no
// snapshot to fall back on, the provider error is returned so the handler keeps
// its existing status mapping.
//
// The generation fences the write. A refresh that was superseded while it was in
// flight still answers its own caller, but it cannot publish a snapshot over a
// newer generation's, and it cannot arm a backoff on top of one either.
func (c *gigahostCatalogCache) record(scope string, generation uint64, snapshot *catalogSnapshot, fetchErr error, now time.Time) *catalogRefreshOutcome {
	if fetchErr == nil && snapshot != nil {
		c.publish(scope, generation, snapshot, now)
		return &catalogRefreshOutcome{snapshot: snapshot}
	}
	failure := fetchErr
	if failure == nil {
		failure = errCatalogSnapshotMissing
	}
	if retained := c.fail(scope, generation, failure, now); retained != nil {
		return &catalogRefreshOutcome{snapshot: retained, stale: true}
	}
	return &catalogRefreshOutcome{err: failure}
}

// publish stores a complete snapshot, replacing any retained answer.
//
// A snapshot from an older generation is dropped rather than written: the client
// that fetched it has already been replaced, and its answer must not become the
// replacement's catalog. Caller keeps its own copy either way, so this only fences
// the retained state.
func (c *gigahostCatalogCache) publish(scope string, generation uint64, snapshot *catalogSnapshot, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, present := c.entries[scope]; present && existing.generation > generation {
		return
	}
	snapshot.capturedAt = now
	if _, present := c.entries[scope]; !present {
		c.evictLocked()
	}
	c.entries[scope] = &gigahostCatalogEntry{snapshot: snapshot, generation: generation, lastUsed: now}
}

// fail records a failed refresh and returns the snapshot that remains servable.
//
// A failure from an older generation is not recorded: it describes a client that has
// already been replaced, and arming its backoff would suppress the replacement's own
// first read.
func (c *gigahostCatalogCache) fail(scope string, generation uint64, failure error, now time.Time) *catalogSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, present := c.entries[scope]
	if !present {
		c.evictLocked()
		entry = &gigahostCatalogEntry{generation: generation}
		c.entries[scope] = entry
	}
	if entry.generation > generation {
		return nil
	}
	entry.failedAt = now
	entry.lastErr = failure
	entry.lastUsed = now
	return entry.snapshot
}

// evictLocked keeps the table bounded by dropping the least recently used scope.
// Caller holds the lock.
func (c *gigahostCatalogCache) evictLocked() {
	if len(c.entries) < gigahostCatalogMaxScopes {
		return
	}
	var oldestKey string
	var oldest time.Time
	for key, entry := range c.entries {
		if oldestKey == "" || entry.lastUsed.Before(oldest) {
			oldestKey, oldest = key, entry.lastUsed
		}
	}
	delete(c.entries, oldestKey)
}

// invalidateAll drops every retained answer.
//
// A replaced provider client is a different account identity for this handler, so
// no earlier answer may outlive it.
func (c *gigahostCatalogCache) invalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
}

// newCatalogRead describes one answer against the freshness policy.
func newCatalogRead(snapshot *catalogSnapshot, stale bool, now time.Time) catalogRead {
	return catalogRead{
		snapshot: snapshot,
		stale:    stale,
		age:      now.Sub(snapshot.capturedAt),
		ttl:      gigahostCatalogTTL,
	}
}
