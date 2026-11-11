package handlers

// The Gigahost catalog DISPLAY boundary: the read-only endpoint the ordering
// page uses, and its provider-failure mapping.
//
// It lives beside - and is deliberately separate from - the purchase path in
// gigahost.go, because the two have opposite requirements. A display read may
// serve a cached snapshot and may serve it stale; a purchase must read the live
// provider catalog and revalidate every selection fact itself. Keeping them in
// different files makes "the order path does not call this" reviewable by
// inspection as well as by test.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// GigahostCatalogHandler handles GET /api/admin/hosting/gigahost/catalog.
// Retrieves available hourly VPS plans with the provider's documented region,
// datacenter and operating-system choices, plus hourly price and currency.
//
// This is a DISPLAY read. It serves the per-account cached snapshot described in
// gigahost_catalog_cache.go and never authorizes a purchase: the order path reads
// the live provider catalog and revalidates the selection itself.
func (h *Handlers) GigahostCatalogHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

	resolved, err := h.resolveGigahostClient(r.Context(), r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "unconfigured", err.Error())
		return
	}

	read, err := h.catalogCache().load(r.Context(), catalogScopeKey(resolved.credential), resolved.generation, h.catalogFetcher(resolved.client))
	if err != nil {
		h.catalogUpstreamError(w, err)
		return
	}

	body := map[string]any{
		"plans":            read.snapshot.plans,
		"count":            len(read.snapshot.plans),
		"operating_system": read.snapshot.images,
		"os_count":         len(read.snapshot.images),
		"stale":            read.stale,
		"fetched_at":       read.snapshot.capturedAt.UTC().Format(time.RFC3339),
		"age_seconds":      int64(read.age / time.Second),
		"ttl_seconds":      int64(read.ttl / time.Second),
	}
	if read.stale {
		// Named explicitly so the portal can say why the snapshot is old instead
		// of implying a failed read produced nothing.
		body["state"] = "stale"
	} else {
		body["state"] = "fresh"
	}
	h.JSONOK(w, body)
}

// catalogFetcher adapts one provider client to the cache's complete-read
// contract. A refresh publishes only when BOTH the plan list and the image
// catalog were read, which is why it reuses loadSelectablePlans: that function
// already fails the whole read when either half fails, so a partial answer can
// never reach the cache.
//
// A malformed HTTP-success response also fails that whole read. The provider's
// distribution and image parsers reject a body whose documented envelope or
// required identity is missing, rather than decoding it into an empty list, so
// the failure reaches the cache as an error and takes the retained-snapshot and
// backoff path instead of publishing a snapshot with no usable image options.
// An explicitly empty provider answer is still a successful read; only a broken
// envelope is rejected.
//
// An empty plan list is a complete answer, not a failure: the provider really can
// publish no hourly plan for an account, and the portal already renders that state
// as "no deployable plans". Reporting it as an error instead would make a genuine
// empty catalog indistinguishable from an unavailable provider.
func (h *Handlers) catalogFetcher(client gigahost.Client) catalogFetcher {
	return func(ctx context.Context) (*catalogSnapshot, error) {
		plans, images, err := h.loadSelectablePlans(ctx, client)
		if err != nil {
			return nil, err
		}
		return &catalogSnapshot{plans: plans, images: images}, nil
	}
}

// catalogUpstreamError maps a provider failure to the catalog endpoint's
// existing status contract.
func (h *Handlers) catalogUpstreamError(w http.ResponseWriter, err error) {
	if errors.Is(err, gigahost.ErrUnauthorized) {
		h.JSONError(w, http.StatusBadGateway, "upstream_auth_failed", "Gigahost API authentication failed")
		return
	}
	if errors.Is(err, gigahost.ErrRateLimited) {
		h.JSONError(w, http.StatusTooManyRequests, "rate_limited", "Gigahost API rate limit exceeded")
		return
	}
	h.JSONError(w, http.StatusBadGateway, "upstream_error", "Gigahost catalog is currently unavailable")
}
