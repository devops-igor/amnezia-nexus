package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// These tests drive the real GigahostOrderHandler and GigahostCatalogHandler with
// a fake provider that returns documented catalog/images. They are the consumer
// side of the valid-selection contract: a selection the provider actually
// published reaches exactly one purchase, and every stale, tampered, unavailable
// or unreadable selection reaches zero.

// selectionHarness is one handler plus the counters a test asserts on.
type selectionHarness struct {
	h    *Handlers
	post *atomic.Int32
}

// newSelectionHarness installs a fake provider whose catalog and image list the
// test supplies.
func newSelectionHarness(
	t *testing.T,
	plans []gigahost.HourlyPlan,
	images []gigahost.OperatingSystem,
	imageErr error,
) *selectionHarness {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	posts := &atomic.Int32{}
	h.SetGigahostClient(&mockGigahostClient{
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return attachImages(plans, images), nil
		},
		getOSFn: func(context.Context) ([]gigahost.OperatingSystem, error) {
			return images, imageErr
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
		orderServerSafeFn: func(_ context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{OrderID: "ord_selected", Status: gigahost.StatusPending}, nil
		},
	})
	return &selectionHarness{h: h, post: posts}
}

// attachImages mirrors the production shape: the catalog read carries the images
// so the plan's os_options are real provider values.
func attachImages(plans []gigahost.HourlyPlan, images []gigahost.OperatingSystem) []gigahost.HourlyPlan {
	out := make([]gigahost.HourlyPlan, len(plans))
	copy(out, plans)
	for i := range out {
		out[i].OSOptions = out[i].InstallableImages(images)
	}
	return out
}

// order posts one order as an admin and returns the recorder. Each call uses a
// distinct admin identity so one case's rejection does not arm the retained
// repeated-submission cooldown for the next: that cooldown is a separate,
// deliberately retained protection and is not what these cases measure.
func (s *selectionHarness) order(t *testing.T, admin string, pid, priceID, regionID, osID int) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(OrderServerPayload{PID: pid, PriceID: priceID, RegionID: regionID, OSID: osID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(string(body)))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: admin, Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	s.h.GigahostOrderHandler(w, req)
	return w
}

// TestGigahostSelection_ValidProviderSelectionPurchasesOnce is the positive
// control: a plan, region and image the provider published must reach exactly one
// purchase call through the real handler.
func TestGigahostSelection_ValidProviderSelectionPurchasesOnce(t *testing.T) {
	s := newSelectionHarness(t, []gigahost.HourlyPlan{fixtureHourlyPlan()}, fixtureOperatingSystems(), nil)

	w := s.order(t, "admin-valid", 101, 555, 1, testOSDebian12)
	if w.Code != http.StatusOK {
		t.Fatalf("valid provider selection: status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if got := s.post.Load(); got != 1 {
		t.Errorf("provider purchase calls = %d, want exactly 1", got)
	}

	orders, err := s.h.getGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("reading orders: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("persisted orders = %d, want 1", len(orders))
	}
	if orders[0].RegionID != 1 || orders[0].PlanID != 101 {
		t.Errorf("persisted selection = plan %d region %d, want 101/1", orders[0].PlanID, orders[0].RegionID)
	}
	if orders[0].HourlyPriceNOK != fixtureHourlyPlan().HourlyRateNOK {
		t.Errorf("persisted hourly price = %v, want the catalog rate %v",
			orders[0].HourlyPriceNOK, fixtureHourlyPlan().HourlyRateNOK)
	}
	if orders[0].Currency != "NOK" {
		t.Errorf("persisted currency = %q, want the catalog currency NOK", orders[0].Currency)
	}
}

// TestGigahostSelection_StaleOrTamperedSelectionNeverPurchases covers every way a
// selection can disagree with the provider: an image the catalog never published,
// an image the plan cannot install, a region the plan does not serve, a region
// with no stock and a plan that is sold out. Each must fail before the purchase.
func TestGigahostSelection_StaleOrTamperedSelectionNeverPurchases(t *testing.T) {
	noStock := false
	soldOutPlan := fixtureHourlyPlan()
	soldOutPlan.ProductID = 103
	soldOutPlan.PriceID = 557
	soldOutPlan.InStock = false
	soldOutPlan.BuiltToOrder = false

	emptyRegionPlan := fixtureHourlyPlan()
	emptyRegionPlan.ProductID = 104
	emptyRegionPlan.PriceID = 558
	emptyRegionPlan.Regions = []gigahost.Region{{ID: 1, Name: "Norway", Available: true, InStock: &noStock}}
	emptyRegionPlan.Datacenters = []gigahost.Datacenter{{ID: 1, RegionID: 1, InStock: false}}

	cases := []struct {
		name      string
		pid       int
		priceID   int
		regionID  int
		osID      int
		wantInMsg string
	}{
		{
			name: "unknown image id", pid: 101, priceID: 555, regionID: 1, osID: 999,
			wantInMsg: "operating system 999 is not available",
		},
		{
			name: "dedicated-only image on a cloud plan", pid: 101, priceID: 555, regionID: 1, osID: 90,
			wantInMsg: "operating system 90 is not available",
		},
		{
			name: "ram-gated image on a 4 GB plan", pid: 101, priceID: 555, regionID: 1, osID: 93,
			wantInMsg: "operating system 93 is not available",
		},
		{
			name: "region the plan does not serve", pid: 101, priceID: 555, regionID: 42, osID: testOSDebian12,
			wantInMsg: "region 42 is not available",
		},
		{
			name: "region with no stock", pid: 104, priceID: 558, regionID: 1, osID: testOSDebian12,
			wantInMsg: "region 1 is not available",
		},
		{
			name: "sold out plan", pid: 103, priceID: 557, regionID: 1, osID: testOSDebian12,
			wantInMsg: "out of stock",
		},
	}

	harness := newSelectionHarness(t,
		[]gigahost.HourlyPlan{fixtureHourlyPlan(), soldOutPlan, emptyRegionPlan},
		fixtureOperatingSystems(), nil)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := harness.post.Load()
			w := harness.order(t, "admin-case-"+tc.name, tc.pid, tc.priceID, tc.regionID, tc.osID)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantInMsg) {
				t.Errorf("body = %s, want it to contain %q", w.Body.String(), tc.wantInMsg)
			}
			if got := harness.post.Load() - before; got != 0 {
				t.Errorf("provider purchase calls = %d, want 0", got)
			}
		})
	}
}

// TestGigahostSelection_ImageCatalogFailureNeverPurchases proves a provider image
// read that fails is a hard refusal: the plan's image set is unknown, so nothing
// may be ordered from it.
func TestGigahostSelection_ImageCatalogFailureNeverPurchases(t *testing.T) {
	s := newSelectionHarness(t,
		[]gigahost.HourlyPlan{fixtureHourlyPlan()},
		nil,
		gigahost.ErrRateLimited)

	w := s.order(t, "admin-imagefail", 101, 555, 1, testOSDebian12)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when the image catalog cannot be read (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "catalog_check_failed") {
		t.Errorf("body = %s, want catalog_check_failed", w.Body.String())
	}
	if got := s.post.Load(); got != 0 {
		t.Errorf("provider purchase calls = %d, want 0", got)
	}
}

// TestGigahostSelection_CatalogHandlerPublishesProviderChoices proves the portal
// read exposes exactly the provider's images and placement facts, including the
// stock of each region and datacenter, and never a synthesized plan.
func TestGigahostSelection_CatalogHandlerPublishesProviderChoices(t *testing.T) {
	noStock, inStock := false, true
	planMixed := fixtureHourlyPlan()
	planMixed.ProductID = 101
	planMixed.Regions = []gigahost.Region{
		{ID: 1, Name: "Norway", Country: "NO", Available: true, InStock: &inStock},
		{ID: 2, Name: "Sweden", Country: "SE", Available: true, InStock: &noStock},
	}
	planMixed.Datacenters = []gigahost.Datacenter{
		{ID: 1, Name: "DC1", RegionID: 1, InStock: true},
		{ID: 2, Name: "DC2", RegionID: 2, InStock: false},
	}

	h, _, _ := setupTestHandlers(t)
	h.SetGigahostClient(&mockGigahostClient{
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{planMixed}, nil
		},
		getOSFn: func(context.Context) ([]gigahost.OperatingSystem, error) {
			return fixtureOperatingSystems(), nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostCatalogHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp struct {
		Count  int                        `json:"count"`
		Plans  []gigahost.HourlyPlan      `json:"plans"`
		Images []gigahost.OperatingSystem `json:"operating_system"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding catalog response: %v (body: %s)", err, w.Body.String())
	}
	if resp.Count != 1 || len(resp.Plans) != 1 {
		t.Fatalf("catalog count = %d (plans %d), want 1", resp.Count, len(resp.Plans))
	}
	if len(resp.Images) != len(fixtureOperatingSystems()) {
		t.Errorf("published images = %d, want the provider's %d", len(resp.Images), len(fixtureOperatingSystems()))
	}

	plan := resp.Plans[0]
	if plan.Currency != "NOK" || plan.HourlyRateNOK != 0.14375 || plan.MonthlyCeiling != 90 {
		t.Errorf("published price = %s %v/hr max %v, want NOK 0.14375/hr max 90",
			plan.Currency, plan.HourlyRateNOK, plan.MonthlyCeiling)
	}
	// The plan is a 4 GB cloud plan, so the dedicated-only and 8 GB images must not
	// be offered even though the provider lists them.
	var offered []int
	for _, os := range plan.OSOptions {
		offered = append(offered, os.OSID)
	}
	if len(offered) != 2 || offered[0] != testOSDebian12 || offered[1] != testOSUbuntu {
		t.Errorf("offered images = %v, want [%d %d]", offered, testOSDebian12, testOSUbuntu)
	}

	// Both regions are published with their own stock fact, so the portal can hide
	// the sold-out one instead of falling back to a guessed region.
	if len(plan.Regions) != 2 {
		t.Fatalf("published regions = %d, want the plan's 2", len(plan.Regions))
	}
	if plan.Regions[0].InStock == nil || !*plan.Regions[0].InStock {
		t.Errorf("region 1 stock = %v, want true", plan.Regions[0].InStock)
	}
	if plan.Regions[1].InStock == nil || *plan.Regions[1].InStock {
		t.Errorf("region 2 stock = %v, want false", plan.Regions[1].InStock)
	}
	if len(plan.Datacenters) != 2 {
		t.Errorf("published datacenters = %d, want the plan's 2", len(plan.Datacenters))
	}
}

// TestGigahostSelection_CatalogHandlerFailsWhenImagesUnreadable proves the portal
// read does not degrade to a plan list whose images are unknown: an unreadable
// image catalog is an upstream failure, not an empty choice set.
func TestGigahostSelection_CatalogHandlerFailsWhenImagesUnreadable(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	h.SetGigahostClient(&mockGigahostClient{
		getCatalogFn: fixtureCatalogFn,
		getOSFn: func(context.Context) ([]gigahost.OperatingSystem, error) {
			return nil, gigahost.ErrUnauthorized
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostCatalogHandler(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "upstream_auth_failed") {
		t.Errorf("body = %s, want upstream_auth_failed", w.Body.String())
	}
}
