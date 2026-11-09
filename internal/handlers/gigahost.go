package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
)

// GigahostOrderRecord is the persisted ledger row. The type lives in models
// because it is a persisted entity; the alias keeps the handler-side call sites
// and JSON contracts unchanged.
type GigahostOrderRecord = models.GigahostOrder

// OrderServerPayload defines the incoming payload for manual hourly VPS orders.
type OrderServerPayload struct {
	PID            int     `json:"pid"`
	PriceID        int     `json:"price_id"`
	RegionID       int     `json:"region_id"`
	OSID           int     `json:"os_id"`
	HourlyPriceNOK float64 `json:"hourly_price_nok"`
}

// SetGigahostClient allows injecting or replacing the Gigahost API client.
func (h *Handlers) SetGigahostClient(c gigahost.Client) {
	h.gigahostMu.Lock()
	defer h.gigahostMu.Unlock()
	if c != nil {
		h.gigahostClient = &mockCatalogFallback{Client: c}
	} else {
		h.gigahostClient = nil
	}
}

// getGigahostClient resolves the client from the injected instance, request header,
// environment variable, or settings database.
func (h *Handlers) getGigahostClient(ctx context.Context, r *http.Request) (gigahost.Client, error) {
	h.gigahostMu.RLock()
	client := h.gigahostClient
	h.gigahostMu.RUnlock()
	if client != nil {
		return client, nil
	}

	var apiKey string
	if r != nil {
		apiKey = r.Header.Get("X-Gigahost-API-Key")
	}
	if apiKey == "" {
		apiKey = os.Getenv("GIGAHOST_API_KEY")
	}
	if apiKey == "" && h.db != nil {
		var cfg struct {
			APIKey string `json:"api_key"`
		}
		_ = h.db.GetSetting(ctx, "gigahost", &cfg)
		apiKey = cfg.APIKey
	}

	if apiKey == "" {
		return nil, errors.New("gigahost api key not configured: set GIGAHOST_API_KEY, gigahost setting, or X-Gigahost-API-Key header")
	}

	// Build the client with one fixed-key timing record per provider call. The
	// record carries only closed-set labels, bounded phase offsets and an
	// outcome class - never a URL, host, id, header, body or error text - so
	// the operator log can be reduced to an allowlisted artifact.
	var onCall func(gigahost.CallTiming)
	if timingEnabled() {
		onCall = func(t gigahost.CallTiming) {
			slog.Info(gigahost.CallTimingMarker, gigahost.TimingRecord(t)...)
		}
	}

	return gigahost.NewClient(gigahost.Config{
		APIKey: apiKey,
		OnCall: onCall,
	})
}

// timingEnabled reports whether provider call timing is switched on.
//
// Off by default: the record exists to diagnose a specific stall, and an
// operator turns it on deliberately for that run. Only the literal "1" enables
// it, so a stray non-empty value cannot silently start publishing records.
func timingEnabled() bool {
	return os.Getenv("GIGAHOST_CALL_TIMING") == "1"
}

// ensureGigahostOrdersTable creates or upgrades the gigahost_orders schema.
// The SQL lives in internal/database, which is the only package allowed to
// issue it.
func (h *Handlers) ensureGigahostOrdersTable(ctx context.Context) error {
	if h.db == nil {
		return nil
	}
	return h.db.EnsureGigahostOrdersSchema(ctx)
}

// saveGigahostOrder writes a new order record into the database.
func (h *Handlers) saveGigahostOrder(ctx context.Context, order *GigahostOrderRecord) error {
	if h.db == nil {
		return nil
	}
	return h.db.InsertGigahostOrder(ctx, order)
}

// updateGigahostOrder updates order_id, server_id, status, and assigned_ip of an order.
func (h *Handlers) updateGigahostOrder(ctx context.Context, order *GigahostOrderRecord) error {
	if h.db == nil {
		return nil
	}
	return h.db.UpdateGigahostOrder(ctx, order)
}

// getGigahostOrders retrieves all orders from the database ordered by creation date descending.
func (h *Handlers) getGigahostOrders(ctx context.Context) ([]GigahostOrderRecord, error) {
	if h.db == nil {
		return []GigahostOrderRecord{}, nil
	}
	return h.db.ListGigahostOrders(ctx)
}

// GigahostCatalogHandler handles GET /api/admin/hosting/gigahost/catalog.
// Retrieves available hourly VPS plans, pricing, regions, and stock status.
func (h *Handlers) GigahostCatalogHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

	client, err := h.getGigahostClient(r.Context(), r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "unconfigured", err.Error())
		return
	}

	plans, err := client.GetCatalog(r.Context())
	if err != nil {
		if errors.Is(err, gigahost.ErrUnauthorized) {
			h.JSONError(w, http.StatusBadGateway, "upstream_auth_failed", "Gigahost API authentication failed")
			return
		}
		if errors.Is(err, gigahost.ErrRateLimited) {
			h.JSONError(w, http.StatusTooManyRequests, "rate_limited", "Gigahost API rate limit exceeded")
			return
		}
		h.JSONError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}

	h.JSONOK(w, map[string]any{
		"plans": plans,
		"count": len(plans),
	})
}

// catalogEligibility derives the eligibility the provider exposes on the
// catalog itself: the first plan that carries a qualifying fact, else the
// client's own report. It is the catalog half of gigahost.HasEligibility.
func catalogEligibility(client gigahost.Client, catalogPlans []gigahost.HourlyPlan) gigahost.CatalogEligibility {
	var catalogElig gigahost.CatalogEligibility
	for _, p := range catalogPlans {
		if p.Eligibility.QualifiesArrears || p.Eligibility.CreditNOK > 0 {
			catalogElig = p.Eligibility
			break
		}
	}
	if catalogElig.QualifiesArrears || catalogElig.CreditNOK > 0 {
		return catalogElig
	}
	if ce, ok := client.(interface {
		GetCatalogEligibility() gigahost.CatalogEligibility
	}); ok {
		return ce.GetCatalogEligibility()
	}
	return catalogElig
}

// verifyAccountEligibility decides whether the account may order an hourly
// server, and returns the catalog it fetched.
//
// The catalog is fetched first because it is needed for the rest of the order
// path anyway, and because the provider documents the same eligibility facts on
// it (qualifies_arrears, credit_nok) that GET /account is consulted for.
// gigahost.HasEligibility is an OR with no deny branch, so the account can only
// ever ADD eligibility: when the catalog already qualifies, consulting the
// account cannot change the decision and is skipped. That removes a provider
// round-trip which has been observed to stall; it does not fix a general
// network fault and it does not explain the historical timeout.
//
// When the catalog does NOT qualify the account is still consulted, with the
// same outcomes as before: a failed call is account_check_failed (fail closed,
// no order) and a reaching call with no credit is ErrInsufficientCredit. No
// credit guard is removed.
func (h *Handlers) verifyAccountEligibility(ctx context.Context, client gigahost.Client) ([]gigahost.HourlyPlan, error) {
	catalogPlans, catErr := client.GetCatalog(ctx)
	if catErr != nil {
		return nil, fmt.Errorf("catalog_check_failed: %w", catErr)
	}

	catalog := &gigahost.Catalog{
		Plans:       catalogPlans,
		Eligibility: catalogEligibility(client, catalogPlans),
	}
	// Catalog-only decision: the account is nil here precisely to prove the
	// skip took effect. HasEligibility(account, catalog) can never be false for
	// a qualifying catalog, so this is equivalent to consulting the account.
	if gigahost.HasEligibility(nil, catalog) {
		return catalogPlans, nil
	}

	account, accErr := client.GetAccount(ctx)
	if accErr != nil {
		return nil, fmt.Errorf("account_check_failed: %w", accErr)
	}
	if !gigahost.HasEligibility(account, catalog) {
		return nil, gigahost.ErrInsufficientCredit
	}
	return catalogPlans, nil
}

func (h *Handlers) handleEligibilityError(w http.ResponseWriter, err error) {
	h.JSONError(w, eligibilityErrorStatus(err), eligibilityErrorCode(err), eligibilityErrorDetail(err))
}

// eligibilityErrorStatus maps an eligibility failure to its HTTP status, so the
// admission cooldown can classify it without duplicating the mapping.
func eligibilityErrorStatus(err error) int {
	if errors.Is(err, gigahost.ErrInsufficientCredit) {
		return http.StatusPaymentRequired
	}
	return http.StatusBadGateway
}

// eligibilityErrorCode is the machine-readable error code for the response.
func eligibilityErrorCode(err error) string {
	if errors.Is(err, gigahost.ErrInsufficientCredit) {
		return "insufficient_credit"
	}
	if strings.HasPrefix(err.Error(), "account_check_failed:") {
		return "account_check_failed"
	}
	return "catalog_check_failed"
}

// eligibilityErrorDetail is the human-readable explanation.
func eligibilityErrorDetail(err error) string {
	if errors.Is(err, gigahost.ErrInsufficientCredit) {
		return "Gigahost account has insufficient credit or zero balance"
	}
	if strings.HasPrefix(err.Error(), "account_check_failed:") {
		return fmt.Sprintf("Failed to check account eligibility: %v", err)
	}
	return fmt.Sprintf("Failed to fetch catalog: %v", err)
}

func (h *Handlers) handleBudgetCheckError(w http.ResponseWriter, err error) {
	if errors.Is(err, errBudgetReconciliationUnresolved) {
		h.JSONError(w, http.StatusServiceUnavailable, "budget_reconciliation_unresolved", err.Error())
	} else if strings.HasPrefix(err.Error(), "Monthly budget cap exceeded") {
		h.JSONError(w, http.StatusBadRequest, "budget_exceeded", err.Error())
	} else if strings.HasPrefix(err.Error(), "invalid_plan:") {
		h.JSONError(w, http.StatusBadRequest, "invalid_plan", strings.TrimPrefix(err.Error(), "invalid_plan: "))
	} else {
		h.JSONError(w, http.StatusBadGateway, "catalog_check_failed", err.Error())
	}
}

// orderPriceIdentity is the price contract persisted for a new order.
type orderPriceIdentity struct {
	priceID       int
	hourlyNOK     float64
	monthlyCapNOK float64
	currency      string
}

// resolveOrderPriceIdentity picks the catalog row the admin selected and keeps
// every price fact it carries: the price id (order-time selection key, never
// returned by the provider afterwards), the monthly cap (the authoritative
// monthly commitment), the hourly rate and the currency. A field the catalog
// does not carry stays zero, which the budget reads as "not recorded".
func resolveOrderPriceIdentity(catalogPlans []gigahost.HourlyPlan, req OrderServerPayload) orderPriceIdentity {
	id := orderPriceIdentity{priceID: req.PriceID, hourlyNOK: resolveAuthoritativeHourlyRate(catalogPlans, req)}
	for _, p := range catalogPlans {
		if p.ProductID != req.PID || (req.PriceID != 0 && p.PriceID != req.PriceID) {
			continue
		}
		if p.PriceID > 0 {
			id.priceID = p.PriceID
		}
		if p.MonthlyCeiling > 0 {
			id.monthlyCapNOK = p.MonthlyCeiling
		}
		if p.Currency != "" {
			id.currency = p.Currency
		}
		return id
	}
	return id
}

func resolveAuthoritativeHourlyRate(catalogPlans []gigahost.HourlyPlan, req OrderServerPayload) float64 {
	for _, p := range catalogPlans {
		if p.ProductID == req.PID && (req.PriceID == 0 || p.PriceID == req.PriceID) {
			if p.HourlyRateNOK > 0 {
				return p.HourlyRateNOK
			} else if p.MonthlyCeiling > 0 {
				return p.MonthlyCeiling / 720
			}
			break
		}
	}
	if req.HourlyPriceNOK > 0 {
		return req.HourlyPriceNOK
	}
	return 0
}

// GigahostOrderHandler handles POST /api/admin/hosting/gigahost/order.
// Verifies account credit, safely dispatches an hourly VPS order, and records the deployment job.
func (h *Handlers) GigahostOrderHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

	var req OrderServerPayload
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.PID <= 0 || req.PriceID <= 0 || req.RegionID <= 0 || req.OSID <= 0 {
		h.JSONError(w, http.StatusBadRequest, "invalid_params", "pid, price_id, region_id, os_id must be positive integers")
		return
	}

	client, err := h.getGigahostClient(r.Context(), r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "unconfigured", err.Error())
		return
	}

	// Repeated rejected attempts are suppressed here, before any provider read:
	// an admin who just hit a persistent rejection gains nothing from re-running
	// the catalog/account/inventory sequence, and the provider is already the
	// suspect. This is a retry suppression, not a cached decision - nothing about
	// eligibility or price is remembered.
	//
	// The reservation is taken ATOMICALLY with the check, before any provider
	// I/O, so concurrent requests from one admin cannot all slip through while
	// the first is blocked on the network. It is released on every terminal path
	// below; no mutex is held across a provider call.
	adminID := sess.UserID
	token, _, _, admitted := h.admitToken(adminID)
	if !admitted {
		h.suppressionWriting(w, adminID)
		return
	}

	// The reservation must survive a panic: the middleware recovers, but a slot
	// left set would lock this admin out until restart. releaseToken is
	// generation-safe - a late call from this attempt cannot clear a later
	// attempt's ownership - so the deferred net and the explicit releases below
	// cannot interfere with each other.
	failureKind := failureProviderError
	releaseOnAbort := func(kind string) {
		h.releaseToken(adminID, token, kind)
	}
	defer func() { releaseOnAbort(failureKind) }()

	catalogPlans, handled, admissionFailure := h.orderEligibilityAdmission(r.Context(), w, client, req)
	if handled {
		releaseOnAbort(admissionFailure)
		return
	}

	// 3. Concurrency serialization: lock around budget check, intent creation, and reservation
	h.budgetMu.Lock()
	defer h.budgetMu.Unlock()

	// 4. Reconcile unknown purchase state and enforce in-flight duplicate lock
	unresolved, reconcileErr := h.reconcilePendingUnknownOrders(r.Context(), client, req)
	if reconcileErr != nil {
		releaseOnAbort(failureProviderError)
		h.JSONError(w, http.StatusServiceUnavailable, "reconciliation_failed", reconcileErr.Error())
		return
	}
	if unresolved != nil {
		// An unresolved prior purchase is not this attempt's failure, but the
		// slot must still be released or the admin would be locked out.
		releaseOnAbort("")
		h.JSON(w, http.StatusAccepted, map[string]any{
			"status":  "unknown",
			"message": "Prior purchase order is pending reconciliation; refusing duplicate purchase until resolved",
			"order":   unresolved,
		})
		return
	}

	// 5. Monthly NOK budget cap enforcement
	if err := h.checkMonthlyBudget(r.Context(), client, req, catalogPlans); err != nil {
		releaseOnAbort(failureBudget)
		h.handleBudgetCheckError(w, err)
		return
	}

	// The attempt passed the pre-provider gates but is NOT finished: intent
	// persistence and the provider purchase still follow, and both are expensive.
	// The reservation is therefore held until the purchase itself terminates, so
	// a second same-admin request cannot repeat the provider reads during that
	// window. Each terminal path below releases explicitly; the deferred release
	// covers a panic.

	// 3. Pre-dispatch durable intent persistence; fail closed if DB cannot record intent
	now := time.Now().UTC()
	// The price identity of the requested order is resolved from the catalog
	// row the admin selected (product id + price id) and persisted with the
	// intent. The provider does not return price id on any later read, and an
	// existing reservation cannot be mapped back to a catalog row without it,
	// so losing it here is what made the same VPS cost 41 or 120 NOK depending
	// on catalog order.
	priceIdentity := resolveOrderPriceIdentity(catalogPlans, req)
	orderRecord := &GigahostOrderRecord{
		OrderID:        fmt.Sprintf("intent_%d", now.UnixNano()),
		Status:         "pending_order",
		PlanID:         req.PID,
		RegionID:       req.RegionID,
		HourlyPriceNOK: priceIdentity.hourlyNOK,
		PriceID:        priceIdentity.priceID,
		MonthlyCapNOK:  priceIdentity.monthlyCapNOK,
		Currency:       priceIdentity.currency,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := h.saveGigahostOrder(r.Context(), orderRecord); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "db_error",
			fmt.Sprintf("Failed to persist deployment intent: %v", err))
		return
	}

	// 4. Safe order dispatch with hourly billing enforcement
	orderReq := gigahost.OrderRequest{
		PID:           req.PID,
		PriceID:       req.PriceID,
		RegionID:      req.RegionID,
		OSID:          req.OSID,
		BillingPeriod: gigahost.BillingPeriodHourly,
		Quantity:      1,
	}

	orderResp, orderErr := client.OrderServerSafe(r.Context(), orderReq)

	// 5. Update record with cancellation-independent context
	updateCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()

	applyOrderResponseToRecord(orderRecord, orderResp, orderErr)

	if updateErr := h.updateGigahostOrder(updateCtx, orderRecord); updateErr != nil {
		h.JSONError(w, http.StatusInternalServerError, "db_update_failed",
			fmt.Sprintf("Order placed (%s) but failed to update record: %v", orderRecord.OrderID, updateErr))
		return
	}

	// The purchase cycle is finished; release the reservation on every remaining
	// outcome (partial, uncertain, failed, or success). A purchase failure arms
	// the cooldown; a success clears it.
	failureKind = failureKindFor(0, orderErr)
	releaseOnAbort(failureKind)

	if orderErr != nil {
		var partialErr *gigahost.OrderPartialError
		if errors.As(orderErr, &partialErr) {
			h.JSON(w, http.StatusPaymentRequired, map[string]any{
				"status":   orderRecord.Status,
				"message":  partialErr.Message,
				"order_id": orderRecord.OrderID,
				"order":    orderRecord,
			})
			return
		}
		var uncertainErr *gigahost.OrderUncertainError
		if errors.As(orderErr, &uncertainErr) || (orderResp != nil && (orderResp.Status == gigahost.StatusUnknown || orderResp.OrderID == "")) {
			h.JSON(w, http.StatusAccepted, map[string]any{
				"status":  "unknown",
				"message": "Order request outcome uncertain; marked unknown to prevent accidental duplicate purchases",
				"order":   orderRecord,
			})
			return
		}
		h.JSONError(w, http.StatusBadGateway, "order_failed", orderErr.Error())
		return
	}

	if orderResp != nil && (orderResp.Status == gigahost.StatusUnknown || orderResp.OrderID == "") {
		h.JSON(w, http.StatusAccepted, map[string]any{
			"status":  "unknown",
			"message": "Order request outcome uncertain; marked unknown to prevent accidental duplicate purchases",
			"order":   orderRecord,
		})
		return
	}

	h.JSONOK(w, map[string]any{
		"order":   orderRecord,
		"message": orderResp.Message,
	})
}

// isOrderActiveForBudget delegates to the shared budget contract so the
// purchase path, the admin breakdown and the recovery utility cannot classify a
// status differently.
func isOrderActiveForBudget(status string) bool {
	return gigahostbudget.IsActiveForBudget(status)
}

// requestMonthlySpend resolves the monthly ceiling of the order being requested
// through the shared calculation. It returns 0 when the requested plan is not
// resolvable, which the caller already treats as an invalid plan.
func requestMonthlySpend(catalog []gigahost.HourlyPlan, req OrderServerPayload) float64 {
	res, err := gigahostbudget.Evaluate(gigahostbudget.Input{
		Plans:   budgetPlans(catalog),
		Request: &gigahostbudget.Request{PlanID: req.PID, PriceID: req.PriceID},
	})
	if err != nil {
		return 0
	}
	return res.RequestedNOK
}

//nolint:misspell // "cancelled" matches documented provider status and test assertions
const statusCancelled = "cancelled"

func validateOrderAgainstCatalog(catalog []gigahost.HourlyPlan, req OrderServerPayload) error {
	if len(catalog) == 0 {
		return fmt.Errorf("invalid_plan: no available plans in catalog")
	}
	var matchedPlan *gigahost.HourlyPlan
	for i := range catalog {
		if catalog[i].ProductID == req.PID && (req.PriceID == 0 || catalog[i].PriceID == req.PriceID) {
			matchedPlan = &catalog[i]
			break
		}
	}
	if matchedPlan == nil {
		return fmt.Errorf("invalid_plan: plan %d (price %d) not found in provider catalog", req.PID, req.PriceID)
	}
	if !matchedPlan.InStock {
		return fmt.Errorf("invalid_plan: plan %d is out of stock", req.PID)
	}
	if len(matchedPlan.Regions) == 0 {
		return fmt.Errorf("invalid_plan: plan %d has no available regions in catalog", req.PID)
	}
	regionValid := false
	for _, r := range matchedPlan.Regions {
		if r.ID == req.RegionID && r.Available {
			regionValid = true
			break
		}
	}
	if !regionValid {
		return fmt.Errorf("invalid_plan: region %d is not available for plan %d", req.RegionID, req.PID)
	}

	planMonthlyRate := requestMonthlySpend(catalog, req)
	if planMonthlyRate <= 0 {
		return fmt.Errorf("invalid_plan: plan %d has zero or negative price in provider catalog", req.PID)
	}
	return nil
}

// budgetEvaluation is one complete budget decision plus the evidence it was
// derived from. The purchase path, the admin breakdown endpoint and the operator
// recovery utility all consume this same structure, so display and decision
// cannot diverge.
type budgetEvaluation struct {
	result gigahostbudget.Result
	// servers/localOrders are the observations the decision used, kept so the
	// reconciliation pass can write status updates without a second read.
	servers     []gigahost.ServerInfo
	localOrders []GigahostOrderRecord
}

// budgetError maps a shared budget error to the handler's HTTP contract. The
// pre-existing 502 catalog_check_failed shape is preserved for an unpriceable
// commitment, because an operator must not mistake it for a budget rejection.
func budgetError(err error) error {
	return fmt.Errorf("failed to calculate committed spend: %w", err)
}

// evaluateBudget computes the single authoritative budget result for one
// request. It reconciles conclusive releases durably before pricing; a rejected
// or failed transition aborts the decision instead of freeing budget in memory.
func (h *Handlers) evaluateBudget(ctx context.Context, client gigahost.Client, req OrderServerPayload, cachedCatalog ...[]gigahost.HourlyPlan) (budgetEvaluation, error) {
	var catalog []gigahost.HourlyPlan
	if len(cachedCatalog) > 0 && cachedCatalog[0] != nil {
		catalog = cachedCatalog[0]
	} else if client != nil {
		var catErr error
		catalog, catErr = client.GetCatalog(ctx)
		if catErr != nil {
			return budgetEvaluation{}, fmt.Errorf("failed to check catalog for budget verification: %w", catErr)
		}
	}

	if err := validateOrderAgainstCatalog(catalog, req); err != nil {
		return budgetEvaluation{}, err
	}

	monthlyBudget, err := h.getMonthlyBudgetNOK(ctx)
	if err != nil {
		return budgetEvaluation{}, fmt.Errorf("failed to verify monthly budget: %w", err)
	}

	// A cap of zero disables the check, exactly as before: no inventory or
	// ledger read is issued in that case, so a disabled cap cannot start
	// failing order attempts on a provider read it never used to make.
	if monthlyBudget <= 0 {
		return budgetEvaluation{result: gigahostbudget.Result{CapNOK: 0, Allowed: true}}, nil
	}

	servers, srvErr := client.GetServers(ctx)
	if srvErr != nil {
		return budgetEvaluation{}, fmt.Errorf("failed to check existing server inventory for budget verification: %w", srvErr)
	}

	localOrders, ordErr := h.getGigahostOrders(ctx)
	if ordErr != nil {
		return budgetEvaluation{}, fmt.Errorf("failed to check local orders for budget verification: %w", ordErr)
	}

	// Reconcile provider status into the ledger first, then price the result:
	// a reservation the provider has conclusively ended must not be counted as
	// committed, and this is the pre-existing automatic reconciliation.
	reconciled := h.reconcileLedgerReservations(ctx, client, servers, localOrders)
	if reconciled.err != nil {
		return budgetEvaluation{}, reconciled.err
	}
	evidence := reconciled.evidence
	if len(reconciled.released) > 0 {
		// Re-read so the priced snapshot includes the releases just written.
		// Failing here must not silently keep released spend in the total.
		fresh, freshErr := h.getGigahostOrders(ctx)
		if freshErr != nil {
			return budgetEvaluation{}, fmt.Errorf("failed to re-read local orders after reconciliation: %w", freshErr)
		}
		localOrders = fresh
	}

	res, err := gigahostbudget.Evaluate(gigahostbudget.Input{
		CapNOK:   monthlyBudget,
		Plans:    budgetPlans(catalog),
		Servers:  budgetServers(servers),
		Entries:  budgetEntries(localOrders),
		Evidence: evidence,
		Request: &gigahostbudget.Request{
			PlanID:         req.PID,
			PriceID:        req.PriceID,
			HourlyPriceNOK: req.HourlyPriceNOK,
		},
	})
	if err != nil {
		return budgetEvaluation{}, budgetError(err)
	}
	return budgetEvaluation{result: res, servers: servers, localOrders: localOrders}, nil
}

func (h *Handlers) checkMonthlyBudget(ctx context.Context, client gigahost.Client, req OrderServerPayload, cachedCatalog ...[]gigahost.HourlyPlan) error {
	evaluated, err := h.evaluateBudget(ctx, client, req, cachedCatalog...)
	if err != nil {
		return err
	}
	if !evaluated.result.Allowed {
		return fmt.Errorf("Monthly budget cap exceeded: requested order exceeds configured budget of %v NOK (committed %v + requested %v)",
			evaluated.result.CapNOK, evaluated.result.CommittedNOK, evaluated.result.RequestedNOK)
	}
	return nil
}

func (h *Handlers) getMonthlyBudgetNOK(ctx context.Context) (float64, error) {
	if h.db == nil {
		return 0, nil
	}
	var ghCfg map[string]any
	if err := h.db.GetSetting(ctx, "gigahost", &ghCfg); err != nil {
		return 0, fmt.Errorf("read monthly budget: %w", err)
	}
	rawVal := ghCfg["monthly_budget_nok"]
	if rawVal == nil {
		var directVal any
		if err := h.db.GetSetting(ctx, "gigahost.monthly_budget_nok", &directVal); err != nil {
			return 0, fmt.Errorf("read monthly budget: %w", err)
		}
		rawVal = directVal
	}
	if rawVal == nil {
		return 0, nil
	}
	val, err := parseBudgetVal(rawVal)
	if err != nil {
		return 0, fmt.Errorf("read monthly budget: %w", err)
	}
	return val, nil
}

func isPendingOrInFlight(status string) bool {
	switch strings.ToLower(status) {
	case "pending_order", gigahost.StatusUnknown, gigahost.StatusWaiting, "pending_payment",
		gigahost.StatusPending, gigahost.StatusDeploying, gigahost.StatusInstalling:
		return true
	default:
		return false
	}
}

func (h *Handlers) reconcileSingleOrder(ctx context.Context, client gigahost.Client, order *GigahostOrderRecord, servers []gigahost.ServerInfo) {
	matched := false
	for _, s := range servers {
		if s.OrderID != "" && s.OrderID == order.OrderID {
			if s.ID > 0 {
				order.ServerID = s.ID
			}
			if ip := s.GetIP(); ip != "" {
				order.AssignedIP = ip
			}
			matched = true
			break
		}
	}
	if order.OrderID != "" && !strings.HasPrefix(order.OrderID, "intent_") && !strings.HasPrefix(order.OrderID, "unknown_") {
		statusResp, err := client.GetDeployStatus(ctx, order.OrderID)
		if err == nil && statusResp != nil && statusResp.Status != "" {
			order.Status = statusResp.Status
			if statusResp.ServerID > 0 {
				order.ServerID = statusResp.ServerID
			}
			if ip := statusResp.GetIP(); ip != "" {
				order.AssignedIP = ip
			}
		} else if matched {
			for _, s := range servers {
				if s.OrderID != "" && s.OrderID == order.OrderID {
					if s.Status == gigahost.StatusReady {
						order.Status = gigahost.StatusReady
					}
					break
				}
			}
		}
		_ = h.updateGigahostOrder(ctx, order)
	} else if matched {
		_ = h.updateGigahostOrder(ctx, order)
	}
}

func (h *Handlers) reconcilePendingUnknownOrders(ctx context.Context, client gigahost.Client, req OrderServerPayload) (*GigahostOrderRecord, error) {
	existingOrders, err := h.getGigahostOrders(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read local orders: %w", err)
	}
	var servers []gigahost.ServerInfo
	var checkErr error
	checkedServers := false

	for i := range existingOrders {
		if !isPendingOrInFlight(existingOrders[i].Status) {
			continue
		}
		if !checkedServers {
			servers, checkErr = client.GetServers(ctx)
			if checkErr != nil {
				return nil, fmt.Errorf("cannot verify provider inventory while order %s is unresolved: %w", existingOrders[i].OrderID, checkErr)
			}
			checkedServers = true
		}
		h.reconcileSingleOrder(ctx, client, &existingOrders[i], servers)

		if isPendingOrInFlight(existingOrders[i].Status) && existingOrders[i].PlanID == req.PID && existingOrders[i].RegionID == req.RegionID {
			return &existingOrders[i], nil
		}
	}
	return nil, nil
}

func applyOrderResponseToRecord(orderRecord *GigahostOrderRecord, orderResp *gigahost.OrderResponse, orderErr error) {
	if orderResp != nil {
		if orderResp.OrderID != "" {
			orderRecord.OrderID = orderResp.OrderID
		}
		if orderResp.ServerID > 0 {
			orderRecord.ServerID = orderResp.ServerID
		}
		if orderResp.Status != "" {
			orderRecord.Status = orderResp.Status
		}
		// The provider's own order-time contract outranks the catalog row the
		// order was placed with: it is what this specific order was billed.
		// Only a real value replaces the catalog estimate; an absent field
		// leaves the catalog-derived value in place.
		if orderResp.MonthlyCap > 0 {
			orderRecord.MonthlyCapNOK = orderResp.MonthlyCap
		}
		if orderResp.RateHourly > 0 {
			orderRecord.HourlyPriceNOK = orderResp.RateHourly
		}
		if orderResp.Currency != "" {
			orderRecord.Currency = orderResp.Currency
		}
	}
	var partialErr *gigahost.OrderPartialError
	if errors.As(orderErr, &partialErr) {
		if firstID := partialErr.FirstOrderID(); firstID != "" {
			orderRecord.OrderID = firstID
		}
		orderRecord.Status = gigahost.StatusWaiting
		return
	}
	var uncertainErr *gigahost.OrderUncertainError
	if errors.As(orderErr, &uncertainErr) || (orderResp != nil && (orderResp.Status == gigahost.StatusUnknown || orderResp.OrderID == "")) {
		orderRecord.Status = gigahost.StatusUnknown
		return
	}
	if orderErr != nil {
		if orderRecord.Status == "pending_order" {
			orderRecord.Status = gigahost.StatusFailed
		}
	}
	if orderRecord.Status == "pending_order" {
		orderRecord.Status = gigahost.StatusPending
	}
}

func isTerminalStatus(status string) bool {
	s := strings.ToLower(status)
	switch {
	case s == gigahost.StatusFailed || s == "deleted" || s == "terminated":
		return true
	case strings.HasPrefix(s, "cancel"):
		return true
	default:
		return false
	}
}

func (h *Handlers) refreshOrderFromServers(servers []gigahost.ServerInfo, order *GigahostOrderRecord) bool {
	for _, s := range servers {
		if s.OrderID != "" && s.OrderID == order.OrderID {
			updated := false
			if s.Status != "" && s.Status != order.Status && !strings.EqualFold(s.Status, "active") {
				if isTerminalStatus(s.Status) || !isPendingOrInFlight(order.Status) {
					order.Status = s.Status
					updated = true
				}
			}
			if s.ID > 0 && order.ServerID != s.ID {
				order.ServerID = s.ID
				updated = true
			}
			if ip := s.GetIP(); ip != "" && ip != order.AssignedIP {
				order.AssignedIP = ip
				updated = true
			}
			return updated
		}
	}
	return false
}

func (h *Handlers) refreshOrderFromDeployStatus(ctx context.Context, client gigahost.Client, order *GigahostOrderRecord) bool {
	if strings.HasPrefix(order.OrderID, "unknown_") || strings.HasPrefix(order.OrderID, "intent_") || order.OrderID == "" {
		return false
	}
	statusResp, deployErr := client.GetDeployStatus(ctx, order.OrderID)
	if deployErr == nil {
		updated := false
		if statusResp != nil && statusResp.Status != "" && statusResp.Status != order.Status {
			order.Status = statusResp.Status
			updated = true
		} else if (order.Status == gigahost.StatusReady || strings.ToLower(order.Status) == "active") && (statusResp == nil || statusResp.Status == "") {
			order.Status = statusCancelled
			updated = true
		}
		if statusResp != nil {
			if ip := statusResp.GetIP(); ip != "" && ip != order.AssignedIP {
				order.AssignedIP = ip
				updated = true
			}
			if statusResp.ServerID > 0 && order.ServerID != statusResp.ServerID {
				order.ServerID = statusResp.ServerID
				updated = true
			}
		}
		return updated
	} else if errors.Is(deployErr, gigahost.ErrNotFound) && (order.Status == gigahost.StatusReady || strings.ToLower(order.Status) == "active") {
		order.Status = statusCancelled
		return true
	}
	return false
}

// GigahostOrdersHandler handles GET /api/admin/hosting/gigahost/orders.
// Lists persistent order history and refreshes status for active/pending jobs.
func (h *Handlers) GigahostOrdersHandler(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return
	}

	orders, err := h.getGigahostOrders(r.Context())
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	// Refresh all non-terminal orders if client is accessible
	client, clientErr := h.getGigahostClient(r.Context(), r)
	if clientErr == nil && len(orders) > 0 {
		servers, _ := client.GetServers(r.Context())
		deployQueries := 0
		const maxDeployQueries = 10
		for i := range orders {
			if isTerminalStatus(orders[i].Status) {
				continue
			}
			updated := false
			if len(servers) > 0 && h.refreshOrderFromServers(servers, &orders[i]) {
				updated = true
			}
			if (isPendingOrInFlight(orders[i].Status) || !updated) && deployQueries < maxDeployQueries {
				if orders[i].OrderID != "" && !strings.HasPrefix(orders[i].OrderID, "unknown_") && !strings.HasPrefix(orders[i].OrderID, "intent_") {
					deployQueries++
					if h.refreshOrderFromDeployStatus(r.Context(), client, &orders[i]) {
						updated = true
					}
				}
			}
			if updated {
				_ = h.updateGigahostOrder(r.Context(), &orders[i])
			}
		}
	}

	h.JSONOK(w, map[string]any{
		"orders": orders,
		"count":  len(orders),
	})
}
