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

// validate rejects a payload the provider cannot be asked to fulfill. Every
// selection key is required; the client-supplied hourly rate is not, because the
// provider catalog is the authoritative price.
func (p OrderServerPayload) validate() error {
	if p.PID <= 0 || p.PriceID <= 0 || p.RegionID <= 0 || p.OSID <= 0 {
		return errors.New("pid, price_id, region_id, os_id must be positive integers")
	}
	return nil
}

// SetGigahostClient allows injecting or replacing the Gigahost API client.
//
// A replaced client is a different provider account identity for this handler, so
// every retained display snapshot is dropped with it, and the catalog generation is
// advanced in the same step. An in-flight refresh that belongs to the previous
// client can then neither be joined by the replacement nor publish over it - not
// even while the replacement's table is still empty.
func (h *Handlers) SetGigahostClient(c gigahost.Client) {
	h.advanceGeneration(c)
}

// gigahostClientResolution is a resolved provider client plus the account
// identity it acts for.
//
// credential is the provider API key the client was built from, and it is empty
// for an explicitly injected client. It is carried out of resolution because the
// display cache is scoped per account; nothing that receives it may log, return,
// store or otherwise expose it.
//
// generation is the catalog client epoch this client was resolved under. Client and
// generation are read under one lock so a request can never act as one client while
// labeling its work with another client's epoch.
type gigahostClientResolution struct {
	client     gigahost.Client
	credential string
	generation uint64
}

// getGigahostClient resolves the client from the injected instance, request header,
// environment variable, or settings database.
func (h *Handlers) getGigahostClient(ctx context.Context, r *http.Request) (gigahost.Client, error) {
	resolved, err := h.resolveGigahostClient(ctx, r)
	if err != nil {
		return nil, err
	}
	return resolved.client, nil
}

// resolveGigahostClient resolves the provider client together with the account
// identity it acts for. See gigahostClientResolution.
func (h *Handlers) resolveGigahostClient(ctx context.Context, r *http.Request) (gigahostClientResolution, error) {
	h.gigahostMu.RLock()
	client := h.gigahostClient
	// Same critical section as the client read: a replacement swaps the client and
	// the epoch together under the write lock, so this pair is never mixed.
	generation := h.catalogCache().currentGeneration()
	h.gigahostMu.RUnlock()
	if client != nil {
		return gigahostClientResolution{client: client, generation: generation}, nil
	}

	apiKey := h.gigahostCredential(ctx, r)
	if apiKey == "" {
		return gigahostClientResolution{}, errors.New("gigahost api key not configured: set GIGAHOST_API_KEY, gigahost setting, or X-Gigahost-API-Key header")
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

	built, err := gigahost.NewClient(gigahost.Config{
		APIKey: apiKey,
		OnCall: onCall,
	})
	if err != nil {
		return gigahostClientResolution{}, err
	}
	// The built client belongs to whatever client generation is current now. The
	// epoch is re-read here because building the client happens outside the lock and
	// a replacement may have raced it; reading it late keeps client and epoch
	// coherent, and the caller's own read then carries that paired identity.
	generation = h.catalogCache().currentGeneration()
	return gigahostClientResolution{client: built, credential: apiKey, generation: generation}, nil
}

// gigahostCredential resolves the provider API key from the request header, the
// environment or the settings database, in that precedence. It returns "" when
// none is configured.
func (h *Handlers) gigahostCredential(ctx context.Context, r *http.Request) string {
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
	return apiKey
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
	if h.gigahostIntentHook != nil {
		h.gigahostIntentHook()
	}
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

// loadSelectablePlans reads the provider catalog and its documented image
// catalog, then attaches to every plan the images that can actually be installed
// on it. Both reads are required: a plan is never published with a guessed or
// partial selection set, because an order built from one would be rejected by
// the provider after the money-moving request.
func (h *Handlers) loadSelectablePlans(ctx context.Context, client gigahost.Client) ([]gigahost.HourlyPlan, []gigahost.OperatingSystem, error) {
	plans, err := client.GetCatalog(ctx)
	if err != nil {
		return nil, nil, err
	}
	images, err := client.GetOperatingSystems(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read provider operating systems: %w", err)
	}
	for i := range plans {
		plans[i].OSOptions = plans[i].InstallableImages(images)
	}
	return plans, images, nil
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
	catalogPlans, _, catErr := h.loadSelectablePlans(ctx, client)
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

// handleCatalogCheckError maps a catalog/plan validation failure to the
// handler's HTTP contract. Every branch here is about what the provider
// catalog says about the requested plan, never about a spending decision.
func (h *Handlers) handleCatalogCheckError(w http.ResponseWriter, err error) {
	if strings.HasPrefix(err.Error(), "invalid_plan:") {
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

	req, client, ok := h.orderRequestAndClient(w, r)
	if !ok {
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

	// 3-4. Serialize the duplicate check together with the durable intent that makes
	// its decision visible to later attempts. The check and the intent write are ONE
	// critical section on purpose: releasing the lock between them let a second
	// request find no durable intent and purchase as well (CI run 42576536602).
	// The lock is dropped before the provider call, so no network I/O runs under it
	// and a genuinely different purchase is not blocked behind this one.
	orderRecord, unlockPurchase, gated := h.beginPurchaseWithIntent(r.Context(), w, client, req, catalogPlans, releaseOnAbort)
	if !gated {
		return
	}

	orderResp, orderErr := h.dispatchOrderPurchase(r.Context(), client, req, orderRecord)
	unlockPurchase()

	if orderRecord == nil {
		h.JSONError(w, http.StatusInternalServerError, "db_update_failed",
			"The order was placed but its record could not be updated; the durable intent remains and blocks a retry")
		return
	}

	// The purchase cycle is finished; release the reservation on every remaining
	// outcome (partial, uncertain, failed, or success). A purchase failure arms
	// the cooldown; a success clears it.
	failureKind = failureKindFor(0, orderErr)
	releaseOnAbort(failureKind)

	h.respondToOrderOutcome(w, orderRecord, orderResp, orderErr)
}

// respondUnresolvedDuplicate refuses a second purchase while a prior attempt's
// outcome is still unknown, and shows the admin which order blocks them.
func (h *Handlers) respondUnresolvedDuplicate(w http.ResponseWriter, unresolved *GigahostOrderRecord) {
	h.JSON(w, http.StatusAccepted, map[string]any{
		"status":  "unknown",
		"message": "Prior purchase order is pending reconciliation; refusing duplicate purchase until resolved",
		"order":   unresolved,
	})
}

// respondToOrderOutcome writes the response for a completed purchase attempt.
//
// The three interesting outcomes are ordered by how much is known: a partial
// order has a real id and a known message, an uncertain outcome is explicitly
// NOT retryable (it is reported as unknown so a second purchase cannot be
// guessed into existence), and anything else is a plain provider failure. A
// success whose provider response carries no usable id is treated as uncertain
// for the same reason.
func (h *Handlers) respondToOrderOutcome(
	w http.ResponseWriter, orderRecord *GigahostOrderRecord, orderResp *gigahost.OrderResponse, orderErr error,
) {
	unknownBody := map[string]any{
		"status":  "unknown",
		"message": "Order request outcome uncertain; marked unknown to prevent accidental duplicate purchases",
		"order":   orderRecord,
	}

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
		if writePrePurchaseRefusal(w, orderErr, h) {
			return
		}
		var uncertainErr *gigahost.OrderUncertainError
		if errors.As(orderErr, &uncertainErr) || orderOutcomeUnknown(orderResp) {
			h.JSON(w, http.StatusAccepted, unknownBody)
			return
		}
		h.JSONError(w, http.StatusBadGateway, "order_failed", orderErr.Error())
		return
	}

	if orderOutcomeUnknown(orderResp) {
		h.JSON(w, http.StatusAccepted, unknownBody)
		return
	}

	h.JSONOK(w, map[string]any{
		"order":   orderRecord,
		"message": orderResp.Message,
	})
}

// orderOutcomeUnknown reports whether a provider order response fails to
// identify what was ordered, which makes the outcome unsafe to retry.
func orderOutcomeUnknown(resp *gigahost.OrderResponse) bool {
	return resp == nil || resp.Status == gigahost.StatusUnknown || resp.OrderID == ""
}

// beginPurchaseWithIntent is the atomic duplicate-decision-plus-intent step.
//
// Invariant: for one logical purchase, the "no unresolved prior order" decision and
// the durable intent row that makes that decision visible to later checks are ONE
// critical section, and the provider purchase cannot begin until that row is
// committed. Splitting them is a real duplicate-purchase defect: a second request
// that takes the lock in the gap sees an empty ledger and purchases too (observed
// in CI run 42576536602 as two provider order calls for five identical requests).
//
// The lock is released before the caller dispatches the purchase. Holding it across
// the provider call would also be correct for duplicate safety, but it would
// serialize every Gigahost purchase in the process (including genuinely different
// plans and regions) and put network I/O under a mutex. The returned unlock is
// idempotent so the caller can call it once, unconditionally, after dispatch.
//
// gated=false means the request was already answered (a refusal was written) and
// the caller must return without purchasing.
func (h *Handlers) beginPurchaseWithIntent(
	ctx context.Context,
	w http.ResponseWriter,
	client gigahost.Client,
	req OrderServerPayload,
	catalogPlans []gigahost.HourlyPlan,
	releaseOnAbort func(string),
) (orderRecord *GigahostOrderRecord, unlock func(), gated bool) {
	h.purchaseMu.Lock()
	locked := true
	unlock = func() {
		if locked {
			locked = false
			h.purchaseMu.Unlock()
		}
	}

	unresolved, reconcileErr := h.reconcilePendingUnknownOrders(ctx, client, req)
	if reconcileErr != nil {
		unlock()
		releaseOnAbort(failureProviderError)
		h.JSONError(w, http.StatusServiceUnavailable, "reconciliation_failed", reconcileErr.Error())
		return nil, nil, false
	}
	if unresolved != nil {
		unlock()
		releaseOnAbort("")
		h.respondUnresolvedDuplicate(w, unresolved)
		return nil, nil, false
	}

	// The intent is written INSIDE the lock, so the duplicate decision above becomes
	// visible to the next attempt the moment the lock is released.
	record, ok := h.persistOrderIntent(ctx, req, catalogPlans)
	if !ok {
		unlock()
		releaseOnAbort(failureProviderError)
		h.JSONError(w, http.StatusInternalServerError, "db_error",
			"Failed to persist the order intent; no purchase was attempted")
		return nil, nil, false
	}
	return record, unlock, true
}

// persistOrderIntent writes the durable pre-purchase intent row.
//
// It reports ok=false only when the intent could not be written, in which case no
// purchase may be attempted. The intent is written before the provider call on
// purpose: the provider does not return the catalog price id on any later read, so
// an intent that lost the price identity could not be reconciled back to the
// catalog row that was ordered.
func (h *Handlers) persistOrderIntent(
	ctx context.Context, req OrderServerPayload, catalogPlans []gigahost.HourlyPlan,
) (*GigahostOrderRecord, bool) {
	now := time.Now().UTC()
	priceIdentity := resolveOrderPriceIdentity(catalogPlans, req)
	record := &GigahostOrderRecord{
		OrderID:        fmt.Sprintf("intent_%d", now.UnixNano()),
		Status:         "pending_order",
		PlanID:         req.PID,
		RegionID:       req.RegionID,
		HourlyPriceNOK: priceIdentity.hourlyNOK,
		PriceID:        priceIdentity.priceID,
		MonthlyCapNOK:  priceIdentity.monthlyCapNOK,
		Currency:       priceIdentity.currency,
		// This is the one writer that may claim the row as a panel purchase, because
		// it is the writer that commits before the provider is asked to sell
		// anything. Stamping it here and nowhere else is what lets the setup pipeline
		// tell a row this panel bought from one that appeared some other way,
		// whatever plan or credential that row happens to carry.
		PurchaseOrigin:     models.PurchaseOriginPanelPurchase,
		PurchaseRecordedAt: now,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := h.saveGigahostOrder(ctx, record); err != nil {
		return nil, false
	}
	return record, true
}

// dispatchOrderPurchase sends the one authorized hourly order and records the
// provider answer.
func (h *Handlers) dispatchOrderPurchase(
	ctx context.Context, client gigahost.Client, req OrderServerPayload, orderRecord *GigahostOrderRecord,
) (*gigahost.OrderResponse, error) {
	// The managed SSH key is registered and proven before the order is sent, and the
	// failure is reported as a refusal, so a credential problem costs zero purchases.
	sshKeyIDs, credErr := h.prepareOrderSSHCredential(ctx, client, orderRecord)
	if credErr != nil {
		record, _, refusalErr, _ := h.refuseBeforePurchase(ctx, orderRecord, credErr)
		_ = record
		return nil, refusalErr
	}

	orderResp, orderErr := client.OrderServerSafe(ctx, gigahost.OrderRequest{
		PID:           req.PID,
		PriceID:       req.PriceID,
		RegionID:      req.RegionID,
		OSID:          req.OSID,
		BillingPeriod: gigahost.BillingPeriodHourly,
		Quantity:      1,
		SSHKeys:       []int64{sshKeyIDs},
	})

	// The record update must survive client cancellation: the purchase already
	// happened, and an unrecorded purchase is the duplicate hazard.
	updateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	applyOrderResponseToRecord(orderRecord, orderResp, orderErr)
	_ = h.updateGigahostOrder(updateCtx, orderRecord)
	return orderResp, orderErr
}

// orderRequestAndClient decodes and validates the order payload and resolves the
// provider client. It reports ok=false after writing the refusal, so the caller
// returns without repeating the error mapping.
func (h *Handlers) orderRequestAndClient(w http.ResponseWriter, r *http.Request) (OrderServerPayload, gigahost.Client, bool) {
	var req OrderServerPayload
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return req, nil, false
	}
	if err := req.validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "invalid_params", err.Error())
		return req, nil, false
	}
	client, err := h.getGigahostClient(r.Context(), r)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "unconfigured", err.Error())
		return req, nil, false
	}
	return req, client, true
}

// catalogPlanFor returns the catalog row the request selected, or nil when the
// provider catalog does not carry that product/price pair.
func catalogPlanFor(catalog []gigahost.HourlyPlan, req OrderServerPayload) *gigahost.HourlyPlan {
	for i := range catalog {
		if catalog[i].ProductID == req.PID && (req.PriceID == 0 || catalog[i].PriceID == req.PriceID) {
			return &catalog[i]
		}
	}
	return nil
}

//nolint:misspell // "cancelled" matches documented provider status and test assertions
const statusCancelled = "cancelled"

func validateOrderAgainstCatalog(catalog []gigahost.HourlyPlan, req OrderServerPayload) error {
	if len(catalog) == 0 {
		return fmt.Errorf("invalid_plan: no available plans in catalog")
	}
	matchedPlan := catalogPlanFor(catalog, req)
	if matchedPlan == nil {
		return fmt.Errorf("invalid_plan: plan %d (price %d) not found in provider catalog", req.PID, req.PriceID)
	}
	if !matchedPlan.HasStock() {
		return fmt.Errorf("invalid_plan: plan %d is out of stock", req.PID)
	}

	// A plan the provider prices at zero would be ordered without an
	// authoritative rate, so ordering stays refused. This is a price-integrity
	// check on the provider catalog entry, not a spending ceiling: nothing
	// compares the plan against a configured amount any more. It is evaluated on
	// the plan alone, before the selection checks, so the operator is told the
	// real reason a plan cannot be ordered at all.
	if matchedPlan.MonthlyCeiling <= 0 && matchedPlan.HourlyRateNOK <= 0 {
		return fmt.Errorf("invalid_plan: plan %d has zero or negative price in provider catalog", req.PID)
	}

	if err := validatePlanRegion(matchedPlan, req); err != nil {
		return err
	}
	if err := validatePlanOS(matchedPlan, req); err != nil {
		return err
	}
	return nil
}

// validatePlanRegion requires the selected region to be one the plan documents
// and to have capacity right now. A region the catalog reported without a stock
// fact is accepted (the provider documents dc_stock as optional), but a region
// the provider marked sold out is refused here rather than by a failed purchase.
func validatePlanRegion(plan *gigahost.HourlyPlan, req OrderServerPayload) error {
	if len(plan.Regions) == 0 {
		return fmt.Errorf("invalid_plan: plan %d has no available regions in catalog", req.PID)
	}
	for _, r := range plan.Regions {
		if r.ID != req.RegionID {
			continue
		}
		if !r.Sellable() {
			return fmt.Errorf("invalid_plan: region %d is not available for plan %d", req.RegionID, req.PID)
		}
		return nil
	}
	return fmt.Errorf("invalid_plan: region %d is not available for plan %d", req.RegionID, req.PID)
}

// validatePlanOS requires the selected image to be one the provider catalog
// actually returned for this plan. A stale or tampered os_id therefore fails
// before any purchase request is built, instead of ordering an image the
// provider would reject — or silently swapping in a different one.
func validatePlanOS(plan *gigahost.HourlyPlan, req OrderServerPayload) error {
	if len(plan.OSOptions) == 0 {
		return fmt.Errorf("invalid_plan: plan %d has no installable operating systems in provider catalog", req.PID)
	}
	for _, image := range plan.OSOptions {
		if image.OSID == req.OSID {
			return nil
		}
	}
	return fmt.Errorf("invalid_plan: operating system %d is not available for plan %d", req.OSID, req.PID)
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
