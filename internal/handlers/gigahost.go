package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// GigahostOrderRecord models persistent deployment jobs in gigahost_orders.
type GigahostOrderRecord struct {
	ID             int64     `json:"id"`
	OrderID        string    `json:"order_id"`
	ServerID       int64     `json:"server_id"`
	Status         string    `json:"status"` // pending, deploying, ready, failed, unknown
	PlanID         int       `json:"plan_id"`
	RegionID       int       `json:"region_id"`
	HourlyPriceNOK float64   `json:"hourly_price_nok"`
	AssignedIP     string    `json:"assigned_ip"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

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
	h.gigahostClient = c
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

	return gigahost.NewClient(gigahost.Config{
		APIKey: apiKey,
	})
}

// ensureGigahostOrdersTable creates the gigahost_orders schema if missing.
func (h *Handlers) ensureGigahostOrdersTable(ctx context.Context) error {
	if h.db == nil || h.db.SQLDB() == nil {
		return nil
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS gigahost_orders (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			order_id TEXT NOT NULL,
			server_id INTEGER DEFAULT 0,
			status TEXT NOT NULL,
			plan_id INTEGER NOT NULL,
			region_id INTEGER NOT NULL,
			hourly_price_nok REAL NOT NULL DEFAULT 0.0,
			assigned_ip TEXT DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_gigahost_orders_order_id ON gigahost_orders(order_id)`,
		`CREATE INDEX IF NOT EXISTS idx_gigahost_orders_status ON gigahost_orders(status)`,
	}
	for _, q := range queries {
		if _, err := h.db.SQLDB().ExecContext(ctx, q); err != nil {
			return fmt.Errorf("failed to init gigahost_orders schema: %w", err)
		}
	}
	return nil
}

// saveGigahostOrder writes a new order record into the database.
func (h *Handlers) saveGigahostOrder(ctx context.Context, order *GigahostOrderRecord) error {
	if err := h.ensureGigahostOrdersTable(ctx); err != nil {
		return err
	}
	if h.db == nil || h.db.SQLDB() == nil {
		return nil
	}

	q := `INSERT INTO gigahost_orders (order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip, created_at, updated_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := h.db.SQLDB().ExecContext(ctx, q,
		order.OrderID,
		order.ServerID,
		order.Status,
		order.PlanID,
		order.RegionID,
		order.HourlyPriceNOK,
		order.AssignedIP,
		order.CreatedAt.Format(time.RFC3339),
		order.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("failed to insert gigahost order: %w", err)
	}
	id, err := res.LastInsertId()
	if err == nil {
		order.ID = id
	}
	return nil
}

// updateGigahostOrder updates order_id, server_id, status, and assigned_ip of an order.
func (h *Handlers) updateGigahostOrder(ctx context.Context, order *GigahostOrderRecord) error {
	if h.db == nil || h.db.SQLDB() == nil {
		return nil
	}

	order.UpdatedAt = time.Now().UTC()
	q := `UPDATE gigahost_orders
	      SET order_id = ?, server_id = ?, status = ?, assigned_ip = ?, updated_at = ?
	      WHERE id = ? OR (order_id = ? AND order_id != '')`
	_, err := h.db.SQLDB().ExecContext(ctx, q,
		order.OrderID,
		order.ServerID,
		order.Status,
		order.AssignedIP,
		order.UpdatedAt.Format(time.RFC3339),
		order.ID,
		order.OrderID,
	)
	return err
}

// getGigahostOrders retrieves all orders from the database ordered by creation date descending.
func (h *Handlers) getGigahostOrders(ctx context.Context) ([]GigahostOrderRecord, error) {
	if err := h.ensureGigahostOrdersTable(ctx); err != nil {
		return nil, err
	}
	if h.db == nil || h.db.SQLDB() == nil {
		return []GigahostOrderRecord{}, nil
	}

	q := `SELECT id, order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip, created_at, updated_at
	      FROM gigahost_orders
	      ORDER BY id DESC`
	rows, err := h.db.SQLDB().QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("failed to query gigahost orders: %w", err)
	}
	defer rows.Close()

	var list []GigahostOrderRecord
	for rows.Next() {
		var o GigahostOrderRecord
		var createdAtStr, updatedAtStr string
		var assignedIP sql.NullString
		if err := rows.Scan(
			&o.ID,
			&o.OrderID,
			&o.ServerID,
			&o.Status,
			&o.PlanID,
			&o.RegionID,
			&o.HourlyPriceNOK,
			&assignedIP,
			&createdAtStr,
			&updatedAtStr,
		); err != nil {
			return nil, err
		}
		if assignedIP.Valid {
			o.AssignedIP = assignedIP.String
		}
		o.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		o.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtStr)
		list = append(list, o)
	}
	return list, nil
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

	// 1. Account balance and credit pre-check
	account, err := client.GetAccount(r.Context())
	if err != nil {
		h.JSONError(w, http.StatusBadGateway, "account_check_failed", fmt.Sprintf("Failed to check account eligibility: %v", err))
		return
	}
	if !account.HasCredit() {
		h.JSONError(w, http.StatusPaymentRequired, "insufficient_credit", "Gigahost account has insufficient credit or zero balance")
		return
	}

	// 2. Concurrency serialization: lock around budget check, intent creation, and reservation
	h.budgetMu.Lock()
	defer h.budgetMu.Unlock()

	// Monthly NOK budget cap enforcement
	if err := h.checkMonthlyBudget(r.Context(), client, req); err != nil {
		if strings.HasPrefix(err.Error(), "Monthly budget cap exceeded") {
			h.JSONError(w, http.StatusBadRequest, "budget_exceeded", err.Error())
		} else if strings.HasPrefix(err.Error(), "invalid_plan:") {
			h.JSONError(w, http.StatusBadRequest, "invalid_plan", strings.TrimPrefix(err.Error(), "invalid_plan: "))
		} else {
			h.JSONError(w, http.StatusBadGateway, "catalog_check_failed", err.Error())
		}
		return
	}

	// 3. Reconcile unknown purchase state before allowing retry (fail closed on error)
	unresolved, reconcileErr := h.reconcilePendingUnknownOrders(r.Context(), client, req)
	if reconcileErr != nil {
		h.JSONError(w, http.StatusServiceUnavailable, "reconciliation_failed", reconcileErr.Error())
		return
	}
	if unresolved != nil {
		h.JSON(w, http.StatusAccepted, map[string]any{
			"status":  "unknown",
			"message": "Prior purchase order is pending reconciliation; refusing duplicate purchase until resolved",
			"order":   unresolved,
		})
		return
	}

	// 3. Pre-dispatch durable intent persistence; fail closed if DB cannot record intent
	now := time.Now().UTC()
	orderRecord := &GigahostOrderRecord{
		OrderID:        fmt.Sprintf("intent_%d", now.UnixNano()),
		Status:         "pending_order",
		PlanID:         req.PID,
		RegionID:       req.RegionID,
		HourlyPriceNOK: req.HourlyPriceNOK,
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
		if orderResp != nil && orderResp.Status == gigahost.StatusUnknown {
			h.JSON(w, http.StatusAccepted, map[string]any{
				"status":  "unknown",
				"message": "Order request encountered a timeout; marked unknown to prevent accidental duplicate purchases",
				"order":   orderRecord,
			})
			return
		}
		h.JSONError(w, http.StatusBadGateway, "order_failed", orderErr.Error())
		return
	}

	h.JSONOK(w, map[string]any{
		"order":   orderRecord,
		"message": orderResp.Message,
	})
}

func planMonthlySpend(catalog []gigahost.HourlyPlan, pid int, fallbackHourly float64) float64 {
	var rate float64
	for _, p := range catalog {
		if p.ProductID == pid {
			if p.MonthlyCeiling > 0 {
				rate = p.MonthlyCeiling
			} else if p.HourlyRateNOK > 0 {
				rate = p.HourlyRateNOK * 720
			}
			break
		}
	}
	if rate == 0 && fallbackHourly > 0 {
		rate = fallbackHourly * 720
	}
	return rate
}

func isServerActiveForBudget(status string) bool {
	switch strings.ToLower(status) {
	case gigahost.StatusReady, "active", gigahost.StatusDeploying, gigahost.StatusPending, gigahost.StatusWaiting, gigahost.StatusInstalling:
		return true
	default:
		return false
	}
}

func isOrderActiveForBudget(status string) bool {
	switch strings.ToLower(status) {
	case gigahost.StatusWaiting, gigahost.StatusDeploying, gigahost.StatusInstalling,
		gigahost.StatusUnknown, "pending_order", gigahost.StatusPending,
		gigahost.StatusReady, "active":
		return true
	default:
		return false
	}
}

func requestMonthlySpend(catalog []gigahost.HourlyPlan, req OrderServerPayload) float64 {
	for _, p := range catalog {
		if p.ProductID == req.PID && (req.PriceID == 0 || p.PriceID == req.PriceID) {
			if p.MonthlyCeiling > 0 {
				return p.MonthlyCeiling
			} else if p.HourlyRateNOK > 0 {
				return p.HourlyRateNOK * 720
			}
			break
		}
	}
	return 0
}

func calculateCommittedSpend(catalog []gigahost.HourlyPlan, servers []gigahost.ServerInfo, localOrders []GigahostOrderRecord) float64 {
	var committed float64
	accountedOrders := make(map[string]bool)
	for _, s := range servers {
		if isServerActiveForBudget(s.Status) {
			if s.OrderID != "" {
				accountedOrders[s.OrderID] = true
			}
			committed += planMonthlySpend(catalog, s.PID, 0)
		}
	}

	for _, o := range localOrders {
		if isOrderActiveForBudget(o.Status) {
			if o.OrderID != "" && accountedOrders[o.OrderID] {
				continue
			}
			if o.OrderID != "" {
				accountedOrders[o.OrderID] = true
			}
			committed += planMonthlySpend(catalog, o.PlanID, o.HourlyPriceNOK)
		}
	}
	return committed
}

//nolint:misspell // "cancelled" matches documented provider status and test assertions
const statusCancelled = "cancelled"

func (h *Handlers) reconcileAbsentReadyOrder(ctx context.Context, client gigahost.Client, order *GigahostOrderRecord) {
	statusResp, err := client.GetDeployStatus(ctx, order.OrderID)
	if err == nil {
		if statusResp == nil || statusResp.Status == "" || isTerminalStatus(statusResp.Status) {
			newStatus := statusCancelled
			if statusResp != nil && isTerminalStatus(statusResp.Status) {
				newStatus = statusResp.Status
			}
			order.Status = newStatus
			_ = h.updateGigahostOrder(ctx, order)
		}
	} else if errors.Is(err, gigahost.ErrNotFound) {
		order.Status = statusCancelled
		_ = h.updateGigahostOrder(ctx, order)
	}
}

func (h *Handlers) reconcileBudgetOrders(ctx context.Context, client gigahost.Client, servers []gigahost.ServerInfo, localOrders []GigahostOrderRecord) {
	for i := range localOrders {
		order := &localOrders[i]
		if order.OrderID == "" || strings.HasPrefix(order.OrderID, "unknown_") || strings.HasPrefix(order.OrderID, "intent_") {
			continue
		}

		var matchedServer *gigahost.ServerInfo
		for j := range servers {
			if servers[j].OrderID != "" && servers[j].OrderID == order.OrderID {
				matchedServer = &servers[j]
				break
			}
		}

		if matchedServer != nil {
			if isTerminalStatus(matchedServer.Status) && order.Status != matchedServer.Status {
				order.Status = matchedServer.Status
				_ = h.updateGigahostOrder(ctx, order)
			}
		} else if order.Status == gigahost.StatusReady || strings.ToLower(order.Status) == "active" {
			h.reconcileAbsentReadyOrder(ctx, client, order)
		}
	}
}

func (h *Handlers) checkMonthlyBudget(ctx context.Context, client gigahost.Client, req OrderServerPayload) error {
	if h.db == nil {
		return nil
	}
	var ghCfg struct {
		MonthlyBudgetNOK float64 `json:"monthly_budget_nok"`
	}
	_ = h.db.GetSetting(ctx, "gigahost", &ghCfg)
	if ghCfg.MonthlyBudgetNOK <= 0 {
		return nil
	}

	catalog, catErr := client.GetCatalog(ctx)
	if catErr != nil {
		return fmt.Errorf("failed to check catalog for budget verification: %w", catErr)
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
	if len(matchedPlan.Regions) > 0 {
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
	}

	planMonthlyRate := requestMonthlySpend(catalog, req)
	if planMonthlyRate <= 0 {
		return fmt.Errorf("invalid_plan: plan %d has zero or negative price in provider catalog", req.PID)
	}

	servers, srvErr := client.GetServers(ctx)
	if srvErr != nil {
		return fmt.Errorf("failed to check existing server inventory for budget verification: %w", srvErr)
	}

	localOrders, ordErr := h.getGigahostOrders(ctx)
	if ordErr != nil {
		return fmt.Errorf("failed to check local orders for budget verification: %w", ordErr)
	}

	h.reconcileBudgetOrders(ctx, client, servers, localOrders)

	committed := calculateCommittedSpend(catalog, servers, localOrders)

	if committed+planMonthlyRate > ghCfg.MonthlyBudgetNOK {
		return fmt.Errorf("Monthly budget cap exceeded: requested order exceeds configured budget of %v NOK", ghCfg.MonthlyBudgetNOK)
	}
	return nil
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

func (h *Handlers) reconcilePendingUnknownOrders(ctx context.Context, client gigahost.Client, req OrderServerPayload) (*GigahostOrderRecord, error) {
	existingOrders, _ := h.getGigahostOrders(ctx)
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
		matched := false
		for _, s := range servers {
			if s.OrderID != "" && s.OrderID == existingOrders[i].OrderID {
				if s.ID > 0 {
					existingOrders[i].ServerID = s.ID
				}
				if s.Status != "" {
					existingOrders[i].Status = s.Status
				}
				if ip := s.GetIP(); ip != "" {
					existingOrders[i].AssignedIP = ip
				}
				_ = h.updateGigahostOrder(ctx, &existingOrders[i])
				matched = true
				break
			}
		}
		if !matched && existingOrders[i].OrderID != "" && !strings.HasPrefix(existingOrders[i].OrderID, "intent_") && !strings.HasPrefix(existingOrders[i].OrderID, "unknown_") {
			statusResp, err := client.GetDeployStatus(ctx, existingOrders[i].OrderID)
			if err == nil && statusResp != nil && statusResp.Status != "" {
				existingOrders[i].Status = statusResp.Status
				if statusResp.ServerID > 0 {
					existingOrders[i].ServerID = statusResp.ServerID
				}
				if ip := statusResp.GetIP(); ip != "" {
					existingOrders[i].AssignedIP = ip
				}
				_ = h.updateGigahostOrder(ctx, &existingOrders[i])
			}
		}
		if !matched && isPendingOrInFlight(existingOrders[i].Status) && existingOrders[i].PlanID == req.PID && existingOrders[i].RegionID == req.RegionID {
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
	}
	var partialErr *gigahost.OrderPartialError
	if errors.As(orderErr, &partialErr) {
		if firstID := partialErr.FirstOrderID(); firstID != "" {
			orderRecord.OrderID = firstID
		}
		orderRecord.Status = gigahost.StatusWaiting
		return
	}
	if orderErr != nil {
		if orderResp != nil && orderResp.Status == gigahost.StatusUnknown {
			orderRecord.Status = gigahost.StatusUnknown
		} else if orderRecord.Status == "pending_order" {
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
			if s.Status != "" && s.Status != order.Status {
				order.Status = s.Status
				updated = true
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
			} else if deployQueries < maxDeployQueries && h.refreshOrderFromDeployStatus(r.Context(), client, &orders[i]) {
				deployQueries++
				updated = true
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
