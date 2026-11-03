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

	// 2. Reconcile unknown purchase state before allowing retry (fail closed on error)
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

func (h *Handlers) reconcilePendingUnknownOrders(ctx context.Context, client gigahost.Client, req OrderServerPayload) (*GigahostOrderRecord, error) {
	existingOrders, _ := h.getGigahostOrders(ctx)
	for i := range existingOrders {
		if existingOrders[i].Status != gigahost.StatusUnknown && existingOrders[i].Status != "pending_order" {
			continue
		}
		servers, checkErr := client.GetServers(ctx)
		if checkErr != nil {
			return nil, fmt.Errorf("cannot verify provider inventory while order %s is unresolved: %w", existingOrders[i].OrderID, checkErr)
		}
		matched := false
		for _, s := range servers {
			if (s.OrderID != "" && s.OrderID == existingOrders[i].OrderID) ||
				(s.PID == existingOrders[i].PlanID && s.RegionID == existingOrders[i].RegionID && (s.Status == gigahost.StatusReady || s.Status == "active")) {
				if s.OrderID != "" {
					existingOrders[i].OrderID = s.OrderID
				}
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
		if !matched && existingOrders[i].PlanID == req.PID && existingOrders[i].RegionID == req.RegionID {
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
	case s == gigahost.StatusReady || s == gigahost.StatusFailed || s == "active" || s == "deleted":
		return true
	case strings.HasPrefix(s, "cancel"):
		return true
	default:
		return false
	}
}

func (h *Handlers) refreshSingleOrder(ctx context.Context, client gigahost.Client, order *GigahostOrderRecord) bool {
	if isTerminalStatus(order.Status) {
		return false
	}
	if !strings.HasPrefix(order.OrderID, "unknown_") && !strings.HasPrefix(order.OrderID, "intent_") {
		statusResp, err := client.GetDeployStatus(ctx, order.OrderID)
		if err == nil && statusResp != nil {
			updated := false
			if statusResp.Status != "" && statusResp.Status != order.Status {
				order.Status = statusResp.Status
				updated = true
			}
			if ip := statusResp.GetIP(); ip != "" && ip != order.AssignedIP {
				order.AssignedIP = ip
				updated = true
			}
			if statusResp.ServerID > 0 && order.ServerID == 0 {
				order.ServerID = statusResp.ServerID
				updated = true
			}
			return updated
		}
		return false
	}

	servers, err := client.GetServers(ctx)
	if err == nil {
		for _, s := range servers {
			if (s.OrderID != "" && s.OrderID == order.OrderID) ||
				(s.PID == order.PlanID && s.RegionID == order.RegionID && (s.Status == gigahost.StatusReady || s.Status == "active")) {
				if s.OrderID != "" {
					order.OrderID = s.OrderID
				}
				if s.ID > 0 {
					order.ServerID = s.ID
				}
				if s.Status != "" {
					order.Status = s.Status
				}
				if ip := s.GetIP(); ip != "" {
					order.AssignedIP = ip
				}
				return true
			}
		}
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
		for i := range orders {
			if h.refreshSingleOrder(r.Context(), client, &orders[i]) {
				_ = h.updateGigahostOrder(r.Context(), &orders[i])
			}
		}
	}

	h.JSONOK(w, map[string]any{
		"orders": orders,
		"count":  len(orders),
	})
}
