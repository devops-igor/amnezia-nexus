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

// updateGigahostOrder updates status, server_id, and assigned_ip of an order.
func (h *Handlers) updateGigahostOrder(ctx context.Context, order *GigahostOrderRecord) error {
	if h.db == nil || h.db.SQLDB() == nil {
		return nil
	}

	order.UpdatedAt = time.Now().UTC()
	q := `UPDATE gigahost_orders
	      SET server_id = ?, status = ?, assigned_ip = ?, updated_at = ?
	      WHERE id = ? OR (order_id = ? AND order_id != '')`
	_, err := h.db.SQLDB().ExecContext(ctx, q,
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

	// 2. Safe order dispatch with hourly billing enforcement
	orderReq := gigahost.OrderRequest{
		PID:           req.PID,
		PriceID:       req.PriceID,
		RegionID:      req.RegionID,
		OSID:          req.OSID,
		BillingPeriod: gigahost.BillingPeriodHourly,
		Quantity:      1,
	}

	orderResp, orderErr := client.OrderServerSafe(r.Context(), orderReq)

	now := time.Now().UTC()
	orderRecord := &GigahostOrderRecord{
		PlanID:         req.PID,
		RegionID:       req.RegionID,
		HourlyPriceNOK: req.HourlyPriceNOK,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if orderResp != nil {
		orderRecord.OrderID = orderResp.OrderID
		orderRecord.ServerID = orderResp.ServerID
		orderRecord.Status = orderResp.Status
	}

	if orderRecord.OrderID == "" {
		orderRecord.OrderID = fmt.Sprintf("unknown_%d", now.UnixNano())
	}
	if orderRecord.Status == "" {
		orderRecord.Status = gigahost.StatusUnknown
	}

	_ = h.saveGigahostOrder(r.Context(), orderRecord)

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

	// Try to refresh non-final orders if client is accessible
	client, clientErr := h.getGigahostClient(r.Context(), r)
	if clientErr == nil && len(orders) > 0 {
		for i := range orders {
			if orders[i].Status == gigahost.StatusPending || orders[i].Status == gigahost.StatusDeploying || orders[i].Status == gigahost.StatusUnknown {
				if !strings.HasPrefix(orders[i].OrderID, "unknown_") {
					statusResp, err := client.GetDeployStatus(r.Context(), orders[i].OrderID)
					if err == nil && statusResp != nil {
						updated := false
						if statusResp.Status != "" && statusResp.Status != orders[i].Status {
							orders[i].Status = statusResp.Status
							updated = true
						}
						if ip := statusResp.GetIP(); ip != "" && ip != orders[i].AssignedIP {
							orders[i].AssignedIP = ip
							updated = true
						}
						if statusResp.ServerID > 0 && orders[i].ServerID == 0 {
							orders[i].ServerID = statusResp.ServerID
							updated = true
						}
						if updated {
							_ = h.updateGigahostOrder(r.Context(), &orders[i])
						}
					}
				}
			}
		}
	}

	h.JSONOK(w, map[string]any{
		"orders": orders,
		"count":  len(orders),
	})
}
