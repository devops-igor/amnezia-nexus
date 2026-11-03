package gigahost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client defines the contract for communicating with Gigahost API v0.
type Client interface {
	GetCatalog(ctx context.Context) ([]HourlyPlan, error)
	GetProducts(ctx context.Context) ([]Product, error)
	GetAccount(ctx context.Context) (*AccountInfo, error)
	OrderServer(ctx context.Context, req OrderRequest) (*OrderResponse, error)
	OrderServerSafe(ctx context.Context, req OrderRequest) (*OrderResponse, error)
	GetDeployStatus(ctx context.Context, orderID string) (*DeployStatusResponse, error)
	GetServers(ctx context.Context) ([]ServerInfo, error)
}

// Config provides configuration settings for creating a Gigahost client.
type Config struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	Transport  http.RoundTripper
	Timeout    time.Duration
}

// client implements Client using standard net/http.
type client struct {
	baseURL       string
	apiKey        string
	httpClient    *http.Client
	mu            sync.Mutex
	unknownOrders map[string]time.Time
}

// Ensure client satisfies the Client interface.
var _ Client = (*client)(nil)

// NewClient initializes and validates a new Gigahost API client.
func NewClient(cfg Config) (Client, error) {
	if err := ValidateAPIKey(cfg.APIKey); err != nil {
		return nil, err
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		transport := cfg.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		httpClient = &http.Client{
			Timeout:   timeout,
			Transport: transport,
		}
	} else if cfg.Transport != nil {
		httpClient.Transport = cfg.Transport
	}

	return &client{
		baseURL:       baseURL,
		apiKey:        cfg.APIKey,
		httpClient:    httpClient,
		unknownOrders: make(map[string]time.Time),
	}, nil
}

// GetProducts queries the raw product catalog from GET /deploy/servers.
func (c *client) GetProducts(ctx context.Context) ([]Product, error) {
	var respData []byte
	err := c.doRequest(ctx, http.MethodGet, "/deploy/servers", nil, &respData)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch products: %w", err)
	}

	products, err := parseProducts(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode catalog products: %w", err)
	}
	return products, nil
}

// GetCatalog queries available products and filters those supporting hourly billing.
func (c *client) GetCatalog(ctx context.Context) ([]HourlyPlan, error) {
	products, err := c.GetProducts(ctx)
	if err != nil {
		return nil, err
	}

	var hourlyPlans []HourlyPlan
	for _, p := range products {
		for _, price := range p.Prices {
			if strings.EqualFold(price.BillingPeriod, BillingPeriodHourly) {
				rate := price.HourlyRate
				if rate <= 0 && price.Amount > 0 {
					rate = price.Amount
				}
				currency := price.Currency
				if currency == "" {
					currency = "NOK"
				}

				plan := HourlyPlan{
					ProductID:      p.GetID(),
					Name:           p.Name,
					Description:    p.Description,
					CPUCores:       p.CPUCores,
					RAMMB:          p.RAMMB,
					DiskGB:         p.DiskGB,
					BandwidthTB:    p.BandwidthTB,
					InStock:        p.InStock,
					PriceID:        price.ID,
					Currency:       currency,
					HourlyRateNOK:  rate,
					MonthlyCeiling: price.MonthlyCeiling,
					Regions:        p.Regions,
					OSList:         p.OSList,
				}
				hourlyPlans = append(hourlyPlans, plan)
			}
		}
	}

	return hourlyPlans, nil
}

// GetAccount queries account credit and balance via GET /account.
func (c *client) GetAccount(ctx context.Context) (*AccountInfo, error) {
	var rawData []byte
	err := c.doRequest(ctx, http.MethodGet, "/account", nil, &rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to get account info: %w", err)
	}

	type docAccount struct {
		Meta struct {
			Status int `json:"status"`
		} `json:"meta"`
		Data struct {
			CustID      string  `json:"cust_id"`
			CustName    string  `json:"cust_name"`
			CustEmail   string  `json:"cust_email"`
			ID          string  `json:"id"`
			Email       string  `json:"email"`
			Balance     float64 `json:"balance"`
			Credit      float64 `json:"credit"`
			Currency    string  `json:"currency"`
			Status      string  `json:"status"`
			Eligibility struct {
				QualifiesArrears bool    `json:"qualifies_arrears"`
				CreditNOK        float64 `json:"credit_nok"`
			} `json:"eligibility"`
		} `json:"data"`
	}
	var doc docAccount
	if err := json.Unmarshal(rawData, &doc); err == nil && (doc.Data.CustID != "" || doc.Data.ID != "" || doc.Data.CustName != "" || doc.Data.Eligibility.QualifiesArrears) {
		acc := &AccountInfo{
			ID:               doc.Data.ID,
			CustID:           doc.Data.CustID,
			CustName:         doc.Data.CustName,
			Email:            doc.Data.CustEmail,
			Balance:          doc.Data.Balance,
			Credit:           doc.Data.Credit,
			CreditNOK:        doc.Data.Eligibility.CreditNOK,
			QualifiesArrears: doc.Data.Eligibility.QualifiesArrears,
			Currency:         doc.Data.Currency,
			Status:           doc.Data.Status,
		}
		if acc.ID == "" {
			acc.ID = doc.Data.CustID
		}
		if acc.Email == "" {
			acc.Email = doc.Data.Email
		}
		return acc, nil
	}

	var wrapped struct {
		Account *AccountInfo `json:"account"`
		Data    *AccountInfo `json:"data"`
	}
	if wrapErr := json.Unmarshal(rawData, &wrapped); wrapErr == nil {
		if wrapped.Account != nil {
			return wrapped.Account, nil
		}
		if wrapped.Data != nil {
			return wrapped.Data, nil
		}
	}

	var acc AccountInfo
	if err := json.Unmarshal(rawData, &acc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal account response: %w", err)
	}
	return &acc, nil
}

// OrderServer dispatches an hourly VPS order via POST /deploy/servers.
func (c *client) OrderServer(ctx context.Context, req OrderRequest) (*OrderResponse, error) {
	if !strings.EqualFold(req.BillingPeriod, BillingPeriodHourly) {
		return nil, fmt.Errorf("%w: got %q", ErrInvalidBillingPeriod, req.BillingPeriod)
	}
	if req.Quantity != 1 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidQuantity, req.Quantity)
	}
	if req.PID <= 0 || req.PriceID <= 0 || req.RegionID <= 0 || req.OSID <= 0 {
		return nil, ErrInvalidOrderParam
	}

	var rawData []byte
	err := c.doRequest(ctx, http.MethodPost, "/deploy/servers", req, &rawData)
	if err != nil {
		return nil, err
	}

	var resp OrderResponse
	if err := json.Unmarshal(rawData, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal order response: %w", err)
	}

	if resp.Status == "" {
		resp.Status = StatusPending
	}
	return &resp, nil
}

// OrderServerSafe executes an order with timeout safety and idempotency inspection.
// If an order request times out or is severed by network partition, it marks the request
// as unknown and fails closed against retries until resolved.
func (c *client) OrderServerSafe(ctx context.Context, req OrderRequest) (*OrderResponse, error) {
	// 1. Pre-order inspection: verify existing provider inventory (FAIL CLOSED on error)
	if _, err := c.GetServers(ctx); err != nil {
		return nil, fmt.Errorf("failed to verify existing inventory: %w", err)
	}

	reqKey := fmt.Sprintf("%d:%d:%d:%d", req.PID, req.PriceID, req.RegionID, req.OSID)
	c.mu.Lock()
	_, hasUnknown := c.unknownOrders[reqKey]
	c.mu.Unlock()

	if hasUnknown {
		// Prior order status is still unknown; fail closed against retries until resolved
		return &OrderResponse{
			Status:  StatusUnknown,
			Message: "prior order status is still unknown; refusing duplicate order until resolved",
		}, fmt.Errorf("prior order status is still unknown (state unknown)")
	}

	// 2. Dispatch order
	resp, orderErr := c.OrderServer(ctx, req)
	if orderErr == nil {
		c.mu.Lock()
		delete(c.unknownOrders, reqKey)
		c.mu.Unlock()
		return resp, nil
	}

	var partialErr *OrderPartialError
	if errors.As(orderErr, &partialErr) {
		c.mu.Lock()
		delete(c.unknownOrders, reqKey)
		c.mu.Unlock()
		return nil, orderErr
	}

	// 3. Inspect if failure is timeout/network related
	if isTimeoutOrNetworkError(orderErr) {
		c.mu.Lock()
		c.unknownOrders[reqKey] = time.Now()
		c.mu.Unlock()

		// Server not confirmed; fail closed with unknown status to guard against duplicate purchases
		return &OrderResponse{
			Status:  StatusUnknown,
			Message: "order timed out; marked unknown to prevent duplicate order",
		}, fmt.Errorf("order timed out (state unknown): %w", orderErr)
	}

	return nil, orderErr
}

// GetDeployStatus polls deployment progress via GET /deploy/status.
func (c *client) GetDeployStatus(ctx context.Context, orderID string) (*DeployStatusResponse, error) {
	if orderID == "" {
		return nil, errors.New("order_id is required")
	}

	path := fmt.Sprintf("/deploy/status?ids=%s", url.QueryEscape(orderID))
	var rawData []byte
	err := c.doRequest(ctx, http.MethodGet, path, nil, &rawData)
	if err != nil && errors.Is(err, ErrNotFound) {
		path = fmt.Sprintf("/deploy/status?order_id=%s", url.QueryEscape(orderID))
		err = c.doRequest(ctx, http.MethodGet, path, nil, &rawData)
		if err != nil && errors.Is(err, ErrNotFound) {
			path = fmt.Sprintf("/deploy/status/%s", url.PathEscape(orderID))
			err = c.doRequest(ctx, http.MethodGet, path, nil, &rawData)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch deploy status: %w", err)
	}

	var statusResp DeployStatusResponse
	if err := json.Unmarshal(rawData, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to decode deploy status: %w", err)
	}
	if statusResp.OrderID == "" {
		statusResp.OrderID = orderID
	}
	return &statusResp, nil
}

// GetServers queries active servers via GET /servers.
func (c *client) GetServers(ctx context.Context) ([]ServerInfo, error) {
	var rawData []byte
	err := c.doRequest(ctx, http.MethodGet, "/servers", nil, &rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to list servers: %w", err)
	}

	servers, err := parseServers(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse servers list: %w", err)
	}
	return servers, nil
}

// doRequest performs an HTTP request, injects Authorization and Content-Type headers,
// and decodes or returns the response body.
func (c *client) doRequest(ctx context.Context, method, path string, body any, target any) error {
	fullURL := c.baseURL + path
	var bodyReader io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if target != nil {
			if rawTarget, ok := target.(*[]byte); ok {
				*rawTarget = respBytes
				return nil
			}
			if err := json.Unmarshal(respBytes, target); err != nil {
				return fmt.Errorf("failed to decode response payload: %w", err)
			}
		}
		return nil

	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w (status %d): %s", ErrUnauthorized, resp.StatusCode, extractErrorMessage(respBytes))

	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %s", ErrRateLimited, extractErrorMessage(respBytes))

	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, extractErrorMessage(respBytes))

	default:
		if partialErr := parsePartialOrderError(resp.StatusCode, respBytes); partialErr != nil {
			return partialErr
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    extractErrorMessage(respBytes),
			RawBody:    string(respBytes),
		}
	}
}

type tierProductDTO struct {
	ProductID      int     `json:"product_id"`
	ProductName    string  `json:"product_name"`
	Type           string  `json:"type"`
	AllowHourly    bool    `json:"allow_hourly"`
	AllowRecurring bool    `json:"allow_recurring"`
	PriceID        int     `json:"price_id"`
	RateHourly     float64 `json:"rate_hourly"`
	RateMonthly    float64 `json:"rate_monthly"`
	RegionIDs      []any   `json:"region_ids"`
	InStock        bool    `json:"in_stock"`
	VMCores        string  `json:"vm_cores"`
	VMMemory       string  `json:"vm_memory"`
	VMStorage      string  `json:"vm_storage"`
	VMBW           string  `json:"vm_bw"`
	Specs          struct {
		CPUCores int `json:"cpu_cores"`
		RAMGB    int `json:"ram_gb"`
		Disks    []struct {
			SizeGB int `json:"size_gb"`
		} `json:"disks"`
		BW float64 `json:"bw"`
	} `json:"specs"`
}

func buildTierProduct(p tierProductDTO, regionMap map[int]Region, currency string) Product {
	cores := p.Specs.CPUCores
	if cores <= 0 && p.VMCores != "" {
		cores, _ = strconv.Atoi(p.VMCores)
	}
	ram := p.Specs.RAMGB * 1024
	if ram <= 0 && p.VMMemory != "" {
		v, _ := strconv.Atoi(p.VMMemory)
		ram = v * 1024
	}
	disk := 0
	for _, d := range p.Specs.Disks {
		disk += d.SizeGB
	}
	if disk <= 0 && p.VMStorage != "" {
		disk, _ = strconv.Atoi(p.VMStorage)
	}
	bw := p.Specs.BW
	if bw <= 0 && p.VMBW != "" {
		bw, _ = strconv.ParseFloat(p.VMBW, 64)
	}

	var regions []Region
	for _, ridAny := range p.RegionIDs {
		rid := int(parseInt64Field(ridAny))
		if reg, ok := regionMap[rid]; ok {
			regions = append(regions, reg)
		} else {
			regions = append(regions, Region{ID: rid, Available: true})
		}
	}

	var prices []Price
	if p.AllowHourly && p.PriceID > 0 && p.InStock {
		prices = append(prices, Price{
			ID:             p.PriceID,
			BillingPeriod:  BillingPeriodHourly,
			Currency:       currency,
			HourlyRate:     p.RateHourly,
			MonthlyCeiling: p.RateMonthly,
		})
	}

	return Product{
		ID:          p.ProductID,
		PID:         p.ProductID,
		Name:        p.ProductName,
		CPUCores:    cores,
		RAMMB:       ram,
		DiskGB:      disk,
		BandwidthTB: bw,
		InStock:     p.InStock,
		Prices:      prices,
		Regions:     regions,
	}
}

func parseProducts(data []byte) ([]Product, error) {
	type docCatalog struct {
		Meta struct {
			Status int `json:"status"`
		} `json:"meta"`
		Data struct {
			Tiers []struct {
				GroupID   int              `json:"group_id"`
				GroupName string           `json:"group_name"`
				InStock   bool             `json:"in_stock"`
				Products  []tierProductDTO `json:"products"`
			} `json:"tiers"`
			Regions []struct {
				RegionID   any    `json:"region_id"`
				RegionName string `json:"region_name"`
				Country    string `json:"region_country"`
			} `json:"regions"`
			Currency string `json:"currency"`
		} `json:"data"`
	}

	var doc docCatalog
	if err := json.Unmarshal(data, &doc); err == nil && len(doc.Data.Tiers) > 0 {
		currency := doc.Data.Currency
		if currency == "" {
			currency = "NOK"
		}
		regionMap := make(map[int]Region)
		for _, r := range doc.Data.Regions {
			rID := int(parseInt64Field(r.RegionID))
			regionMap[rID] = Region{
				ID:        rID,
				Name:      r.RegionName,
				Country:   r.Country,
				Available: true,
			}
		}

		var products []Product
		for _, tier := range doc.Data.Tiers {
			for _, p := range tier.Products {
				products = append(products, buildTierProduct(p, regionMap, currency))
			}
		}
		if len(products) > 0 {
			return products, nil
		}
	}

	var direct []Product
	if err := json.Unmarshal(data, &direct); err == nil && len(direct) >= 0 {
		return direct, nil
	}

	var wrapped struct {
		Products []Product `json:"products"`
		Data     []Product `json:"data"`
		Servers  []Product `json:"servers"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil {
		if wrapped.Products != nil {
			return wrapped.Products, nil
		}
		if wrapped.Data != nil {
			return wrapped.Data, nil
		}
		if wrapped.Servers != nil {
			return wrapped.Servers, nil
		}
	}

	return nil, errors.New("unable to parse products response format")
}

func parseServers(data []byte) ([]ServerInfo, error) {
	var direct []ServerInfo
	if err := json.Unmarshal(data, &direct); err == nil && len(direct) >= 0 {
		return direct, nil
	}

	var wrapped struct {
		Servers []ServerInfo `json:"servers"`
		Data    []ServerInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil {
		if wrapped.Servers != nil {
			return wrapped.Servers, nil
		}
		if wrapped.Data != nil {
			return wrapped.Data, nil
		}
	}

	return nil, errors.New("unable to parse servers response format")
}

func extractErrorMessage(data []byte) string {
	if len(data) == 0 {
		return "empty response"
	}
	var errResp struct {
		Message string `json:"message"`
		Error   string `json:"error"`
		Detail  string `json:"detail"`
	}
	if err := json.Unmarshal(data, &errResp); err == nil {
		if errResp.Message != "" {
			return errResp.Message
		}
		if errResp.Error != "" {
			return errResp.Error
		}
		if errResp.Detail != "" {
			return errResp.Detail
		}
	}
	return strings.TrimSpace(string(data))
}

func isTimeoutOrNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "eof")
}

func parsePartialOrderError(statusCode int, data []byte) *OrderPartialError {
	if len(data) == 0 {
		return nil
	}
	type rawOrderEnvelope struct {
		OrderIDs []any `json:"order_ids"`
		OrderID  any   `json:"order_id"`
		Orders   []struct {
			OrderID any `json:"order_id"`
		} `json:"orders"`
		Data struct {
			OrderIDs []any `json:"order_ids"`
			OrderID  any   `json:"order_id"`
			Orders   []struct {
				OrderID any `json:"order_id"`
			} `json:"orders"`
		} `json:"data"`
	}
	var env rawOrderEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil
	}

	var parsedIDs []int64
	addID := func(v any) {
		id := parseInt64Field(v)
		if id > 0 {
			for _, existing := range parsedIDs {
				if existing == id {
					return
				}
			}
			parsedIDs = append(parsedIDs, id)
		}
	}

	for _, id := range env.OrderIDs {
		addID(id)
	}
	if env.OrderID != nil {
		addID(env.OrderID)
	}
	for _, o := range env.Orders {
		addID(o.OrderID)
	}
	for _, id := range env.Data.OrderIDs {
		addID(id)
	}
	if env.Data.OrderID != nil {
		addID(env.Data.OrderID)
	}
	for _, o := range env.Data.Orders {
		addID(o.OrderID)
	}

	if len(parsedIDs) == 0 {
		return nil
	}

	msg := extractErrorMessage(data)
	if msg == "" || msg == string(data) {
		msg = fmt.Sprintf("order pending payment/approval (status %d)", statusCode)
	}

	return &OrderPartialError{
		StatusCode: statusCode,
		Message:    msg,
		OrderIDs:   parsedIDs,
		RawBody:    string(data),
	}
}
