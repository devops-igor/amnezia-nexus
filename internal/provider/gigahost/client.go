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
	baseURL         string
	apiKey          string
	httpClient      *http.Client
	mu              sync.Mutex
	unknownOrders   map[string]time.Time
	lastEligibility CatalogEligibility
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

	products, elig, err := parseProducts(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode catalog products: %w", err)
	}
	c.mu.Lock()
	c.lastEligibility = elig
	c.mu.Unlock()
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
					Eligibility:    p.Eligibility,
				}
				hourlyPlans = append(hourlyPlans, plan)
			}
		}
	}

	return hourlyPlans, nil
}

// GetCatalogEligibility returns the most recently decoded catalog eligibility.
func (c *client) GetCatalogEligibility() CatalogEligibility {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastEligibility
}

// GetCatalogResponse returns catalog plans and account eligibility.
func (c *client) GetCatalogResponse(ctx context.Context) (*CatalogResponse, error) {
	plans, err := c.GetCatalog(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	elig := c.lastEligibility
	c.mu.Unlock()
	if !elig.QualifiesArrears && elig.CreditNOK == 0 && len(plans) > 0 {
		elig = plans[0].Eligibility
	}
	return &CatalogResponse{
		Plans:       plans,
		Eligibility: elig,
	}, nil
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
		return nil, &OrderUncertainError{
			StatusCode: http.StatusOK,
			Message:    fmt.Sprintf("provider accepted request but returned no order id: %v", err),
			Err:        err,
		}
	}

	if resp.OrderID == "" {
		return nil, &OrderUncertainError{
			StatusCode: http.StatusOK,
			Message:    "provider accepted request but returned no order id",
		}
	}

	if resp.Status == "" {
		resp.Status = StatusPending
	}
	return &resp, nil
}

// OrderUncertainError represents an order outcome where provider execution is uncertain
// (e.g. 5xx, timeouts, connection errors, or malformed JSON responses on 200/201).
type OrderUncertainError struct {
	StatusCode int    `json:"status_code,omitempty"`
	Message    string `json:"message"`
	Err        error  `json:"-"`
}

func (e *OrderUncertainError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("order status uncertain (status %d): %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("order status uncertain: %s", e.Message)
}

func (e *OrderUncertainError) Unwrap() error {
	return e.Err
}

func isUncertainOrderError(err error) bool {
	if err == nil {
		return false
	}
	var uncertainErr *OrderUncertainError
	if errors.As(err, &uncertainErr) {
		return true
	}
	var partialErr *OrderPartialError
	if errors.As(err, &partialErr) {
		return false
	}
	if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrRateLimited) ||
		errors.Is(err, ErrInvalidBillingPeriod) || errors.Is(err, ErrInvalidQuantity) || errors.Is(err, ErrInvalidOrderParam) {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return false
		}
		if apiErr.StatusCode >= 500 {
			return true
		}
	}
	if isTimeoutOrNetworkError(err) {
		return true
	}
	if strings.Contains(strings.ToLower(err.Error()), "failed to unmarshal order response") {
		return true
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return true
	}
	var unmarshalErr *json.UnmarshalTypeError
	if errors.As(err, &unmarshalErr) {
		return true
	}
	return false
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
		uncertainErr := &OrderUncertainError{
			Message: "prior order status is still unknown; refusing duplicate order until resolved",
		}
		return &OrderResponse{
			Status:  StatusUnknown,
			Message: uncertainErr.Message,
		}, uncertainErr
	}

	// 2. Dispatch order
	resp, orderErr := c.OrderServer(ctx, req)
	if orderErr == nil {
		if resp == nil || resp.OrderID == "" {
			uncertainErr := &OrderUncertainError{
				Message: "provider accepted request but returned no order id",
			}
			c.mu.Lock()
			c.unknownOrders[reqKey] = time.Now()
			c.mu.Unlock()
			return &OrderResponse{
				Status:  StatusUnknown,
				Message: uncertainErr.Message,
			}, uncertainErr
		}
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

	// 3. Inspect if failure is timeout, 5xx, or malformed JSON (uncertain outcome)
	if isUncertainOrderError(orderErr) {
		c.mu.Lock()
		c.unknownOrders[reqKey] = time.Now()
		c.mu.Unlock()

		var statusCode int
		var apiErr *APIError
		if errors.As(orderErr, &apiErr) {
			statusCode = apiErr.StatusCode
		}
		uncertain := &OrderUncertainError{
			StatusCode: statusCode,
			Message:    orderErr.Error(),
			Err:        orderErr,
		}
		return &OrderResponse{
			Status:  StatusUnknown,
			Message: uncertain.Error(),
		}, uncertain
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

// GetServers queries active servers via GET /servers with pagination aggregation.
func (c *client) GetServers(ctx context.Context) ([]ServerInfo, error) {
	var rawData []byte
	if err := c.doRequest(ctx, http.MethodGet, "/servers?page=1", nil, &rawData); err != nil {
		return nil, fmt.Errorf("failed to list servers: %w", err)
	}

	servers, meta, err := parseServersPage(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse servers list: %w", err)
	}
	totalPages := meta.TotalPages
	if totalPages < 1 {
		totalPages = 1
	}
	hasExpectedTotal := meta.HasTotal
	expectedTotal := meta.Total
	if err := meta.Validate(1, totalPages, hasExpectedTotal, expectedTotal, len(servers), len(servers)); err != nil {
		return nil, err
	}
	allServers := append([]ServerInfo(nil), servers...)
	for page := 2; page <= totalPages; page++ {
		var pageData []byte
		if err := c.doRequest(ctx, http.MethodGet, fmt.Sprintf("/servers?page=%d", page), nil, &pageData); err != nil {
			return nil, fmt.Errorf("failed to list servers page %d: %w", page, err)
		}
		pageServers, pageMeta, err := parseServersPage(pageData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse servers page %d: %w", page, err)
		}
		if err := pageMeta.Validate(page, totalPages, hasExpectedTotal, expectedTotal, len(pageServers), len(allServers)); err != nil {
			return nil, err
		}
		if !hasExpectedTotal && pageMeta.HasTotal {
			hasExpectedTotal = true
			expectedTotal = pageMeta.Total
		}
		allServers = append(allServers, pageServers...)
	}
	if hasExpectedTotal && len(allServers) != expectedTotal {
		return nil, fmt.Errorf("incomplete inventory: expected %d servers from meta.total, got %d", expectedTotal, len(allServers))
	}
	return allServers, nil
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
	ProductID      int                `json:"product_id"`
	ProductName    string             `json:"product_name"`
	Type           string             `json:"type"`
	AllowHourly    bool               `json:"allow_hourly"`
	AllowRecurring bool               `json:"allow_recurring"`
	PriceID        int                `json:"price_id"`
	RateHourly     float64            `json:"rate_hourly"`
	RateMonthly    float64            `json:"rate_monthly"`
	RegionIDs      []any              `json:"region_ids"`
	InStock        bool               `json:"in_stock"`
	VMCores        string             `json:"vm_cores"`
	VMMemory       string             `json:"vm_memory"`
	VMStorage      string             `json:"vm_storage"`
	VMBW           string             `json:"vm_bw"`
	Eligibility    CatalogEligibility `json:"eligibility,omitempty"`
	Specs          struct {
		CPUCores int `json:"cpu_cores"`
		RAMGB    int `json:"ram_gb"`
		Disks    []struct {
			SizeGB int `json:"size_gb"`
		} `json:"disks"`
		BW float64 `json:"bw"`
	} `json:"specs"`
}

func buildTierProduct(p tierProductDTO, regionMap map[int]Region, currency string, eligibility CatalogEligibility) Product {
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

	if p.Eligibility.QualifiesArrears || p.Eligibility.CreditNOK > 0 {
		eligibility = p.Eligibility
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
		Eligibility: eligibility,
	}
}

func parseProducts(data []byte) ([]Product, CatalogEligibility, error) {
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
			Currency    string             `json:"currency"`
			Eligibility CatalogEligibility `json:"eligibility"`
		} `json:"data"`
		Eligibility CatalogEligibility `json:"eligibility"`
	}

	var doc docCatalog
	if err := json.Unmarshal(data, &doc); err == nil && len(doc.Data.Tiers) > 0 {
		currency := doc.Data.Currency
		if currency == "" {
			currency = "NOK"
		}
		eligibility := doc.Data.Eligibility
		if !eligibility.QualifiesArrears && eligibility.CreditNOK == 0 && (doc.Eligibility.QualifiesArrears || doc.Eligibility.CreditNOK > 0) {
			eligibility = doc.Eligibility
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
				products = append(products, buildTierProduct(p, regionMap, currency, eligibility))
			}
		}
		if len(products) > 0 {
			return products, eligibility, nil
		}
	}

	var direct []Product
	if err := json.Unmarshal(data, &direct); err == nil && direct != nil {
		return direct, CatalogEligibility{}, nil
	}

	var wrapped struct {
		Products    []Product          `json:"products"`
		Data        []Product          `json:"data"`
		Servers     []Product          `json:"servers"`
		Eligibility CatalogEligibility `json:"eligibility"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil {
		if wrapped.Products != nil {
			return wrapped.Products, wrapped.Eligibility, nil
		}
		if wrapped.Data != nil {
			return wrapped.Data, wrapped.Eligibility, nil
		}
		if wrapped.Servers != nil {
			return wrapped.Servers, wrapped.Eligibility, nil
		}
	}

	return nil, CatalogEligibility{}, errors.New("unable to parse products response format")
}

func parseServersPage(data []byte) ([]ServerInfo, PaginationMeta, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, PaginationMeta{}, errors.New("servers payload cannot be null")
	}

	var direct []ServerInfo
	if err := json.Unmarshal(data, &direct); err == nil {
		if direct == nil {
			return nil, PaginationMeta{}, errors.New("servers payload cannot be null")
		}
		return direct, PaginationMeta{Page: 1, TotalPages: 1, HasPage: true, HasTotalPages: true}, nil
	}

	var wrapped struct {
		Servers []ServerInfo   `json:"servers"`
		Data    []ServerInfo   `json:"data"`
		Meta    PaginationMeta `json:"meta"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return nil, PaginationMeta{}, fmt.Errorf("failed to parse servers response: %w", err)
	}

	// Normalize unpaginated responses
	if !wrapped.Meta.HasTotalPages {
		wrapped.Meta.TotalPages, wrapped.Meta.Page = 1, 1
	} else if !wrapped.Meta.HasPage {
		wrapped.Meta.Page = 1
	}

	if wrapped.Servers != nil {
		return wrapped.Servers, wrapped.Meta, nil
	} else if wrapped.Data != nil {
		return wrapped.Data, wrapped.Meta, nil
	}

	return nil, PaginationMeta{}, errors.New("unable to parse servers response format")
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
