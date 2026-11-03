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
	"strings"
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
	baseURL    string
	apiKey     string
	httpClient *http.Client
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
		baseURL:    baseURL,
		apiKey:     cfg.APIKey,
		httpClient: httpClient,
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

	var wrapped struct {
		Order *OrderResponse `json:"order"`
		Data  *OrderResponse `json:"data"`
	}
	if wrapErr := json.Unmarshal(rawData, &wrapped); wrapErr == nil {
		if wrapped.Order != nil {
			return wrapped.Order, nil
		}
		if wrapped.Data != nil {
			return wrapped.Data, nil
		}
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
// If an order request times out or is severed by network partition, it checks GET /servers
// before returning to avoid accidental duplicate orders.
func (c *client) OrderServerSafe(ctx context.Context, req OrderRequest) (*OrderResponse, error) {
	// 1. Pre-order inspection: verify if matching server exists already
	existingServers, err := c.GetServers(ctx)
	if err == nil {
		for _, s := range existingServers {
			if s.PID == req.PID && s.RegionID == req.RegionID &&
				(s.Status == StatusPending || s.Status == StatusDeploying || s.Status == StatusReady || s.Status == "active") {
				return &OrderResponse{
					OrderID:  s.OrderID,
					ServerID: s.ID,
					Status:   s.Status,
					Message:  "existing matching server found, reusing without duplicate order",
				}, nil
			}
		}
	}

	// 2. Dispatch order
	resp, orderErr := c.OrderServer(ctx, req)
	if orderErr == nil {
		return resp, nil
	}

	// 3. Inspect if failure is timeout/network related
	if isTimeoutOrNetworkError(orderErr) {
		inspectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		servers, checkErr := c.GetServers(inspectCtx)
		if checkErr == nil {
			for _, s := range servers {
				if s.PID == req.PID && s.RegionID == req.RegionID {
					// Found server provisioned during or right after timeout
					return &OrderResponse{
						OrderID:  s.OrderID,
						ServerID: s.ID,
						Status:   s.Status,
						Message:  "server found after order timeout recovery",
					}, nil
				}
			}
		}

		// Server not confirmed, mark state as unknown to guard against blind retries
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

	path := fmt.Sprintf("/deploy/status?order_id=%s", url.QueryEscape(orderID))
	var rawData []byte
	err := c.doRequest(ctx, http.MethodGet, path, nil, &rawData)
	if err != nil {
		// Fallback to path parameter format if query returns 404
		if errors.Is(err, ErrNotFound) {
			path = fmt.Sprintf("/deploy/status/%s", url.PathEscape(orderID))
			err = c.doRequest(ctx, http.MethodGet, path, nil, &rawData)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to fetch deploy status: %w", err)
		}
	}

	var wrapped struct {
		Status *DeployStatusResponse `json:"status"`
		Data   *DeployStatusResponse `json:"data"`
	}
	if wrapErr := json.Unmarshal(rawData, &wrapped); wrapErr == nil {
		if wrapped.Status != nil {
			return wrapped.Status, nil
		}
		if wrapped.Data != nil {
			return wrapped.Data, nil
		}
	}

	var statusResp DeployStatusResponse
	if err := json.Unmarshal(rawData, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to decode deploy status: %w", err)
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
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    extractErrorMessage(respBytes),
			RawBody:    string(respBytes),
		}
	}
}

func parseProducts(data []byte) ([]Product, error) {
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
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset")
}
