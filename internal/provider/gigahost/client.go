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
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client defines the contract for communicating with Gigahost API v0.
type Client interface {
	GetCatalog(ctx context.Context) ([]HourlyPlan, error)
	GetProducts(ctx context.Context) ([]Product, error)
	GetOperatingSystems(ctx context.Context) ([]OperatingSystem, error)
	GetAccount(ctx context.Context) (*AccountInfo, error)
	ListSSHKeys(ctx context.Context) ([]SSHKeyInfo, error)
	RegisterSSHKey(ctx context.Context, name, publicKey string) error
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
	// OnCall, when set, receives one bounded timing record per provider call.
	// It is opt-in: a nil callback attaches no httptrace client, so the request
	// path is unchanged. Implementations must not block or panic.
	OnCall func(CallTiming)
}

// client implements Client using standard net/http.
type client struct {
	baseURL         string
	apiKey          string
	httpClient      *http.Client
	onCall          func(CallTiming)
	mu              sync.Mutex
	unknownOrders   map[string]time.Time
	lastEligibility CatalogEligibility
}

// Ensure client satisfies the Client interface.
var _ Client = (*client)(nil)

// NewClient initializes and validates a new Gigahost API client.
//
// A client built without an injected HTTPClient/Transport owns a transport of
// its own (see newOwnedTransport): the standard transport settings with
// connection reuse disabled. Nothing written here ever reaches
// http.DefaultTransport or a transport the caller supplied.
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
			transport = newOwnedTransport()
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
		onCall:        cfg.OnCall,
		unknownOrders: make(map[string]time.Time),
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

// orderBody is the documented POST /deploy/servers request body. Field order is
// kept identical to OrderRequest's, so a provider-chosen (region-only) order
// serializes to exactly the bytes it did before dc_id existed.
type orderBody struct {
	PID           int     `json:"pid"`
	PriceID       int     `json:"price_id"`
	RegionID      int     `json:"region_id,omitempty"`
	DCID          int     `json:"dc_id,omitempty"`
	OSID          int     `json:"os_id"`
	BillingPeriod string  `json:"billing_period"`
	Quantity      int     `json:"quantity"`
	SSHKeys       []int64 `json:"ssh_keys,omitempty"`
}

// wireBody renders the placement-specific request body. A pinned order never
// carries region_id: the provider takes the region from the datacenter, and
// sending a combination whose precedence the documentation does not define is
// avoided rather than guessed. An unpinned order never carries dc_id.
func (r OrderRequest) wireBody() orderBody {
	body := orderBody{
		PID:           r.PID,
		PriceID:       r.PriceID,
		RegionID:      r.RegionID,
		OSID:          r.OSID,
		BillingPeriod: r.BillingPeriod,
		Quantity:      r.Quantity,
		SSHKeys:       r.SSHKeys,
	}
	if r.DCID > 0 {
		body.DCID = r.DCID
		body.RegionID = 0
	}
	return body
}

// OrderServer dispatches an hourly VPS order via POST /deploy/servers.
//
// The body is built explicitly per placement mode, because the two documented
// shapes are different requests, not one request with an optional extra field:
//
//   - pinned (DCID > 0): dc_id is sent and region_id is omitted, per "region_id
//     is then taken from the datacenter and can be left out";
//   - provider-chosen (DCID == 0): region_id is sent and dc_id is omitted, which
//     is byte-identical to the body this client sent before dc_id existed.
func (c *client) OrderServer(ctx context.Context, req OrderRequest) (*OrderResponse, error) {
	if !strings.EqualFold(req.BillingPeriod, BillingPeriodHourly) {
		return nil, fmt.Errorf("%w: got %q", ErrInvalidBillingPeriod, req.BillingPeriod)
	}
	if req.Quantity != 1 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidQuantity, req.Quantity)
	}
	if req.PID <= 0 || req.PriceID <= 0 || req.OSID <= 0 || (req.RegionID <= 0 && req.DCID <= 0) {
		return nil, ErrInvalidOrderParam
	}

	var rawData []byte
	err := c.doRequest(ctx, http.MethodPost, "/deploy/servers", req.wireBody(), &rawData)
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
	seenIDs := make(map[int64]struct{}, len(servers))
	for _, s := range servers {
		if s.ID > 0 {
			if _, seen := seenIDs[s.ID]; seen {
				return nil, fmt.Errorf("inconsistent inventory: duplicate server id %d across pages", s.ID)
			}
			seenIDs[s.ID] = struct{}{}
		}
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
		for _, s := range pageServers {
			if s.ID > 0 {
				if _, seen := seenIDs[s.ID]; seen {
					return nil, fmt.Errorf("inconsistent inventory: duplicate server id %d across pages", s.ID)
				}
				seenIDs[s.ID] = struct{}{}
			}
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

	// Timing is opt-in: with no sink configured no recorder and no trace are
	// created, leaving this path byte-for-byte unchanged.
	var recorder *timingRecorder
	if c.onCall != nil {
		recorder = newTimingRecorder(method, path)
		ctx = httptrace.WithClientTrace(ctx, recorder.clientTrace())
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
		if recorder != nil {
			recorder.finish(ctx, c.onCall, 0, err)
		}
		return err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		if recorder != nil {
			recorder.finish(ctx, c.onCall, resp.StatusCode, err)
		}
		return fmt.Errorf("failed to read response body: %w", err)
	}
	if recorder != nil {
		recorder.finish(ctx, c.onCall, resp.StatusCode, nil)
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

func parseServersPage(data []byte) ([]ServerInfo, PaginationMeta, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, PaginationMeta{}, errors.New("servers payload cannot be null")
	}

	var direct []ServerInfo
	if err := json.Unmarshal(data, &direct); err == nil {
		if direct == nil {
			return nil, PaginationMeta{}, errors.New("servers payload cannot be null")
		}
		if len(direct) >= 100 {
			return nil, PaginationMeta{}, errors.New("invalid inventory response: direct array missing pagination metadata")
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

	var servers []ServerInfo
	if wrapped.Servers != nil {
		servers = wrapped.Servers
	} else if wrapped.Data != nil {
		servers = wrapped.Data
	} else {
		return nil, PaginationMeta{}, errors.New("unable to parse servers response format")
	}

	if !wrapped.Meta.HasPage || !wrapped.Meta.HasTotalPages || !wrapped.Meta.HasTotal {
		return nil, PaginationMeta{}, errors.New("invalid inventory response: wrapped response missing pagination metadata")
	}
	if wrapped.Meta.Page < 1 || wrapped.Meta.TotalPages < 1 || wrapped.Meta.Total < 0 {
		return nil, PaginationMeta{}, errors.New("invalid pagination metadata: page and total_pages must be >= 1")
	}

	return servers, wrapped.Meta, nil
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
