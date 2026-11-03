package gigahost

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Standard constants for Gigahost API.
const (
	DefaultBaseURL = "https://api.gigahost.no/api/v0"

	BillingPeriodHourly  = "hourly"
	BillingPeriodMonthly = "monthly"

	StatusPending   = "pending"
	StatusDeploying = "deploying"
	StatusReady     = "ready"
	StatusFailed    = "failed"
	StatusUnknown   = "unknown"
)

// Sentinel errors for provider validation and API responses.
var (
	ErrInvalidAPIKey        = errors.New("invalid gigahost api key: must be flux_live_<64-hex-chars>")
	ErrInsufficientCredit   = errors.New("insufficient account credit or balance")
	ErrInvalidBillingPeriod = errors.New("billing period must be hourly")
	ErrInvalidQuantity      = errors.New("quantity must be 1")
	ErrRateLimited          = errors.New("gigahost api rate limit exceeded (429)")
	ErrUnauthorized         = errors.New("gigahost api authentication failed (401/403)")
	ErrNotFound             = errors.New("gigahost resource not found (404)")
	ErrInvalidOrderParam    = errors.New("invalid order parameter: pid, price_id, region_id, os_id must be positive")
)

// APIError represents a structured error returned by the Gigahost API.
type APIError struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
	RawBody    string `json:"raw_body,omitempty"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gigahost api error (status %d): %s", e.StatusCode, e.Message)
}

// ValidateAPIKey ensures the key complies with the format: flux_live_<64-hex-chars>.
func ValidateAPIKey(key string) error {
	const prefix = "flux_live_"
	if !strings.HasPrefix(key, prefix) {
		return fmt.Errorf("%w: missing '%s' prefix", ErrInvalidAPIKey, prefix)
	}
	hexPart := strings.TrimPrefix(key, prefix)
	if len(hexPart) != 64 {
		return fmt.Errorf("%w: expected 64 hex characters, got %d", ErrInvalidAPIKey, len(hexPart))
	}
	for _, c := range hexPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("%w: non-hex character '%c'", ErrInvalidAPIKey, c)
		}
	}
	return nil
}

// Region represents a datacenter region.
type Region struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Country   string `json:"country,omitempty"`
	Available bool   `json:"available"`
}

// OS represents an available operating system image.
type OS struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Price represents billing details for a product.
type Price struct {
	ID             int     `json:"id"`
	BillingPeriod  string  `json:"billing_period"`
	Currency       string  `json:"currency"`
	HourlyRate     float64 `json:"hourly_rate"`
	MonthlyCeiling float64 `json:"monthly_ceiling"`
	Amount         float64 `json:"amount,omitempty"`
}

// Product represents a server product in the catalog.
type Product struct {
	ID          int      `json:"id"`
	PID         int      `json:"pid"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	CPUCores    int      `json:"cpu_cores"`
	RAMMB       int      `json:"ram_mb"`
	DiskGB      int      `json:"disk_gb"`
	BandwidthTB float64  `json:"bandwidth_tb,omitempty"`
	InStock     bool     `json:"in_stock"`
	Prices      []Price  `json:"prices,omitempty"`
	Regions     []Region `json:"regions,omitempty"`
	OSList      []OS     `json:"os_list,omitempty"`
}

// GetID returns the primary product identifier (PID or ID).
func (p Product) GetID() int {
	if p.PID > 0 {
		return p.PID
	}
	return p.ID
}

// HourlyPlan represents an hourly VPS plan formatted for admin inspection.
type HourlyPlan struct {
	ProductID      int      `json:"product_id"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	CPUCores       int      `json:"cpu_cores"`
	RAMMB          int      `json:"ram_mb"`
	DiskGB         int      `json:"disk_gb"`
	BandwidthTB    float64  `json:"bandwidth_tb,omitempty"`
	InStock        bool     `json:"in_stock"`
	PriceID        int      `json:"price_id"`
	Currency       string   `json:"currency"`
	HourlyRateNOK  float64  `json:"hourly_rate_nok"`
	MonthlyCeiling float64  `json:"monthly_ceiling_nok"`
	Regions        []Region `json:"regions"`
	OSList         []OS     `json:"os_list"`
}

// AccountInfo represents account balance, credit, and order eligibility.
type AccountInfo struct {
	ID       string  `json:"id,omitempty"`
	Email    string  `json:"email,omitempty"`
	Balance  float64 `json:"balance"`
	Credit   float64 `json:"credit"`
	Currency string  `json:"currency"`
	Status   string  `json:"status,omitempty"`
}

// HasCredit checks if the account has positive balance or credit available.
func (a *AccountInfo) HasCredit() bool {
	if a == nil {
		return false
	}
	return (a.Balance + a.Credit) > 0
}

// OrderRequest represents the payload for ordering a VPS.
type OrderRequest struct {
	PID           int    `json:"pid"`
	PriceID       int    `json:"price_id"`
	RegionID      int    `json:"region_id"`
	OSID          int    `json:"os_id"`
	BillingPeriod string `json:"billing_period"`
	Quantity      int    `json:"quantity"`
}

// OrderResponse represents the response when an order is submitted.
type OrderResponse struct {
	OrderID   string `json:"order_id"`
	ServerID  int64  `json:"server_id,omitempty"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// UnmarshalJSON supports string or integer order_id and server_id.
func (o *OrderResponse) UnmarshalJSON(data []byte) error {
	type rawOrder struct {
		OrderID   any    `json:"order_id"`
		ServerID  any    `json:"server_id"`
		Status    string `json:"status"`
		Message   string `json:"message"`
		CreatedAt string `json:"created_at"`
	}
	var raw rawOrder
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	o.Status = raw.Status
	o.Message = raw.Message
	o.CreatedAt = raw.CreatedAt

	o.OrderID = parseStringField(raw.OrderID)
	o.ServerID = parseInt64Field(raw.ServerID)
	return nil
}

// DeployStatusResponse represents deployment progress and assigned networking.
type DeployStatusResponse struct {
	OrderID    string `json:"order_id"`
	ServerID   int64  `json:"server_id,omitempty"`
	Status     string `json:"status"`
	Progress   int    `json:"progress,omitempty"`
	AssignedIP string `json:"assigned_ip,omitempty"`
	PublicIP   string `json:"public_ip,omitempty"`
	IPv4       string `json:"ipv4,omitempty"`
	Error      string `json:"error,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// UnmarshalJSON supports flexible field types in DeployStatusResponse.
func (d *DeployStatusResponse) UnmarshalJSON(data []byte) error {
	type rawStatus struct {
		OrderID    any    `json:"order_id"`
		ServerID   any    `json:"server_id"`
		Status     string `json:"status"`
		Progress   int    `json:"progress"`
		AssignedIP string `json:"assigned_ip"`
		PublicIP   string `json:"public_ip"`
		IPv4       string `json:"ipv4"`
		Error      string `json:"error"`
		UpdatedAt  string `json:"updated_at"`
	}
	var raw rawStatus
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d.Status = raw.Status
	d.Progress = raw.Progress
	d.AssignedIP = raw.AssignedIP
	d.PublicIP = raw.PublicIP
	d.IPv4 = raw.IPv4
	d.Error = raw.Error
	d.UpdatedAt = raw.UpdatedAt

	d.OrderID = parseStringField(raw.OrderID)
	d.ServerID = parseInt64Field(raw.ServerID)
	return nil
}

// GetIP returns the first available non-empty IP address.
func (d *DeployStatusResponse) GetIP() string {
	if d == nil {
		return ""
	}
	if d.AssignedIP != "" {
		return d.AssignedIP
	}
	if d.PublicIP != "" {
		return d.PublicIP
	}
	return d.IPv4
}

// ServerInfo represents an existing server instance.
type ServerInfo struct {
	ID        int64  `json:"id"`
	OrderID   string `json:"order_id,omitempty"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	IPv4      string `json:"ipv4,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	RegionID  int    `json:"region_id,omitempty"`
	PID       int    `json:"pid,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// UnmarshalJSON handles flexible ID/OrderID types for ServerInfo.
func (s *ServerInfo) UnmarshalJSON(data []byte) error {
	type rawServer struct {
		ID        any    `json:"id"`
		OrderID   any    `json:"order_id"`
		Name      string `json:"name"`
		Status    string `json:"status"`
		IPv4      string `json:"ipv4"`
		IPAddress string `json:"ip_address"`
		RegionID  int    `json:"region_id"`
		PID       int    `json:"pid"`
		CreatedAt string `json:"created_at"`
	}
	var raw rawServer
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.Name = raw.Name
	s.Status = raw.Status
	s.IPv4 = raw.IPv4
	s.IPAddress = raw.IPAddress
	s.RegionID = raw.RegionID
	s.PID = raw.PID
	s.CreatedAt = raw.CreatedAt

	s.ID = parseInt64Field(raw.ID)
	s.OrderID = parseStringField(raw.OrderID)
	return nil
}

// GetIP returns the public IPv4 or IP address.
func (s *ServerInfo) GetIP() string {
	if s == nil {
		return ""
	}
	if s.IPv4 != "" {
		return s.IPv4
	}
	return s.IPAddress
}

func parseStringField(val any) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case int:
		return strconv.Itoa(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func parseInt64Field(val any) int64 {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	default:
		return 0
	}
}
