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

	StatusPending    = "pending"
	StatusDeploying  = "deploying"
	StatusWaiting    = "waiting"
	StatusInstalling = "installing"
	StatusReady      = "ready"
	StatusFailed     = "failed"
	StatusUnknown    = "unknown"
)

// IsTerminalStatus returns true if deployment reached a finished state.
func IsTerminalStatus(status string) bool {
	s := strings.ToLower(status)
	switch {
	case s == StatusReady || s == StatusFailed || s == "active" || s == "deleted":
		return true
	case strings.HasPrefix(s, "cancel"):
		return true
	default:
		return false
	}
}

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

// OrderPartialError represents an error where the provider returned a non-2xx HTTP status
// (e.g. 402 Payment Required or approval pending), but order IDs were created and returned.
type OrderPartialError struct {
	StatusCode int     `json:"status_code"`
	Message    string  `json:"message"`
	OrderIDs   []int64 `json:"order_ids"`
	RawBody    string  `json:"raw_body,omitempty"`
}

func (e *OrderPartialError) Error() string {
	return fmt.Sprintf("order pending payment/approval (status %d, order_ids %v): %s", e.StatusCode, e.OrderIDs, e.Message)
}

func (e *OrderPartialError) FirstOrderID() string {
	if len(e.OrderIDs) > 0 {
		return strconv.FormatInt(e.OrderIDs[0], 10)
	}
	return ""
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
	ID          int                `json:"id"`
	PID         int                `json:"pid"`
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	CPUCores    int                `json:"cpu_cores"`
	RAMMB       int                `json:"ram_mb"`
	DiskGB      int                `json:"disk_gb"`
	BandwidthTB float64            `json:"bandwidth_tb,omitempty"`
	InStock     bool               `json:"in_stock"`
	Prices      []Price            `json:"prices,omitempty"`
	Regions     []Region           `json:"regions,omitempty"`
	OSList      []OS               `json:"os_list,omitempty"`
	Eligibility CatalogEligibility `json:"eligibility,omitempty"`
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
	ProductID      int                `json:"product_id"`
	Name           string             `json:"name"`
	Description    string             `json:"description,omitempty"`
	CPUCores       int                `json:"cpu_cores"`
	RAMMB          int                `json:"ram_mb"`
	DiskGB         int                `json:"disk_gb"`
	BandwidthTB    float64            `json:"bandwidth_tb,omitempty"`
	InStock        bool               `json:"in_stock"`
	PriceID        int                `json:"price_id"`
	Currency       string             `json:"currency"`
	HourlyRateNOK  float64            `json:"hourly_rate_nok"`
	MonthlyCeiling float64            `json:"monthly_ceiling_nok"`
	Regions        []Region           `json:"regions"`
	OSList         []OS               `json:"os_list"`
	Eligibility    CatalogEligibility `json:"eligibility,omitempty"`
}

// CatalogEligibility represents account deployment eligibility returned in the catalog.
type CatalogEligibility struct {
	QualifiesArrears bool    `json:"qualifies_arrears"`
	CreditNOK        float64 `json:"credit_nok"`
}

// Catalog represents catalog plans and account eligibility.
type Catalog struct {
	Plans       []HourlyPlan       `json:"plans"`
	Eligibility CatalogEligibility `json:"eligibility"`
}

// CatalogResponse is an alias for Catalog.
type CatalogResponse = Catalog

// HasEligibility evaluates account and catalog eligibility for ordering hourly servers.
func HasEligibility(account *AccountInfo, catalog *Catalog) bool {
	if catalog != nil {
		if catalog.Eligibility.QualifiesArrears || catalog.Eligibility.CreditNOK > 0 {
			return true
		}
		for _, p := range catalog.Plans {
			if p.Eligibility.QualifiesArrears || p.Eligibility.CreditNOK > 0 {
				return true
			}
		}
	}
	if account != nil {
		if account.QualifiesArrears || (account.Balance+account.Credit+account.CreditNOK) > 0 {
			return true
		}
	}
	return false
}

// AccountInfo represents account balance, credit, and order eligibility.
type AccountInfo struct {
	ID               string  `json:"id,omitempty"`
	CustID           string  `json:"cust_id,omitempty"`
	CustName         string  `json:"cust_name,omitempty"`
	Email            string  `json:"email,omitempty"`
	Balance          float64 `json:"balance"`
	Credit           float64 `json:"credit"`
	CreditNOK        float64 `json:"credit_nok"`
	QualifiesArrears bool    `json:"qualifies_arrears"`
	Currency         string  `json:"currency"`
	Status           string  `json:"status,omitempty"`
}

// HasCredit checks if the account has positive balance, credit, or arrears qualification.
func (a *AccountInfo) HasCredit() bool {
	if a == nil {
		return false
	}
	if a.QualifiesArrears {
		return true
	}
	return (a.Balance + a.Credit + a.CreditNOK) > 0
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

// UnmarshalJSON supports string or integer order_id and server_id, and handles {data: {order_ids: [...]}}.
func (o *OrderResponse) UnmarshalJSON(data []byte) error {
	type rawOrder struct {
		OrderID   any    `json:"order_id"`
		ServerID  any    `json:"server_id"`
		Status    string `json:"status"`
		Message   string `json:"message"`
		CreatedAt string `json:"created_at"`
		Success   bool   `json:"success"`
		OrderIDs  []any  `json:"order_ids"`
	}
	type envelope struct {
		Data rawOrder `json:"data"`
	}
	var raw rawOrder
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err == nil && (len(env.Data.OrderIDs) > 0 || env.Data.OrderID != nil || env.Data.Success) {
		raw = env.Data
	}

	o.Status = raw.Status
	o.Message = raw.Message
	o.CreatedAt = raw.CreatedAt

	if len(raw.OrderIDs) > 0 {
		o.OrderID = parseStringField(raw.OrderIDs[0])
	} else if raw.OrderID != nil {
		o.OrderID = parseStringField(raw.OrderID)
	}
	o.ServerID = parseInt64Field(raw.ServerID)

	if o.Status == "" && (raw.Success || o.OrderID != "") {
		o.Status = StatusPending
	}
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

// UnmarshalJSON supports flexible field types and data.servers[] envelope in DeployStatusResponse.
func (d *DeployStatusResponse) UnmarshalJSON(data []byte) error {
	type rawServer struct {
		OrderID    any    `json:"order_id"`
		SrvID      any    `json:"srv_id"`
		ServerID   any    `json:"server_id"`
		ID         any    `json:"id"`
		Status     string `json:"status"`
		Progress   int    `json:"progress"`
		IP         string `json:"ip"`
		AssignedIP string `json:"assigned_ip"`
		PublicIP   string `json:"public_ip"`
		IPv4       string `json:"ipv4"`
		Error      string `json:"error"`
		UpdatedAt  string `json:"updated_at"`
	}
	type rawStatus struct {
		OrderID    any         `json:"order_id"`
		ServerID   any         `json:"server_id"`
		Status     string      `json:"status"`
		Progress   int         `json:"progress"`
		AssignedIP string      `json:"assigned_ip"`
		PublicIP   string      `json:"public_ip"`
		IPv4       string      `json:"ipv4"`
		Error      string      `json:"error"`
		UpdatedAt  string      `json:"updated_at"`
		Servers    []rawServer `json:"servers"`
	}
	type envelope struct {
		Data   *rawStatus `json:"data"`
		Status *rawStatus `json:"status"`
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err == nil && (env.Data != nil || env.Status != nil) {
		var src *rawStatus
		if env.Data != nil {
			src = env.Data
		} else {
			src = env.Status
		}
		if len(src.Servers) > 0 {
			s := src.Servers[0]
			d.Status = s.Status
			d.Progress = s.Progress
			d.Error = s.Error
			d.UpdatedAt = s.UpdatedAt
			d.OrderID = parseStringField(s.OrderID)
			if s.SrvID != nil {
				d.ServerID = parseInt64Field(s.SrvID)
			} else if s.ServerID != nil {
				d.ServerID = parseInt64Field(s.ServerID)
			} else if s.ID != nil {
				d.ServerID = parseInt64Field(s.ID)
			}
			ip := s.IP
			if ip == "" {
				ip = s.AssignedIP
			}
			if ip == "" {
				ip = s.PublicIP
			}
			if ip == "" {
				ip = s.IPv4
			}
			d.AssignedIP = ip
			d.PublicIP = ip
			d.IPv4 = ip
			return nil
		}
		d.Status = src.Status
		d.Progress = src.Progress
		d.AssignedIP = src.AssignedIP
		d.PublicIP = src.PublicIP
		d.IPv4 = src.IPv4
		d.Error = src.Error
		d.UpdatedAt = src.UpdatedAt
		d.OrderID = parseStringField(src.OrderID)
		d.ServerID = parseInt64Field(src.ServerID)
		return nil
	}

	var raw rawStatus
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if len(raw.Servers) > 0 {
		s := raw.Servers[0]
		d.Status = s.Status
		d.Progress = s.Progress
		d.Error = s.Error
		d.UpdatedAt = s.UpdatedAt
		d.OrderID = parseStringField(s.OrderID)
		if s.SrvID != nil {
			d.ServerID = parseInt64Field(s.SrvID)
		} else if s.ServerID != nil {
			d.ServerID = parseInt64Field(s.ServerID)
		} else if s.ID != nil {
			d.ServerID = parseInt64Field(s.ID)
		}
		ip := s.IP
		if ip == "" {
			ip = s.AssignedIP
		}
		if ip == "" {
			ip = s.PublicIP
		}
		if ip == "" {
			ip = s.IPv4
		}
		d.AssignedIP = ip
		d.PublicIP = ip
		d.IPv4 = ip
		return nil
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

// UnmarshalJSON handles flexible ID/OrderID types and documented /servers structures.
func (s *ServerInfo) UnmarshalJSON(data []byte) error {
	type rawOrder struct {
		OrderID     any `json:"order_id"`
		ProductID   any `json:"product_id"`
		OrderStatus any `json:"order_status"`
	}
	type rawDC struct {
		RegionID any `json:"region_id"`
	}
	type rawServer struct {
		ID         any      `json:"id"`
		SrvID      any      `json:"srv_id"`
		OrderID    any      `json:"order_id"`
		Name       string   `json:"name"`
		SrvName    string   `json:"srv_name"`
		Status     string   `json:"status"`
		SrvStatus  any      `json:"srv_status"`
		IPv4       string   `json:"ipv4"`
		IPAddress  string   `json:"ip_address"`
		SrvPrimIP  string   `json:"srv_primary_ip"`
		RegionID   any      `json:"region_id"`
		PID        any      `json:"pid"`
		CreatedAt  string   `json:"created_at"`
		Order      rawOrder `json:"order"`
		Datacenter rawDC    `json:"datacenter"`
	}
	var raw rawServer
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.SrvName != "" {
		s.Name = raw.SrvName
	} else {
		s.Name = raw.Name
	}

	if raw.Order.OrderStatus != nil {
		s.Status = parseStringField(raw.Order.OrderStatus)
	} else if raw.Status != "" {
		s.Status = raw.Status
	} else if b, ok := raw.SrvStatus.(bool); ok && b {
		s.Status = "ready"
	}

	ip := raw.SrvPrimIP
	if ip == "" {
		ip = raw.IPv4
	}
	if ip == "" {
		ip = raw.IPAddress
	}
	s.IPv4 = ip
	s.IPAddress = ip

	if raw.Datacenter.RegionID != nil {
		s.RegionID = int(parseInt64Field(raw.Datacenter.RegionID))
	} else if raw.RegionID != nil {
		s.RegionID = int(parseInt64Field(raw.RegionID))
	}

	if raw.Order.ProductID != nil {
		s.PID = int(parseInt64Field(raw.Order.ProductID))
	} else if raw.PID != nil {
		s.PID = int(parseInt64Field(raw.PID))
	}

	s.CreatedAt = raw.CreatedAt

	if raw.SrvID != nil {
		s.ID = parseInt64Field(raw.SrvID)
	} else {
		s.ID = parseInt64Field(raw.ID)
	}

	if raw.Order.OrderID != nil {
		s.OrderID = parseStringField(raw.Order.OrderID)
	} else {
		s.OrderID = parseStringField(raw.OrderID)
	}
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
