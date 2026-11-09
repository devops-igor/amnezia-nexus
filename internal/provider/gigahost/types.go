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
	ErrOSNotAvailable       = errors.New("operating system is not available")
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
//
// Available is whether the plan may be deployed in the region at all
// (region_ids). InStock is whether at least one datacenter of that region
// currently has capacity for the plan (dc_ids + dc_stock). InStock is a
// pointer on purpose: nil means the provider catalog carried no per-datacenter
// stock fact, which is not the same as "sold out", and the handler must not
// treat an absent fact as a guess in either direction.
type Region struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Country   string `json:"country,omitempty"`
	Available bool   `json:"available"`
	InStock   *bool  `json:"in_stock,omitempty"`
}

// Sellable reports whether the plan may be ordered in this region right now.
func (r Region) Sellable() bool {
	if !r.Available {
		return false
	}
	return r.InStock == nil || *r.InStock
}

// OS is an available operating system image.
type OS struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// OperatingSystem is one installable image from GET /reinstall/distro/{dist_id}.
//
// Only documented fields are decoded: os_dedicated_only, os_minram,
// os_single_disk_only, os_support_raid, os_custom_partition, os_slow_install
// and, on GET /reinstall/os/{os_id}, os_limited_support. The distro endpoint
// documents no minimum disk for plain images (os_min_disk exists for one-click
// apps only), so no disk requirement is claimed here.
//
// Provider ids are the only identity that matters: an image is offered and
// accepted only when the provider catalog returned that os_id.
type OperatingSystem struct {
	OSID           int    `json:"os_id"`
	DistID         int    `json:"dist_id"`
	DistName       string `json:"dist_name,omitempty"`
	Name           string `json:"os_name"`
	Arch           string `json:"os_arch,omitempty"`
	MinRAMGB       int    `json:"os_minram"`
	DedicatedOnly  bool   `json:"os_dedicated_only"`
	LimitedSupport bool   `json:"os_limited_support,omitempty"`
}

// UnmarshalJSON accepts the documented string-encoded numeric and boolean
// fields ("147", "0"/"1") as well as real JSON numbers and booleans.
func (o *OperatingSystem) UnmarshalJSON(data []byte) error {
	type rawOS struct {
		OSID           any    `json:"os_id"`
		DistID         any    `json:"dist_id"`
		DistName       string `json:"dist_name"`
		Name           string `json:"os_name"`
		Arch           string `json:"os_arch"`
		MinRAMGB       any    `json:"os_minram"`
		DedicatedOnly  any    `json:"os_dedicated_only"`
		LimitedSupport any    `json:"os_limited_support"`
	}
	var raw rawOS
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	o.OSID = int(parseInt64Field(raw.OSID))
	o.DistID = int(parseInt64Field(raw.DistID))
	o.DistName = raw.DistName
	o.Name = raw.Name
	o.Arch = raw.Arch
	o.MinRAMGB = int(parseInt64Field(raw.MinRAMGB))
	if b, ok := parseBoolFieldStrict(raw.DedicatedOnly); ok {
		o.DedicatedOnly = b
	}
	if b, ok := parseBoolFieldStrict(raw.LimitedSupport); ok {
		o.LimitedSupport = b
	}
	return nil
}

// CompatibleWith reports whether the image can be installed on the plan using
// only documented requirements: os_dedicated_only needs a dedicated or auction
// server and os_minram is the minimum memory in GB (0 = none). A plan whose
// memory or type the catalog did not report therefore rejects an image that
// states a requirement, which fails closed instead of guessing.
func (o OperatingSystem) CompatibleWith(plan HourlyPlan) error {
	if o.OSID <= 0 {
		return fmt.Errorf("%w: image has no os_id", ErrOSNotAvailable)
	}
	if o.DedicatedOnly && !plan.IsDedicated() {
		return fmt.Errorf("%w: image %d is dedicated-only but plan %d is not a dedicated server", ErrOSNotAvailable, o.OSID, plan.ProductID)
	}
	if ramGB := plan.RAMMB / 1024; o.MinRAMGB > 0 && ramGB < o.MinRAMGB {
		return fmt.Errorf("%w: image %d needs %d GB RAM but plan %d has %d GB", ErrOSNotAvailable, o.OSID, o.MinRAMGB, plan.ProductID, ramGB)
	}
	return nil
}

// IsDedicated reports whether the plan is a dedicated or auction server, which
// is what os_dedicated_only images require.
func (p HourlyPlan) IsDedicated() bool {
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "dedicated", "auction", "baremetal":
		return true
	default:
		return false
	}
}

// HasStock reports whether the plan can be deployed at all right now: either the
// provider reports it in stock or documents it as built to order.
func (p HourlyPlan) HasStock() bool {
	return p.InStock || p.BuiltToOrder
}

// InstallableImages returns the images that can actually be installed on this
// plan, in the order the provider listed them. The provider catalog has no
// per-product image list, so the supported set is the provider's documented
// image catalog narrowed by each image's documented requirements.
func (p HourlyPlan) InstallableImages(catalog []OperatingSystem) []OperatingSystem {
	options := make([]OperatingSystem, 0, len(catalog))
	for _, os := range catalog {
		if os.CompatibleWith(p) == nil {
			options = append(options, os)
		}
	}
	return options
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
	ID           int                `json:"id"`
	PID          int                `json:"pid"`
	Name         string             `json:"name"`
	Description  string             `json:"description,omitempty"`
	Type         string             `json:"type,omitempty"`
	CPUCores     int                `json:"cpu_cores"`
	RAMMB        int                `json:"ram_mb"`
	DiskGB       int                `json:"disk_gb"`
	BandwidthTB  float64            `json:"bandwidth_tb,omitempty"`
	InStock      bool               `json:"in_stock"`
	BuiltToOrder bool               `json:"built_to_order,omitempty"`
	WaitlistOK   bool               `json:"waitlist_eligible,omitempty"`
	Prices       []Price            `json:"prices,omitempty"`
	Regions      []Region           `json:"regions,omitempty"`
	Datacenters  []Datacenter       `json:"datacenters,omitempty"`
	OSList       []OS               `json:"os_list,omitempty"`
	Eligibility  CatalogEligibility `json:"eligibility,omitempty"`
}

// GetID returns the primary product identifier (PID or ID).
func (p Product) GetID() int {
	if p.PID > 0 {
		return p.PID
	}
	return p.ID
}

// HourlyPlan represents an hourly VPS plan formatted for admin inspection.
//
// Type, BuiltToOrder and Datacenters are documented catalog facts
// (type, built_to_order, dc_ids/dc_stock). They exist so the portal can offer
// only selections the provider will actually accept, and so the handler can
// revalidate them instead of assuming them.
type HourlyPlan struct {
	ProductID      int                `json:"product_id"`
	Name           string             `json:"name"`
	Description    string             `json:"description,omitempty"`
	Type           string             `json:"type,omitempty"`
	CPUCores       int                `json:"cpu_cores"`
	RAMMB          int                `json:"ram_mb"`
	DiskGB         int                `json:"disk_gb"`
	BandwidthTB    float64            `json:"bandwidth_tb,omitempty"`
	InStock        bool               `json:"in_stock"`
	BuiltToOrder   bool               `json:"built_to_order,omitempty"`
	WaitlistOK     bool               `json:"waitlist_eligible,omitempty"`
	PriceID        int                `json:"price_id"`
	Currency       string             `json:"currency"`
	HourlyRateNOK  float64            `json:"hourly_rate_nok"`
	MonthlyCeiling float64            `json:"monthly_ceiling_nok"`
	Regions        []Region           `json:"regions"`
	Datacenters    []Datacenter       `json:"datacenters,omitempty"`
	OSOptions      []OperatingSystem  `json:"os_options"`
	Eligibility    CatalogEligibility `json:"eligibility,omitempty"`
}

// Datacenter is a placement location the plan documents, with its own stock
// fact. Only datacenters referenced by the plan's dc_ids are listed.
type Datacenter struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	RegionID int    `json:"region_id"`
	Location string `json:"location,omitempty"`
	Country  string `json:"country,omitempty"`
	InStock  bool   `json:"in_stock"`
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
//
// RateHourly, MonthlyCap and Currency are the per-order price contract the
// provider returns at order time. They are the only authoritative record of
// what an existing hourly reservation costs, so they are decoded here and
// persisted by the caller; the provider does not expose price_id on any later
// read.
type OrderResponse struct {
	OrderID   string `json:"order_id"`
	ServerID  int64  `json:"server_id,omitempty"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`

	RateHourly float64 `json:"rate_hourly,omitempty"`
	MonthlyCap float64 `json:"monthly_cap,omitempty"`
	Currency   string  `json:"currency,omitempty"`
}

// UnmarshalJSON supports string or integer order_id and server_id, and handles {data: {order_ids: [...]}}.
func (o *OrderResponse) UnmarshalJSON(data []byte) error {
	type rawOrder struct {
		OrderID    any     `json:"order_id"`
		ServerID   any     `json:"server_id"`
		Status     string  `json:"status"`
		Message    string  `json:"message"`
		CreatedAt  string  `json:"created_at"`
		Success    *bool   `json:"success"`
		OrderIDs   []any   `json:"order_ids"`
		RateHourly float64 `json:"rate_hourly"`
		MonthlyCap float64 `json:"monthly_cap"`
		Currency   string  `json:"currency"`
	}
	type envelope struct {
		Data rawOrder `json:"data"`
	}
	var raw rawOrder
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err == nil && (len(env.Data.OrderIDs) > 0 || env.Data.OrderID != nil || (env.Data.Success != nil && *env.Data.Success)) {
		raw = env.Data
	}

	o.Status = raw.Status
	o.Message = raw.Message
	o.CreatedAt = raw.CreatedAt
	o.RateHourly = raw.RateHourly
	o.MonthlyCap = raw.MonthlyCap
	o.Currency = raw.Currency

	if len(raw.OrderIDs) > 0 {
		o.OrderID = parseStringField(raw.OrderIDs[0])
	} else if raw.OrderID != nil {
		o.OrderID = parseStringField(raw.OrderID)
	}
	o.ServerID = parseInt64Field(raw.ServerID)

	if raw.Success != nil && !*raw.Success {
		return errors.New("provider reported order failure (success=false)")
	}
	if o.OrderID == "" {
		return errors.New("provider accepted request but returned no order id")
	}

	if o.Status == "" {
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

// PaginationMeta represents pagination metadata returned in list endpoints.
type PaginationMeta struct {
	Page          int  `json:"page"`
	TotalPages    int  `json:"total_pages"`
	PerPage       int  `json:"per_page,omitempty"`
	Total         int  `json:"total,omitempty"`
	HasPage       bool `json:"-"`
	HasTotalPages bool `json:"-"`
	HasTotal      bool `json:"-"`
}

// UnmarshalJSON handles flexible numeric and string types for pagination metadata.
func (m *PaginationMeta) UnmarshalJSON(data []byte) error {
	type rawMeta struct {
		Page       any `json:"page"`
		TotalPages any `json:"total_pages"`
		PerPage    any `json:"per_page"`
		Total      any `json:"total"`
	}
	var raw rawMeta
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Page != nil {
		v, ok := parseIntFieldStrict(raw.Page)
		if !ok || v <= 0 {
			return fmt.Errorf("invalid pagination metadata: page must be positive integer, got %v", raw.Page)
		}
		m.Page = v
		m.HasPage = true
	}
	if raw.TotalPages != nil {
		v, ok := parseIntFieldStrict(raw.TotalPages)
		if !ok || v < 1 {
			return fmt.Errorf("invalid pagination metadata: total_pages must be >= 1, got %v", raw.TotalPages)
		}
		m.TotalPages = v
		m.HasTotalPages = true
	}
	if raw.Total != nil {
		v, ok := parseIntFieldStrict(raw.Total)
		if !ok || v < 0 {
			return fmt.Errorf("invalid pagination metadata: total must be >= 0, got %v", raw.Total)
		}
		m.Total = v
		m.HasTotal = true
	}
	if raw.PerPage != nil {
		if v, ok := parseIntFieldStrict(raw.PerPage); ok && v >= 0 {
			m.PerPage = v
		}
	}
	return nil
}

// Validate checks pagination consistency and rejects malformed, incomplete, or inconsistent metadata.
func (m PaginationMeta) Validate(page, expectedPages int, hasExpectedTotal bool, expectedTotal, pageCount, currentAggregate int) error {
	if m.HasPage && m.Page != page {
		return fmt.Errorf("inconsistent pagination metadata: requested page %d but got page %d", page, m.Page)
	}
	if m.HasTotalPages {
		if m.TotalPages < 1 {
			return fmt.Errorf("invalid pagination metadata: total_pages must be >= 1, got %d", m.TotalPages)
		}
		if expectedPages > 0 && m.TotalPages != expectedPages {
			return fmt.Errorf("inconsistent pagination metadata: total_pages changed from %d to %d on page %d", expectedPages, m.TotalPages, page)
		}
	}
	if m.HasTotal && hasExpectedTotal && m.Total != expectedTotal {
		return fmt.Errorf("inconsistent pagination metadata: total changed from %d to %d on page %d", expectedTotal, m.Total, page)
	}
	if m.HasTotal && m.Total == 0 && pageCount > 0 {
		return fmt.Errorf("contradictory inventory: meta.total is 0 but page %d returned %d servers", page, pageCount)
	}
	if hasExpectedTotal && expectedTotal == 0 && pageCount > 0 {
		return fmt.Errorf("contradictory inventory: meta.total is 0 but page %d returned %d servers", page, pageCount)
	}
	if expectedPages > 1 && page < expectedPages && pageCount == 0 {
		return fmt.Errorf("incomplete inventory: intermediate page %d of %d returned 0 servers", page, expectedPages)
	}
	if hasExpectedTotal && expectedTotal > 0 && pageCount == 0 && currentAggregate < expectedTotal {
		return fmt.Errorf("incomplete inventory: page %d returned 0 servers but expected total is %d (received %d)", page, expectedTotal, currentAggregate)
	}
	return nil
}

// ServerInfo represents an existing server instance.
type ServerInfo struct {
	ID         int64  `json:"id"`
	OrderID    string `json:"order_id,omitempty"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	IPv4       string `json:"ipv4,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	RegionID   int    `json:"region_id,omitempty"`
	PID        int    `json:"pid,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	SrvType    string `json:"srv_type,omitempty"`
	SrvVPSType string `json:"srv_vps_type,omitempty"`
	BwIsHourly *bool  `json:"bw_is_hourly,omitempty"`
}

// IsHourlyVPS checks if a server is relevant to hourly VPS budget calculations.
func (s *ServerInfo) IsHourlyVPS() bool {
	if s == nil {
		return false
	}
	srvType := strings.ToLower(strings.TrimSpace(s.SrvType))
	if srvType == "dedicated" || srvType == "baremetal" || srvType == "recurring" {
		return false
	}
	if s.BwIsHourly != nil {
		return *s.BwIsHourly
	}
	if srvType == "vps" {
		return true
	}
	return srvType == ""
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
		SrvType    string   `json:"srv_type"`
		SrvVPSType string   `json:"srv_vps_type"`
		BwIsHourly any      `json:"bw_is_hourly"`
	}
	var raw rawServer
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	s.SrvType = raw.SrvType
	s.SrvVPSType = raw.SrvVPSType
	if raw.BwIsHourly != nil {
		if b, ok := parseBoolFieldStrict(raw.BwIsHourly); ok {
			s.BwIsHourly = &b
		} else {
			s.BwIsHourly = nil
		}
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

func parseIntFieldStrict(val any) (int, bool) {
	if val == nil {
		return 0, false
	}
	switch v := val.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v != float64(int64(v)) {
			return 0, false
		}
		return int(v), true
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, false
		}
		n, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func parseBoolFieldStrict(val any) (bool, bool) {
	if val == nil {
		return false, false
	}
	switch v := val.(type) {
	case bool:
		return v, true
	case int:
		if v == 1 {
			return true, true
		} else if v == 0 {
			return false, true
		}
		return false, false
	case int64:
		if v == 1 {
			return true, true
		} else if v == 0 {
			return false, true
		}
		return false, false
	case float64:
		if v == 1 {
			return true, true
		} else if v == 0 {
			return false, true
		}
		return false, false
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return false, false
		}
		b, err := strconv.ParseBool(trimmed)
		if err != nil {
			return false, false
		}
		return b, true
	default:
		return false, false
	}
}
