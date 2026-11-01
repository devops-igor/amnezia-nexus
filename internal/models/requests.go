package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	UsernameRegex      = regexp.MustCompile(`^[a-z0-9_-]+$`)
	SetupUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	TLSDomainRegex     = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,126}[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)
	HostnameRegex      = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)
	// shellMetacharRegex matches characters that are dangerous if interpolated
	// into a shell command: control characters (0x00-0x1f, 0x7f), and shell
	// metacharacters: ; | & $ ` ( ) < > { } ! # \ " ' and backslash.
	// Everything else — including Unicode letters — is allowed, because
	// ClientName never reaches a shell directly; it is written into JSON and
	// uploaded via SFTP. The reject-list blocks injection chars while keeping
	// non-Latin names (Cyrillic, Arabic, CJK, etc.) working.
	shellMetacharRegex = regexp.MustCompile("[\\x00-\\x1f\\x7f;|&$`()<>{}!#\\\\\"']")
)

// ValidatePasswordComplexity enforces password strength rules.
func ValidatePasswordComplexity(p string) error {
	var hasUpper, hasLower, hasDigit bool
	for _, c := range p {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		}
	}
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}
	return nil
}

// ValidateHost checks if a host string is a valid IP or hostname.
func ValidateHost(host string) error {
	raw := host
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = raw[1 : len(raw)-1]
	}
	if ip := net.ParseIP(raw); ip != nil {
		return nil
	}
	if HostnameRegex.MatchString(host) {
		return nil
	}
	return errors.New("host must be a valid IPv4 address or hostname")
}

// ValidateTLSDomain checks if a TLS domain string matches permitted patterns.
func ValidateTLSDomain(domain string) error {
	if !TLSDomainRegex.MatchString(domain) {
		return errors.New("tls_domain must be 1-128 chars, alphanumeric/dots/hyphens/underscores only")
	}
	return nil
}

// ValidateIdentifierName checks that name is non-empty, within length limits,
// free of null bytes, and free of shell metacharacters. Used by request
// Validate() methods for connection/client/server names.
func ValidateIdentifierName(name string) error {
	if strings.Contains(name, "\x00") {
		return errors.New("name cannot contain null bytes")
	}
	if name == "" {
		return errors.New("name must be between 1 and 255 characters")
	}
	if len(name) > 255 {
		return errors.New("name must be between 1 and 255 characters")
	}
	if shellMetacharRegex.MatchString(name) {
		return errors.New("name contains invalid characters; shell metacharacters and control characters are not allowed")
	}
	return nil
}

// LoginRequest defines credentials for dashboard authentication.
type LoginRequest struct {
	Username      string  `json:"username"`
	Password      string  `json:"password"`
	Captcha       *string `json:"captcha,omitempty"` // ignored legacy text field
	CaptchaTicket string  `json:"captcha_ticket,omitempty"`
}

func (r *LoginRequest) Validate() error {
	if strings.TrimSpace(r.Username) == "" {
		return errors.New("username is required")
	}
	if r.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

// SetupRequest defines the initial admin account creation payload.
type SetupRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

func (r *SetupRequest) Validate() error {
	if len(r.Username) < 3 || len(r.Username) > 32 || !SetupUsernameRegex.MatchString(r.Username) {
		return errors.New("username must be 3-32 alphanumeric characters or underscore")
	}
	if len(r.Password) < 8 || len(r.Password) > 4096 {
		return errors.New("password must be between 8 and 4096 characters")
	}
	if r.Password != r.ConfirmPassword {
		return errors.New("passwords do not match")
	}
	return ValidatePasswordComplexity(r.Password)
}

// ChangePasswordRequest defines password update payload for the current user.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

func (r *ChangePasswordRequest) Validate() error {
	if strings.Contains(r.NewPassword, "\x00") {
		return errors.New("password must not contain null bytes")
	}
	if len(r.NewPassword) < 8 || len(r.NewPassword) > 4096 {
		return errors.New("password must be between 8 and 4096 characters")
	}
	if r.NewPassword != r.ConfirmPassword {
		return errors.New("passwords do not match")
	}
	return ValidatePasswordComplexity(r.NewPassword)
}

// AddServerRequest defines parameters for adding a new server.
type AddServerRequest struct {
	Host       string `json:"host"`
	SSHPort    int    `json:"ssh_port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Name       string `json:"name"`
}

func (r *AddServerRequest) Validate() error {
	if r.SSHPort == 0 {
		r.SSHPort = 22
	}
	if r.SSHPort < 1 || r.SSHPort > 65535 {
		return errors.New("ssh_port must be between 1 and 65535")
	}
	if r.Host != "" {
		return ValidateHost(r.Host)
	}
	return nil
}

// ConfirmFingerprintRequest defines SSH fingerprint verification payload.
type ConfirmFingerprintRequest struct {
	AddServerRequest
	ServerInfo  string `json:"server_info"`
	Fingerprint string `json:"fingerprint"`
}

// RenameServerRequest defines server rename payload.
type RenameServerRequest struct {
	Name string `json:"name"`
}

func (r *RenameServerRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if err := ValidateIdentifierName(r.Name); err != nil {
		return err
	}
	return nil
}

// UpdateServerHostRequest defines server host/IP update payload.
type UpdateServerHostRequest struct {
	Host string `json:"host"`
}

func (r *UpdateServerHostRequest) Validate() error {
	r.Host = strings.TrimSpace(r.Host)
	if r.Host == "" {
		return errors.New("host cannot be empty")
	}
	if strings.HasPrefix(r.Host, "[") && strings.HasSuffix(r.Host, "]") {
		inner := r.Host[1 : len(r.Host)-1]
		if ip := net.ParseIP(inner); ip != nil {
			r.Host = inner
		}
	}
	return ValidateHost(r.Host)
}

// VLESSInstallOptions defines installation parameters specific to VLESS+REALITY.
type VLESSInstallOptions struct {
	Port          string `json:"port,omitempty"`
	ServerName    string `json:"server_name,omitempty"`
	Flow          string `json:"flow"`
	FlowSet       bool   `json:"-"`
	EngineProfile string `json:"engine_profile,omitempty"`
	Mux           *bool  `json:"mux,omitempty"`
}

// UnmarshalJSON preserves awareness of whether the "flow" field was explicitly present in the JSON payload.
func (v *VLESSInstallOptions) UnmarshalJSON(data []byte) error {
	type Alias VLESSInstallOptions
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*v = VLESSInstallOptions(a)
	if _, ok := raw["flow"]; ok {
		v.FlowSet = true
	}
	return nil
}

// NaiveInstallOptions defines installation parameters specific to NaiveProxy.
type NaiveInstallOptions struct {
	Port          string `json:"port,omitempty"`
	Domain        string `json:"domain,omitempty"`
	DecoyTemplate string `json:"decoy_template,omitempty"`
}

// InstallProtocolRequest defines protocol deployment options on a server.
type InstallProtocolRequest struct {
	Protocol            string                 `json:"protocol"`
	Port                string                 `json:"port"`
	TLSEmulation        *bool                  `json:"tls_emulation,omitempty"`
	TLSDomain           *string                `json:"tls_domain,omitempty"`
	MaxConnections      *int                   `json:"max_connections,omitempty"`
	AWGProfile          *AWGObfuscationProfile `json:"awg_profile,omitempty"`
	AWGCPSProtocol      *string                `json:"awg_cps_protocol,omitempty"`
	AWGHeaderProtection *bool                  `json:"awg_header_protection,omitempty"`
	VLESSOptions        *VLESSInstallOptions   `json:"vless_options,omitempty"`
	NaiveOptions        *NaiveInstallOptions   `json:"naive_options,omitempty"`
	EngineProfile       string                 `json:"engine_profile,omitempty"`
}

func (r *InstallProtocolRequest) hasConfigOptions() bool {
	return r.EngineProfile != "" || r.VLESSOptions != nil || r.NaiveOptions != nil ||
		r.TLSEmulation != nil || r.TLSDomain != nil || r.MaxConnections != nil ||
		r.AWGProfile != nil || r.AWGCPSProtocol != nil || r.AWGHeaderProtection != nil
}

func (r *InstallProtocolRequest) validateVLESS() error {
	if r.VLESSOptions == nil {
		return nil
	}
	if r.VLESSOptions.Port != "" {
		p, err := strconv.Atoi(r.VLESSOptions.Port)
		if err != nil || p < 1 || p > 65535 {
			return errors.New("vless port must be an integer between 1 and 65535")
		}
	}
	if r.VLESSOptions.ServerName != "" {
		if err := ValidateTLSDomain(r.VLESSOptions.ServerName); err != nil {
			return fmt.Errorf("invalid vless server_name: %w", err)
		}
	}
	return nil
}

func (r *InstallProtocolRequest) validateNaive() error {
	if r.NaiveOptions == nil {
		return nil
	}
	if r.NaiveOptions.Port != "" {
		p, err := strconv.Atoi(r.NaiveOptions.Port)
		if err != nil || p < 1 || p > 65535 {
			return errors.New("naive port must be an integer between 1 and 65535")
		}
	}
	if r.NaiveOptions.Domain != "" {
		if err := ValidateTLSDomain(r.NaiveOptions.Domain); err != nil {
			return fmt.Errorf("invalid naive domain: %w", err)
		}
	}
	return nil
}

func (r *InstallProtocolRequest) Validate() error {
	r.Protocol = NormalizeProtocol(r.Protocol)
	if !IsValidProtocol(r.Protocol) {
		return fmt.Errorf("invalid protocol: %s", r.Protocol)
	}
	if r.Port != "" {
		portNum, err := strconv.Atoi(r.Port)
		if err != nil || portNum < 1 || portNum > 65535 {
			return errors.New("port must be an integer between 1 and 65535")
		}
	} else if !r.hasConfigOptions() {
		return errors.New("port must be an integer between 1 and 65535")
	}
	if r.TLSDomain != nil && *r.TLSDomain != "" {
		if err := ValidateTLSDomain(*r.TLSDomain); err != nil {
			return err
		}
	}
	if err := r.validateVLESS(); err != nil {
		return err
	}
	return r.validateNaive()
}

// AddUserRequest defines user creation parameters.
type AddUserRequest struct {
	Username             string   `json:"username"`
	Password             string   `json:"password"`
	Role                 UserRole `json:"role"`
	TelegramID           *string  `json:"telegramId,omitempty"`
	Email                *string  `json:"email,omitempty"`
	Description          *string  `json:"description,omitempty"`
	TrafficLimit         float64  `json:"traffic_limit"`
	TrafficResetStrategy string   `json:"traffic_reset_strategy"`
	ServerID             *int64   `json:"server_id,omitempty"`
	Protocol             *string  `json:"protocol,omitempty"`
	ConnectionName       *string  `json:"connection_name,omitempty"`
	ExpirationDate       *string  `json:"expiration_date,omitempty"`
	ExpiresAt            *string  `json:"expires_at,omitempty"`
	AWGMimicry           *string  `json:"awg_mimicry,omitempty"`
}

func (r *AddUserRequest) Validate() error {
	r.Username = strings.ToLower(strings.TrimSpace(r.Username))
	if len(r.Username) < 3 || len(r.Username) > 255 || !UsernameRegex.MatchString(r.Username) {
		return errors.New("username must be 3-255 characters with lowercase letters, digits, hyphens, and underscores")
	}
	if len(r.Password) < 8 || len(r.Password) > 4096 {
		return errors.New("password must be between 8 and 4096 characters")
	}
	if err := ValidatePasswordComplexity(r.Password); err != nil {
		return err
	}
	if r.Role != "" && !ValidateRole(r.Role) {
		return fmt.Errorf("invalid user role: %s", r.Role)
	}
	if r.Protocol != nil && *r.Protocol != "" {
		*r.Protocol = NormalizeProtocol(*r.Protocol)
		if !IsValidProtocol(*r.Protocol) {
			return fmt.Errorf("invalid protocol: %s", *r.Protocol)
		}
	}
	return nil
}

// ProtocolRequest defines a request with just a protocol name.
type ProtocolRequest struct {
	Protocol string `json:"protocol"`
}

func (r *ProtocolRequest) Validate() error {
	r.Protocol = NormalizeProtocol(r.Protocol)
	if !IsValidProtocol(r.Protocol) {
		return fmt.Errorf("invalid protocol: %s", r.Protocol)
	}
	return nil
}

// ServerConfigSaveRequest defines a payload to save server protocol configuration.
type ServerConfigSaveRequest struct {
	Protocol string `json:"protocol"`
	Config   string `json:"config"`
}

func (r *ServerConfigSaveRequest) Validate() error {
	r.Protocol = NormalizeProtocol(r.Protocol)
	if !IsValidProtocol(r.Protocol) {
		return fmt.Errorf("invalid protocol: %s", r.Protocol)
	}
	if len(r.Config) == 0 || len(r.Config) > 65536 {
		return errors.New("config must be between 1 and 65536 characters")
	}
	return nil
}

// AddConnectionRequest defines parameters for adding a new connection to a server.
type AddConnectionRequest struct {
	Protocol     string  `json:"protocol"`
	Name         string  `json:"name"`
	UserID       *string `json:"user_id,omitempty"`
	TelemtQuota  *string `json:"telemt_quota,omitempty"`
	TelemtMaxIPs *int    `json:"telemt_max_ips,omitempty"`
	TelemtExpiry *string `json:"telemt_expiry,omitempty"`
	AWGMimicry   *string `json:"awg_mimicry,omitempty"`
}

func (r *AddConnectionRequest) Validate() error {
	r.Protocol = NormalizeProtocol(r.Protocol)
	if !IsValidProtocol(r.Protocol) {
		return fmt.Errorf("invalid protocol: %s", r.Protocol)
	}
	r.Name = strings.TrimSpace(r.Name)
	if err := ValidateIdentifierName(r.Name); err != nil {
		return err
	}
	return nil
}

// MyAddConnectionRequest defines parameters for adding a user's own connection.
type MyAddConnectionRequest struct {
	ServerID     int64   `json:"server_id"`
	Protocol     string  `json:"protocol"`
	Name         string  `json:"name"`
	LoadBalanced bool    `json:"load_balanced,omitempty"`
	TelemtQuota  *string `json:"telemt_quota,omitempty"`
	TelemtMaxIPs *int    `json:"telemt_max_ips,omitempty"`
	TelemtExpiry *string `json:"telemt_expiry,omitempty"`
	AWGMimicry   *string `json:"awg_mimicry,omitempty"`
}

func (r *MyAddConnectionRequest) Validate() error {
	r.Protocol = NormalizeProtocol(r.Protocol)
	if !IsValidProtocol(r.Protocol) {
		return fmt.Errorf("invalid protocol: %s", r.Protocol)
	}
	if r.LoadBalanced || r.ServerID == 0 {
		if r.ServerID < 0 {
			return errors.New("server_id must be greater than or equal to 0")
		}
		if r.Protocol != "awg" {
			return errors.New("load-balanced connections only support awg protocol")
		}
	} else if r.ServerID <= 0 {
		return errors.New("server_id must be greater than 0")
	}
	r.Name = strings.TrimSpace(r.Name)
	if err := ValidateIdentifierName(r.Name); err != nil {
		return err
	}
	return nil
}

// AddUserConnectionRequest defines parameters for adding a connection to a specific user.
type AddUserConnectionRequest struct {
	ServerID     int64   `json:"server_id"`
	Protocol     string  `json:"protocol"`
	Name         string  `json:"name"`
	ClientID     *string `json:"client_id,omitempty"`
	TelemtQuota  *string `json:"telemt_quota,omitempty"`
	TelemtMaxIPs *int    `json:"telemt_max_ips,omitempty"`
	TelemtExpiry *string `json:"telemt_expiry,omitempty"`
	AWGMimicry   *string `json:"awg_mimicry,omitempty"`
}

func (r *AddUserConnectionRequest) Validate() error {
	if r.ServerID <= 0 {
		return errors.New("server_id must be greater than 0")
	}
	r.Protocol = NormalizeProtocol(r.Protocol)
	if !IsValidProtocol(r.Protocol) {
		return fmt.Errorf("invalid protocol: %s", r.Protocol)
	}
	r.Name = strings.TrimSpace(r.Name)
	if err := ValidateIdentifierName(r.Name); err != nil {
		return err
	}
	return nil
}

// EditConnectionRequest defines parameters for editing an existing connection.
type EditConnectionRequest struct {
	Protocol     string  `json:"protocol"`
	ClientID     string  `json:"client_id"`
	Name         *string `json:"name,omitempty"`
	UserID       *string `json:"user_id,omitempty"`
	TelemtQuota  *string `json:"telemt_quota,omitempty"`
	TelemtMaxIPs *int    `json:"telemt_max_ips,omitempty"`
	TelemtExpiry *string `json:"telemt_expiry,omitempty"`
	AWGMimicry   *string `json:"awg_mimicry,omitempty"`
}

// Validate checks the EditConnectionRequest fields for protocol validity and,
// when Name is provided, ensures it contains only safe identifier characters.
// Protocol validation is conditional: if Protocol is empty, the check is
// skipped to preserve backward compatibility (edit requests that only update
// name or limits don't need to re-specify the protocol).
func (r *EditConnectionRequest) Validate() error {
	if r.Protocol != "" {
		r.Protocol = NormalizeProtocol(r.Protocol)
		if !IsValidProtocol(r.Protocol) {
			return fmt.Errorf("invalid protocol: %s", r.Protocol)
		}
	}
	if r.ClientID == "" {
		return errors.New("client_id is required")
	}
	if r.Name != nil {
		name := strings.TrimSpace(*r.Name)
		if err := ValidateIdentifierName(name); err != nil {
			return err
		}
		r.Name = &name
	}
	return nil
}

// RenameConnectionRequest defines connection rename payload.
type RenameConnectionRequest struct {
	Name string `json:"name"`
}

func (r *RenameConnectionRequest) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if err := ValidateIdentifierName(r.Name); err != nil {
		return err
	}
	return nil
}

// UpdateUserRequest defines parameters for updating an existing user.
type UpdateUserRequest struct {
	TelegramID           *string  `json:"telegramId,omitempty"`
	Email                *string  `json:"email,omitempty"`
	Description          *string  `json:"description,omitempty"`
	TrafficLimit         *float64 `json:"traffic_limit,omitempty"`
	TrafficResetStrategy *string  `json:"traffic_reset_strategy,omitempty"`
	ExpirationDate       *string  `json:"expiration_date,omitempty"`
	ExpiresAt            *string  `json:"expires_at,omitempty"`
	AWGMimicry           *string  `json:"awg_mimicry,omitempty"`
	Password             *string  `json:"password,omitempty"`
}

func (r *UpdateUserRequest) Validate() error {
	if r.Password != nil && *r.Password != "" {
		if len(*r.Password) < 8 || len(*r.Password) > 4096 {
			return errors.New("password must be between 8 and 4096 characters")
		}
		return ValidatePasswordComplexity(*r.Password)
	}
	return nil
}

// ToggleUserRequest defines user enable/disable payload.
type ToggleUserRequest struct {
	Enabled bool `json:"enabled"`
}

// ToggleConnectionRequest defines connection enable/disable payload.
type ToggleConnectionRequest struct {
	Enabled bool `json:"enabled"`
}

// ConnectionActionRequest defines common client ID + protocol request payload.
type ConnectionActionRequest struct {
	ClientID string `json:"client_id"`
	Protocol string `json:"protocol"`
}

func (r *ConnectionActionRequest) Validate() error {
	if r.ClientID == "" {
		return errors.New("client_id is required")
	}
	r.Protocol = NormalizeProtocol(r.Protocol)
	if !IsValidProtocol(r.Protocol) {
		return fmt.Errorf("invalid protocol: %s", r.Protocol)
	}
	return nil
}

// ShareSetupRequest defines parameters for configuring user share link.
type ShareSetupRequest struct {
	Password       *string `json:"password,omitempty"`
	ExpiresInHours *int    `json:"expires_in_hours,omitempty"`
}

// ShareAuthRequest defines password verification payload for public share link.
type ShareAuthRequest struct {
	Password string `json:"password"`
}

// AutoTrialRequest defines parameters for server reachability/auto-trial testing.
type AutoTrialRequest struct {
	ServerID  int64    `json:"server_id"`
	Protocols []string `json:"protocols"`
}

// SaveSettingsRequest defines settings save payload.
type SaveSettingsRequest struct {
	Appearance AppearanceSettings     `json:"appearance"`
	Captcha    CaptchaSettings        `json:"captcha"`
	Telegram   map[string]interface{} `json:"telegram,omitempty"`
	SSL        SSLSettings            `json:"ssl"`
	Limits     ConnectionLimits       `json:"limits"`
}
