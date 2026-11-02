package models

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	ProtocolAWG   = "awg"
	ProtocolVLESS = "vless"
	ProtocolNaive = "naive"
)

var ValidProtocols = map[string]bool{
	ProtocolAWG:   true,
	"telemt":      true,
	"dns":         true,
	ProtocolVLESS: true,
	ProtocolNaive: true,
}

// ProtocolAliases maps legacy protocol names to standardized names.
var ProtocolAliases = map[string]string{
	"awg2":          ProtocolAWG,
	"awg_legacy":    ProtocolAWG,
	"vless-reality": ProtocolVLESS,
	"vless_reality": ProtocolVLESS,
	"naiveproxy":    ProtocolNaive,
}

// NormalizeProtocol normalizes legacy protocol names (e.g., awg2, awg_legacy -> awg).
func NormalizeProtocol(proto string) string {
	if mapped, ok := ProtocolAliases[proto]; ok {
		return mapped
	}
	return proto
}

// IsValidProtocol checks if a given protocol string is supported.
func IsValidProtocol(proto string) bool {
	return ValidProtocols[NormalizeProtocol(proto)]
}

// ContainerNameForProtocol maps a validated protocol to its Docker container name.
// The second return value is false for unknown protocols, so callers must reject
// unvalidated user input instead of interpolating it into shell commands.
func ContainerNameForProtocol(proto string) (string, bool) {
	switch NormalizeProtocol(proto) {
	case ProtocolAWG:
		return "amnezia-awg", true
	case "telemt":
		return "telemt", true
	case "dns":
		return "amnezia-dns", true
	case ProtocolVLESS:
		return "amnezia-xray", true
	case ProtocolNaive:
		return "amnezia-caddy", true
	default:
		return "", false
	}
}

// ConfigPathForProtocol maps a validated protocol to its remote config file path.
// Rejecting unknown protocols here prevents path injection via user-supplied input.
func ConfigPathForProtocol(proto string) (string, bool) {
	switch NormalizeProtocol(proto) {
	case ProtocolAWG:
		return "/opt/amnezia/awg/awg0.conf", true
	case "dns":
		return "/opt/amnezia/dns/unbound.conf", true
	case "telemt":
		return "/opt/mtproxyl/settings.conf", true
	case ProtocolVLESS:
		return "/opt/amnezia/xray/config.json", true
	case ProtocolNaive:
		return "/opt/amnezia/caddy/Caddyfile", true
	default:
		return "", false
	}
}

// AWGObfuscationProfile determines AWG junk packet ranges and overhead.
type AWGObfuscationProfile string

const (
	AWGProfileLite     AWGObfuscationProfile = "lite"     // Jc: 3-5
	AWGProfileStandard AWGObfuscationProfile = "standard" // Jc: 5-8 (default)
	AWGProfilePro      AWGObfuscationProfile = "pro"      // Jc: 4-16
)

// AWGMimicryProfile determines DPI mimicry protocol signature.
type AWGMimicryProfile string

const (
	AWGMimicryAuto AWGMimicryProfile = "auto"
	AWGMimicryTLS  AWGMimicryProfile = "tls"
	AWGMimicryDNS  AWGMimicryProfile = "dns"
	AWGMimicrySIP  AWGMimicryProfile = "sip"
	AWGMimicryQUIC AWGMimicryProfile = "quic"
)

// UserRole defines user authorization levels.
type UserRole string

const (
	RoleAdmin   UserRole = "admin"
	RoleSupport UserRole = "support"
	RoleUser    UserRole = "user"
)

// ValidRoles lists valid user roles.
var ValidRoles = map[UserRole]bool{
	RoleAdmin:   true,
	RoleSupport: true,
	RoleUser:    true,
}

// ValidateRole checks if a given user role is recognized.
func ValidateRole(role UserRole) bool {
	return ValidRoles[role]
}

// IsValidRole checks if a string corresponds to a valid user role.
func IsValidRole(role string) bool {
	return ValidRoles[UserRole(role)]
}

// IsAdminOrSupport checks if the role has administrative or support privileges.
func (r UserRole) IsAdminOrSupport() bool {
	return r == RoleAdmin || r == RoleSupport
}

// IsAdmin checks if the user has administrative or support privileges.
func (u *User) IsAdmin() bool {
	if u == nil {
		return false
	}
	return u.Role.IsAdminOrSupport()
}

// TrafficResetStrategy defines counter reset policy.
type TrafficResetStrategy string

const (
	ResetStrategyNever   TrafficResetStrategy = "never"   // Default: counters accumulate monotonically
	ResetStrategyMonthly TrafficResetStrategy = "monthly" // Active in runtime: resets monthly_rx/tx and traffic_used on 1st of month
	ResetStrategyDaily   TrafficResetStrategy = "daily"   // Allowed in schema/API for compatibility
)

// ReachabilityStatus defines server probe states.
type ReachabilityStatus string

const (
	ReachabilityOnline  ReachabilityStatus = "online"
	ReachabilityOffline ReachabilityStatus = "offline"
	ReachabilityUnknown ReachabilityStatus = "unknown"
)

// LoadBalancingAlgorithm defines VPN routing algorithm.
type LoadBalancingAlgorithm string

const (
	LBLeastConnections LoadBalancingAlgorithm = "least_conn"
	LBWeighted         LoadBalancingAlgorithm = "weighted"
	LBRoundRobin       LoadBalancingAlgorithm = "round_robin"
)

// Server represents a managed remote VPN host.
type Server struct {
	ID         int64              `json:"id" db:"id"`
	Name       string             `json:"name" db:"name"`
	Host       string             `json:"host" db:"host"`
	SSHUser    string             `json:"ssh_user" db:"ssh_user"`
	SSHPort    int                `json:"ssh_port" db:"ssh_port"`
	SSHPass    string             `json:"-" db:"ssh_pass"`
	SSHKey     string             `json:"-" db:"ssh_key"`
	Protocols  map[string]any     `json:"protocols" db:"protocols"`
	CreatedAt  time.Time          `json:"created_at" db:"created_at"`
	Status     ReachabilityStatus `json:"status,omitempty"`
	ServerInfo map[string]any     `json:"server_info,omitempty"`
}

// Reachable returns true if the server status is not offline.
func (s Server) Reachable() bool {
	return s.Status != ReachabilityOffline
}

// User represents an authenticated dashboard user or VPN client subscriber.
type User struct {
	ID                     string               `json:"id" db:"id"`
	Username               string               `json:"username" db:"username"`
	Email                  *string              `json:"email,omitempty" db:"email"`
	TelegramID             *string              `json:"telegramId,omitempty" db:"telegramId"`
	Description            *string              `json:"description,omitempty" db:"description"`
	PasswordHash           string               `json:"-" db:"password_hash"`
	Role                   UserRole             `json:"role" db:"role"`
	Enabled                bool                 `json:"enabled" db:"enabled"`
	TrafficLimit           int64                `json:"traffic_limit" db:"traffic_limit"`
	TrafficUsed            int64                `json:"traffic_used" db:"traffic_used"`
	TrafficTotal           int64                `json:"traffic_total" db:"traffic_total"`
	TrafficTotalRx         int64                `json:"traffic_total_rx" db:"traffic_total_rx"`
	TrafficTotalTx         int64                `json:"traffic_total_tx" db:"traffic_total_tx"`
	MonthlyRx              int64                `json:"monthly_rx" db:"monthly_rx"`
	MonthlyTx              int64                `json:"monthly_tx" db:"monthly_tx"`
	MonthlyResetAt         *string              `json:"monthly_reset_at,omitempty" db:"monthly_reset_at"`
	TrafficResetStrategy   TrafficResetStrategy `json:"traffic_reset_strategy" db:"traffic_reset_strategy"`
	ShareEnabled           bool                 `json:"share_enabled" db:"share_enabled"`
	ShareToken             *string              `json:"share_token,omitempty" db:"share_token"`
	SharePasswordHash      *string              `json:"-" db:"share_password_hash"`
	CreatedAt              time.Time            `json:"created_at" db:"created_at"`
	LastResetAt            *string              `json:"last_reset_at,omitempty" db:"last_reset_at"`
	ExpirationDate         *time.Time           `json:"expiration_date,omitempty" db:"expiration_date"`
	ExpiresAt              *time.Time           `json:"expires_at,omitempty" db:"expires_at"`
	AWGMimicry             AWGMimicryProfile    `json:"awg_mimicry" db:"awg_mimicry"`
	PasswordChangeRequired bool                 `json:"password_change_required" db:"password_change_required"`
	SessionVersion         int                  `json:"session_version" db:"session_version"`
	Limits                 map[string]any       `json:"limits,omitempty" db:"limits"`
}

// UserConnection binds a User to a specific protocol on a Server.
type UserConnection struct {
	ID             string            `json:"id" db:"id"`
	UserID         string            `json:"user_id" db:"user_id"`
	ServerID       int64             `json:"server_id" db:"server_id"`
	ServerName     string            `json:"server_name,omitempty" db:"-"`
	Protocol       string            `json:"protocol" db:"protocol"`
	ClientID       string            `json:"client_id" db:"client_id"`
	Name           string            `json:"name" db:"name"`
	AWGMimicry     AWGMimicryProfile `json:"awg_mimicry" db:"awg_mimicry"`
	ClientParams   map[string]any    `json:"client_params,omitempty" db:"client_params"`
	LastRx         int64             `json:"last_rx" db:"last_rx"`
	LastTx         int64             `json:"last_tx" db:"last_tx"`
	TrafficDeltaRx int64             `json:"traffic_delta_rx" db:"traffic_delta_rx"`
	TrafficDeltaTx int64             `json:"traffic_delta_tx" db:"traffic_delta_tx"`
	TrafficTotalRx int64             `json:"traffic_total_rx" db:"traffic_total_rx"`
	TrafficTotalTx int64             `json:"traffic_total_tx" db:"traffic_total_tx"`
	TrafficTotal   int64             `json:"traffic_total" db:"traffic_total"`
	CreatedAt      time.Time         `json:"created_at" db:"created_at"`
}

// Setting represents a generic key-value configuration entry.
type Setting struct {
	Key   string `json:"key" db:"key"`
	Value string `json:"value" db:"value"`
}

// KnownHost stores verified SSH host public key fingerprints.
type KnownHost struct {
	ServerID    int64     `json:"server_id" db:"server_id"`
	Fingerprint string    `json:"fingerprint" db:"fingerprint"`
	FirstSeen   time.Time `json:"first_seen" db:"first_seen"`
}

// LeaderboardEntry represents a ranked user in the traffic leaderboard.
type LeaderboardEntry struct {
	Rank     int    `json:"rank"`
	Username string `json:"username"`
	Download int64  `json:"download"`
	Upload   int64  `json:"upload"`
	Total    int64  `json:"total"`
}

// LeaderboardSnapshot stores historical user traffic stats.
type LeaderboardSnapshot struct {
	ID         int64     `json:"id" db:"id"`
	Year       int       `json:"year" db:"year"`
	Month      int       `json:"month" db:"month"`
	Username   string    `json:"username" db:"username"`
	Rank       int       `json:"rank" db:"rank"`
	Download   int64     `json:"download" db:"download"`
	Upload     int64     `json:"upload" db:"upload"`
	Total      int64     `json:"total" db:"total"`
	SnapshotAt time.Time `json:"snapshot_at" db:"snapshot_at"`
}

// ConnectionLogEntry tracks timestamps of client connection creations for rate limiting.
type ConnectionLogEntry struct {
	ID        int64     `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Backend tunnel statuses and disable reasons.
const (
	TunnelStatusConnecting = "connecting"
	TunnelStatusActive     = "active"
	TunnelStatusDegraded   = "degraded"
	TunnelStatusDisabled   = "disabled"

	DisableReasonNone   = ""
	DisableReasonHealth = "health"
	DisableReasonAdmin  = "admin"
)

// VLESSRealityParams holds connection and cryptographic parameters for VLESS+REALITY backends.
type VLESSRealityParams struct {
	UUID          string `json:"uuid"`
	Flow          string `json:"flow"`
	PublicKey     string `json:"public_key"`
	ShortID       string `json:"short_id"`
	ServerName    string `json:"server_name"`
	Fingerprint   string `json:"fingerprint"`
	Transport     string `json:"transport"`
	EngineProfile string `json:"engine_profile,omitempty"`
}

// NaiveProxyParams holds connection and authentication parameters for NaiveProxy backends.
type NaiveProxyParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	EnableH3 bool   `json:"enable_h3"`
}

// BackendTunnel represents an in-process tunnel to a backend VPN server.
type BackendTunnel struct {
	ID            int64  `json:"id" db:"id"`
	ServerID      int64  `json:"server_id" db:"server_id"`
	InterfaceName string `json:"interface_name" db:"interface_name"`
	PublicKey     string `json:"public_key" db:"public_key"`
	PrivateKey    string `json:"-" db:"private_key"` // Encrypted at rest
	// ProbePrivateKey is the dedicated health-probe client key, distinct from
	// PrivateKey (the data device identity). Sharing one key made the backend
	// roam the peer's return endpoint to whichever socket sent last (issue #43).
	ProbePrivateKey   string          `json:"-" db:"probe_private_key"` // Encrypted at rest
	Endpoint          string          `json:"endpoint" db:"endpoint"`
	Enabled           bool            `json:"enabled" db:"enabled"` // administrative intent; independent from runtime health
	Status            string          `json:"status" db:"status"`   // runtime health: connecting, active, degraded, disabled
	DisableReason     string          `json:"disable_reason,omitempty" db:"disable_reason"`
	StateVersion      int64           `json:"state_version" db:"state_version"`
	LastHealthCheck   *time.Time      `json:"last_health_check,omitempty" db:"last_health_check"`
	LatencyMS         int64           `json:"latency_ms" db:"latency_ms"`
	ActiveConnections int             `json:"active_connections" db:"active_connections"`
	CreatedAt         time.Time       `json:"created_at" db:"created_at"`
	Protocol          string          `json:"protocol" db:"protocol"`
	ProtocolParams    json.RawMessage `json:"-" db:"protocol_params"`
}

func NormalizeTunnelProtocol(proto string) string {
	if proto == "" {
		return ProtocolAWG
	}
	return NormalizeProtocol(proto)
}

func normalizeTunnelProtocol(proto string) string {
	return NormalizeTunnelProtocol(proto)
}

// IsSupportedBackendProtocol reports whether a backend tunnel protocol is supported
// by the multi-protocol orchestrator (AWG, VLESS, or Naive).
func IsSupportedBackendProtocol(proto string) bool {
	switch NormalizeTunnelProtocol(proto) {
	case ProtocolAWG, ProtocolVLESS, ProtocolNaive:
		return true
	default:
		return false
	}
}

// FilterTunnelsByProtocol returns a new slice containing only non-nil tunnels
// whose effective normalized protocol matches the target protocol family.
// It never mutates the input slice or tunnel objects.
func FilterTunnelsByProtocol(tunnels []*BackendTunnel, proto string) []*BackendTunnel {
	target := NormalizeTunnelProtocol(proto)
	result := make([]*BackendTunnel, 0, len(tunnels))
	for _, t := range tunnels {
		if t != nil && NormalizeTunnelProtocol(t.Protocol) == target {
			result = append(result, t)
		}
	}
	return result
}

func equalJSON(a, b json.RawMessage) bool {
	if bytes.Equal(a, b) {
		return true
	}
	if len(a) == 0 || len(b) == 0 {
		return len(a) == 0 && len(b) == 0
	}
	var valA, valB any
	if err := json.Unmarshal(a, &valA); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &valB); err != nil {
		return false
	}
	return reflect.DeepEqual(valA, valB)
}

// SameTunnelIdentity reports whether two backend tunnels have identical immutable
// configuration and cryptographic identity (ID, endpoint, protocol, and key material / protocol params).
// Runtime health (Status, StateVersion, LatencyMS, etc.) and administrative state
// (Enabled, DisableReason) are not part of identity.
func SameTunnelIdentity(a, b *BackendTunnel) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.ID != b.ID || a.Endpoint != b.Endpoint {
		return false
	}
	protoA := normalizeTunnelProtocol(a.Protocol)
	protoB := normalizeTunnelProtocol(b.Protocol)
	if protoA != protoB {
		return false
	}
	if protoA == ProtocolAWG {
		return a.PublicKey == b.PublicKey &&
			a.PrivateKey == b.PrivateKey &&
			a.ProbePrivateKey == b.ProbePrivateKey
	}
	return equalJSON(a.ProtocolParams, b.ProtocolParams)
}

// ParseEndpoint parses an endpoint string (IPv4, bracketed IPv6, or hostname with port)
// into host and port components without splitting on internal IPv6 colons.
func ParseEndpoint(endpoint string) (host, port string, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", "", errors.New("empty endpoint")
	}
	return net.SplitHostPort(endpoint)
}

// FormatEndpoint constructs a host:port endpoint string, ensuring IPv6 literals are
// properly bracketed exactly once without internal colon splitting or double brackets.
func FormatEndpoint(host string, defaultPort int) string {
	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	port := defaultPort
	if h, pStr, err := net.SplitHostPort(host); err == nil && h != "" {
		cleanHost = strings.Trim(strings.TrimSpace(h), "[]")
		if pInt, err := strconv.Atoi(pStr); err == nil && pInt > 0 {
			port = pInt
		}
	}
	return net.JoinHostPort(cleanHost, strconv.Itoa(port))
}

// EndpointHostPort parses the BackendTunnel's endpoint into host and port.
func (t *BackendTunnel) EndpointHostPort() (host, port string, err error) {
	if t == nil {
		return "", "", errors.New("nil backend tunnel")
	}
	return ParseEndpoint(t.Endpoint)
}

// VPNSession tracks an active user connection through the portal AWG endpoint.
//
// vpn_sessions is a table of ACTIVE NEXUS BACKEND-ROUTING SESSIONS, not a
// peer registry: a row exists only while this portal process is routing that
// peer's traffic to a backend. It does NOT track configured upstream peers
// (durable: user_connections) or AWG transport/crypto sessions (upstream,
// invisible to Nexus). A configured peer with no row is the healthy idle
// state — its next plaintext packet lazily creates a fresh session
// (EnsureBackendSessionForIngress) — and every row dies with the process
// (InvalidateVPNSessionsForRestart) or with the peer's idle reap.
type VPNSession struct {
	ID              string    `json:"id" db:"id"`
	UserID          string    `json:"user_id" db:"user_id"`
	BackendTunnelID int64     `json:"backend_tunnel_id" db:"backend_tunnel_id"`
	PeerPublicKey   string    `json:"peer_public_key" db:"peer_public_key"`
	AssignedIP      string    `json:"assigned_ip" db:"assigned_ip"`
	ConnectedAt     time.Time `json:"connected_at" db:"connected_at"`
	LastSeen        time.Time `json:"last_seen" db:"last_seen"`
	RxBytes         int64     `json:"rx_bytes" db:"rx_bytes"`
	TxBytes         int64     `json:"tx_bytes" db:"tx_bytes"`
	Status          string    `json:"status" db:"status"` // connected, disconnected, draining
	// ConnectionName is the user-facing config name (UserConnection.Name)
	// resolved at admission time. Legacy rows pre-dating the column carry ""
	// and are never backfilled.
	ConnectionName string `json:"connection_name" db:"connection_name"`
	Username       string `json:"username,omitempty" db:"-"`
	ConnectionID   string `json:"connection_id,omitempty" db:"-"`
	// Generation tracks monotonic per-peer admission sequence numbers to prevent
	// out-of-order commits from clobbering newer state.
	Generation uint64 `json:"generation,omitempty" db:"-"`
	// AdmittedVia records which admission path created this session so the
	// idle reaper can select the session's teardown class: "ingress" sessions
	// are reaped routing-only, while "" (the zero value, untagged / direct admission)
	// uses standard teardown. In-memory state like Generation — vpn_sessions
	// has no column, and rows do not survive a process restart
	// (InvalidateVPNSessionsForRestart), so in-memory provenance is complete.
	AdmittedVia string `json:"admitted_via,omitempty" db:"-"`
	// TimedOutAt records when CheckTimeouts detected that the session exceeded
	// the idle timeout. Used by the session reaper to avoid duplicate counter
	// decrements if periodic reconciliation ran after this timestamp.
	TimedOutAt time.Time `json:"-" db:"-"`
}

// Session admission provenance values for VPNSession.AdmittedVia.
const (
	// SessionAdmissionDirect marks sessions created directly without explicit
	// ingress admission tagging (or legacy untagged sessions). The empty string
	// is the untagged zero value.
	SessionAdmissionDirect = ""
	// SessionAdmissionIngress marks sessions created by the client
	// engine's ingress admission (EnsureBackendSessionForIngress). Their idle reap
	// is routing-only: no endpoint transport prune, no client re-handshake.
	SessionAdmissionIngress = "ingress"
)

// EnrichedVPNSession is an active VPN session with identity joins resolved:
// username from users, backend tunnel and server identity from backend
// tunnels and servers. Read-path only; used by the admin sessions view
// (issue #189).
type EnrichedVPNSession struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	Username        string    `json:"username"`
	ConnectionID    string    `json:"connection_id"`
	BackendTunnelID int64     `json:"backend_tunnel_id"`
	ServerID        int64     `json:"server_id"`
	ServerName      string    `json:"server_name"`
	PeerPublicKey   string    `json:"peer_public_key"`
	AssignedIP      string    `json:"assigned_ip"`
	ConnectedAt     time.Time `json:"connected_at"`
	// LastSeen is the last accounted traffic activity visible via the
	// accountant flush; not transport-level peer liveness (review-2 P2).
	LastSeen time.Time `json:"last_seen"`
	RxBytes  int64     `json:"rx_bytes"`
	TxBytes  int64     `json:"tx_bytes"`
	Status   string    `json:"status"`
	// ConnectionName is the user-facing config name captured at admission;
	// "unknown" when the underlying user_connection row is gone.
	ConnectionName string `json:"connection_name"`
}

// VPNConfig holds runtime configuration for the built-in VPN service.
type VPNConfig struct {
	VPNDataPlaneI1Protocol string                 `json:"vpn_data_plane_i1_protocol,omitempty"`
	Algorithm              LoadBalancingAlgorithm `json:"algorithm"`
	Weights                map[int64]int          `json:"weights"` // server_id -> weight (1-100)
	HealthThresholdMS      int                    `json:"health_threshold_ms"`
	ListenPort             int                    `json:"listen_port"`
	SubnetCIDR             string                 `json:"subnet_cidr"`
	MaxTotalPeers          int                    `json:"max_total_peers"`
	MaxPeersPerBackend     int                    `json:"max_peers_per_backend"`
	AffinityTTLMinutes     int                    `json:"affinity_ttl_minutes,omitempty"`
	MinRebalanceSessions   int                    `json:"min_rebalance_sessions"`       // rebalancer minimum-load gate; default 8 when zero/absent
	ClientQueueSize        int                    `json:"client_queue_size,omitempty"`  // per-peer downstream queue capacity, bounded by the forwarder
	ServerPrivateKey       string                 `json:"server_private_key,omitempty"` // portal endpoint Curve25519 private key (base64), encrypted at rest
	ServerPublicKey        string                 `json:"server_public_key,omitempty"`  // derived public key, safe to expose
	PublicEndpoint         string                 `json:"public_endpoint,omitempty"`    // host or host:port of the panel's public LB entry point
	H1                     HeaderRange            `json:"h1"`
	H2                     HeaderRange            `json:"h2"`
	H3                     HeaderRange            `json:"h3"`
	H4                     HeaderRange            `json:"h4"`
	S1                     int                    `json:"s1"`
	S2                     int                    `json:"s2"`
	S3                     int                    `json:"s3"`
	S4                     int                    `json:"s4"`
	HeaderProtectionKey    string                 `json:"header_protection_key,omitempty"`
	ContentPaddingAddition string                 `json:"content_padding_addition,omitempty"`
	RandomTrailers         bool                   `json:"random_trailers,omitempty"`
	DisableCookies         bool                   `json:"disable_cookies,omitempty"`
	// Multi-protocol backends are unconditionally active out-of-the-box (#661).
	// Retained for backward-compatible JSON serialization.
	EnableMultiProtocolBackends bool `json:"enable_multi_protocol_backends"`
}

// AppearanceSettings holds UI display configuration.
type AppearanceSettings struct {
	Title    string `json:"title"`
	Logo     string `json:"logo"`
	Subtitle string `json:"subtitle"`
	Language string `json:"language"`
}

// CaptchaSettings holds CAPTCHA toggle configuration.
type CaptchaSettings struct {
	Enabled bool `json:"enabled"`
}

// SSLSettings holds custom TLS certificate configuration.
type SSLSettings struct {
	Enabled   bool   `json:"enabled"`
	Domain    string `json:"domain"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
	CertText  string `json:"cert_text"`
	KeyText   string `json:"key_text"`
	PanelPort int    `json:"panel_port"`
}

// ConnectionLimits holds global connection creation rate limits.
type ConnectionLimits struct {
	MaxConnectionsPerUser     int `json:"max_connections_per_user"`
	ConnectionRateLimitCount  int `json:"connection_rate_limit_count"`
	ConnectionRateLimitWindow int `json:"connection_rate_limit_window"`
}

// BackupData represents the complete database dump for backup / restore / data.json migration.
type BackupData struct {
	Servers               []map[string]any `json:"servers"`
	Users                 []map[string]any `json:"users"`
	UserConnections       []map[string]any `json:"user_connections"`
	ConnectionCreationLog []map[string]any `json:"connection_creation_log"`
	KnownHosts            []map[string]any `json:"known_hosts,omitempty"`
	LeaderboardSnapshots  []map[string]any `json:"leaderboard_snapshots,omitempty"`
	AWGIPAllocations      []map[string]any `json:"awg_ip_allocations,omitempty"`
	Settings              map[string]any   `json:"settings"`
}

// SessionData represents authenticated session information stored in signed cookies and request context.
type SessionData struct {
	UserID                 string   `json:"user_id,omitempty"`
	Username               string   `json:"username,omitempty"`
	Role                   UserRole `json:"role,omitempty"`
	PasswordChangeRequired bool     `json:"password_change_required,omitempty"`
	SessionVersion         int      `json:"session_version,omitempty"`
	// CaptchaID is the opaque id of the server-side captcha challenge
	// (issue #84). The answer itself never leaves the server.
	CaptchaID          string          `json:"captcha_id,omitempty"`
	ShareAuthenticated map[string]bool `json:"share_authenticated,omitempty"`
	Extra              map[string]any  `json:"extra,omitempty"`
}

// IsAuthenticated returns true if the session contains a valid user ID.
func (s *SessionData) IsAuthenticated() bool {
	return s != nil && s.UserID != ""
}

// IsAdmin returns true if the session user has admin privileges.
func (s *SessionData) IsAdmin() bool {
	return s != nil && s.Role == RoleAdmin
}

// IsAdminOrSupport returns true if the session user has admin or support privileges.
func (s *SessionData) IsAdminOrSupport() bool {
	return s != nil && s.Role.IsAdminOrSupport()
}

// ToMap converts SessionData to a map for serialization.
func (s *SessionData) ToMap() map[string]any {
	if s == nil {
		return nil
	}
	m := make(map[string]any)
	if s.UserID != "" {
		m["user_id"] = s.UserID
	}
	if s.Username != "" {
		m["username"] = s.Username
	}
	if s.Role != "" {
		m["role"] = string(s.Role)
	}
	if s.PasswordChangeRequired {
		m["password_change_required"] = true
	}
	if s.SessionVersion > 0 {
		m["session_version"] = s.SessionVersion
	}
	if s.CaptchaID != "" {
		m["captcha_id"] = s.CaptchaID
	}
	if len(s.ShareAuthenticated) > 0 {
		m["share_authenticated"] = s.ShareAuthenticated
	}
	for k, v := range s.Extra {
		m[k] = v
	}
	return m
}

// SessionDataFromMap converts a generic map into typed SessionData.
func SessionDataFromMap(m map[string]any) *SessionData {
	if m == nil {
		return nil
	}
	s := &SessionData{
		ShareAuthenticated: make(map[string]bool),
		Extra:              make(map[string]any),
	}
	for k, v := range m {
		switch k {
		case "user_id":
			if str, ok := v.(string); ok {
				s.UserID = str
			}
		case "username":
			if str, ok := v.(string); ok {
				s.Username = str
			}
		case "role":
			if str, ok := v.(string); ok {
				s.Role = UserRole(str)
			}
		case "password_change_required":
			if b, ok := v.(bool); ok {
				s.PasswordChangeRequired = b
			}
		case "session_version":
			switch val := v.(type) {
			case int:
				s.SessionVersion = val
			case float64:
				s.SessionVersion = int(val)
			case int64:
				s.SessionVersion = int(val)
			}
		case "captcha_id":
			if str, ok := v.(string); ok {
				s.CaptchaID = str
			}
		case "share_authenticated":
			if sm, ok := v.(map[string]bool); ok {
				for token, auth := range sm {
					s.ShareAuthenticated[token] = auth
				}
			} else if sm, ok := v.(map[string]any); ok {
				for token, auth := range sm {
					if b, ok := auth.(bool); ok {
						s.ShareAuthenticated[token] = b
					}
				}
			}
		default:
			s.Extra[k] = v
		}
	}
	return s
}
