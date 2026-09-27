// Package preflight validates durable portal AWG identity without repairing it.
// It has no database, device, socket, or IP-allocation side effects.
package preflight

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
	"golang.org/x/crypto/curve25519"
)

// Snapshot contains only persisted input. Never serialize it into diagnostics:
// Config and ClientParams can contain secrets. A reader must obtain one consistent snapshot.
type Snapshot struct {
	Config      string
	Connections []Connection
}

// Connection preserves the raw durable identity and parameters for one row.
type Connection struct {
	ID, UserID, Protocol, PublicKey, ClientParams string
	ServerID                                      int64
	User                                          *User
}

// User contains the same eligibility inputs used by the portal authenticator.
// Dates remain raw so malformed persisted values cannot silently become unlimited.
type User struct {
	Enabled                   bool
	TrafficLimit, TrafficUsed int64
	ExpiresAt, ExpirationDate string
}

// Problem is a stable reason code and a diagnostic without secret input values.
type Problem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ConnectionResult records whether a durable row is valid, excluded, or invalid.
type ConnectionResult struct {
	ConnectionID string    `json:"connection_id"`
	UserID       string    `json:"user_id"`
	Status       string    `json:"status"` // valid, excluded, or invalid
	Problems     []Problem `json:"problems,omitempty"`
}

// Peer is a candidate definition, not an authorization cache. Eligibility must
// be rechecked at activation and runtime; preflight cannot authorize future traffic.
type Peer struct {
	ConnectionID string `json:"connection_id"`
	UserID       string `json:"user_id"`
	PublicKey    string `json:"public_key"` // canonical base64 identity
	AllowedIP    string `json:"allowed_ip"` // unique IPv4 /32
}

// UAPI returns only public peer configuration. It never includes private keys.
func (p Peer) UAPI() string {
	key, err := publicKey(p.PublicKey)
	ip, ipErr := netip.ParsePrefix(p.AllowedIP)
	if err != nil || ipErr != nil || !ip.Addr().Is4() || ip.Bits() != 32 {
		return ""
	}
	return "public_key=" + hex.EncodeToString(key) + "\nreplace_allowed_ips=true\nallowed_ip=" + p.AllowedIP + "\n"
}

// Report describes database readiness and candidate peers at CheckedAt.
type Report struct {
	Ready          bool               `json:"ready"`
	CheckedAt      time.Time          `json:"checked_at"`
	PortalIdentity bool               `json:"portal_identity_verified"`
	Problems       []Problem          `json:"problems,omitempty"`
	Connections    []ConnectionResult `json:"connections"`
	Peers          []Peer             `json:"peers"`
}

// Validate audits a snapshot at a caller-supplied time. Ready means the durable
// inputs pass preflight, not that wire compatibility or production cutover is approved.
// Invalid rows block readiness; deliberately disabled/expired/quota-limited and
// quarantined rows remain excluded. No repair or normalization is persisted.
func Validate(snapshot Snapshot, secret string, now time.Time) Report {
	r := Report{Ready: true, CheckedAt: now.UTC(), Connections: []ConnectionResult{}, Peers: []Peer{}}
	var cfg models.VPNConfig
	if err := json.Unmarshal([]byte(snapshot.Config), &cfg); err != nil || snapshot.Config == "" || bytes.Equal(bytes.TrimSpace([]byte(snapshot.Config)), []byte("null")) {
		r.Problems = append(r.Problems, Problem{"invalid_vpn_config", "Persisted vpn_config must be a JSON object."})
	} else {
		r.PortalIdentity = validateIdentity(cfg, secret, &r)
	}
	subnet, err := netip.ParsePrefix(cfg.SubnetCIDR)
	if err != nil || !subnet.Addr().Is4() || subnet.Bits() > 30 {
		r.Problems = append(r.Problems, Problem{"invalid_subnet", "Persisted portal subnet must be IPv4 with space for network, gateway, broadcast, and clients."})
		subnet = netip.Prefix{}
	} else {
		subnet = subnet.Masked()
	}
	if cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
		r.Problems = append(r.Problems, Problem{"invalid_listen_port", "Persisted listener port must be between 1 and 65535; preflight does not choose defaults."})
	}

	connections := append([]Connection(nil), snapshot.Connections...)
	sort.Slice(connections, func(i, j int) bool { return connections[i].ID < connections[j].ID })
	keys, ips := map[string][]int{}, map[string][]int{}
	candidates := map[int]Peer{}
	for _, c := range connections {
		if c.ServerID != 0 || models.NormalizeProtocol(c.Protocol) != "awg" {
			continue
		}
		row, peer := validateConnection(c, subnet, now)
		if row.Status != "excluded" && c.PublicKey == cfg.ServerPublicKey {
			row.Status = "invalid"
			row.Problems = append(row.Problems, Problem{"peer_is_portal", "A client peer cannot use the portal's own public key."})
		}
		idx := len(r.Connections)
		r.Connections = append(r.Connections, row)
		if row.Status == "excluded" {
			continue
		}
		if _, err := publicKey(c.PublicKey); err == nil {
			keys[c.PublicKey] = append(keys[c.PublicKey], idx)
		}
		if ip, err := netip.ParsePrefix(peer.AllowedIP); err == nil && ip.Addr().Is4() {
			ips[ip.Addr().String()] = append(ips[ip.Addr().String()], idx)
		}
		candidates[idx] = peer
	}
	markDuplicates := func(groups map[string][]int, code, message string) {
		for _, indices := range groups {
			if len(indices) < 2 {
				continue
			}
			for _, i := range indices {
				r.Connections[i].Status = "invalid"
				r.Connections[i].Problems = append(r.Connections[i].Problems, Problem{code, message})
			}
		}
	}
	markDuplicates(keys, "duplicate_public_key", "Multiple active connections claim this public key; all claimants are excluded.")
	markDuplicates(ips, "duplicate_assigned_ip", "Multiple active connections claim this IPv4 address; all claimants are excluded.")
	for i, row := range r.Connections {
		if row.Status == "invalid" {
			r.Ready = false
		} else if row.Status == "valid" {
			r.Peers = append(r.Peers, candidates[i])
		}
	}
	if len(r.Problems) > 0 {
		r.Ready = false
		// Without a verified portal identity/subnet no peer set is installable.
		r.Peers = []Peer{}
	}
	return r
}

func validateConnection(c Connection, subnet netip.Prefix, now time.Time) (ConnectionResult, Peer) {
	row := ConnectionResult{ConnectionID: c.ID, UserID: c.UserID, Status: "valid"}
	add := func(code, message string) { row.Problems = append(row.Problems, Problem{code, message}) }
	userExcluded := validateUser(c.User, now, &row)
	params, quarantined := readParams(c.ClientParams, &row)
	if userExcluded || quarantined {
		row.Status = "excluded"
		return row, Peer{}
	}
	key, keyErr := publicKey(c.PublicKey)
	if keyErr != nil {
		add("invalid_public_key", "client_id must be a canonical base64 32-byte usable Curve25519 public key.")
	}
	var address string
	_ = json.Unmarshal(params["assigned_ip"], &address)
	ip, ipErr := netip.ParseAddr(address)
	if ipErr != nil || !ip.Is4() {
		add("invalid_assigned_ip", "assigned_ip must be a persisted IPv4 address, without a prefix.")
	} else if subnet.IsValid() {
		if !subnet.Contains(ip) {
			add("ip_outside_subnet", "assigned_ip is outside the portal subnet.")
		} else if reserved(ip, subnet) {
			add("reserved_ip", "assigned_ip is the network, gateway, or broadcast address.")
		}
	}
	// Portal-generated configs retain this key for lossless regeneration.
	var private string
	_ = json.Unmarshal(params["client_private_key"], &private)
	priv, privErr := decodeKey(private)
	if privErr != nil || allZero(priv) {
		add("invalid_client_private_key", "Persisted client private key is missing or invalid; preflight will not regenerate it.")
	} else if keyErr == nil {
		derived, _ := curve25519.X25519(priv, curve25519.Basepoint)
		if !bytes.Equal(derived, key) {
			add("client_identity_mismatch", "Persisted client private key does not match client_id.")
		}
	}
	if len(row.Problems) > 0 {
		row.Status = "invalid"
	}
	return row, Peer{c.ID, c.UserID, c.PublicKey, address + "/32"}
}

func validateUser(user *User, now time.Time, row *ConnectionResult) bool {
	add := func(code, message string) { row.Problems = append(row.Problems, Problem{code, message}) }
	excluded := false
	if user == nil {
		add("missing_user", "Connection owner does not exist.")
	} else {
		if !user.Enabled {
			excluded = true
			add("user_disabled", "Owner is disabled; do not install this peer.")
		}
		for _, date := range []string{user.ExpiresAt, user.ExpirationDate} {
			if date == "" {
				continue
			}
			expires, ok := parseDate(date)
			if !ok {
				add("invalid_expiry", "Owner has a malformed expiration date.")
			} else if !expires.IsZero() && now.After(expires) {
				excluded = true
				add("user_expired", "Owner is expired; do not install this peer.")
			}
		}
		if user.TrafficLimit > 0 && user.TrafficUsed >= user.TrafficLimit {
			excluded = true
			add("quota_exhausted", "Owner's traffic quota is exhausted; do not install this peer.")
		}
	}
	return excluded
}

func readParams(rawParams string, row *ConnectionResult) (map[string]json.RawMessage, bool) {
	add := func(code, message string) { row.Problems = append(row.Problems, Problem{code, message}) }
	excluded := false
	var params map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawParams), &params); err != nil || params == nil {
		add("invalid_client_params", "client_params must be a JSON object.")
	}
	if raw, ok := params["config_regeneration_required"]; ok {
		var flag bool
		if string(raw) == "null" || json.Unmarshal(raw, &flag) != nil {
			add("invalid_quarantine_flag", "config_regeneration_required must be a boolean.")
		} else if flag {
			excluded = true
			add("config_regeneration_required", "Existing regeneration quarantine is retained; no repair is attempted.")
		}
	}
	if raw, ok := params["quarantined_ip_collision"]; ok && string(raw) != "null" && string(raw) != `""` {
		excluded = true
		add("quarantined_ip_collision", "Existing IP-collision quarantine is retained; no repair is attempted.")
	}
	return params, excluded
}

func validateIdentity(cfg models.VPNConfig, secret string, r *Report) bool {
	plain, err := security.DecryptCredential(cfg.ServerPrivateKey, secret)
	if err != nil {
		r.Problems = append(r.Problems, Problem{"portal_key_decryption_failed", "Cannot decrypt persisted portal private key with the supplied SECRET_KEY."})
		return false
	}
	private, err := decodeKey(plain)
	if err != nil || allZero(private) {
		r.Problems = append(r.Problems, Problem{"invalid_portal_private_key", "Persisted portal private key must decrypt to a nonzero 32-byte base64 key."})
		return false
	}
	public, err := publicKey(cfg.ServerPublicKey)
	derived, _ := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil || !bytes.Equal(derived, public) {
		r.Problems = append(r.Problems, Problem{"portal_identity_mismatch", "Derived portal public key does not match persisted server_public_key."})
		return false
	}
	return true
}

func decodeKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != value {
		return nil, base64.CorruptInputError(0)
	}
	return key, nil
}

func publicKey(value string) ([]byte, error) {
	key, err := decodeKey(value)
	if err != nil {
		return nil, err
	}
	// X25519 rejects low-order points. This fixed validation scalar is not a secret.
	var scalar [32]byte
	scalar[0] = 1
	if _, err := curve25519.X25519(scalar[:], key); err != nil {
		return nil, err
	}
	return key, nil
}

func allZero(key []byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}

func reserved(ip netip.Addr, subnet netip.Prefix) bool {
	network := subnet.Addr().As4()
	address := ip.As4()
	n := binary.BigEndian.Uint32(network[:])
	a := binary.BigEndian.Uint32(address[:])
	broadcast := n | (^uint32(0) >> subnet.Bits())
	return a == n || a == n+1 || a == broadcast
}

func parseDate(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
