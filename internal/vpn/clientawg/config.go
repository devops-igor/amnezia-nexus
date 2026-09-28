// Package clientawg owns the client-facing upstream AWG device and its plaintext
// boundary. It does not select backends or implement any AWG protocol state.
package clientawg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"golang.org/x/crypto/curve25519"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// Parameters are the persisted portal obfuscation parameters. Empty H values in
// an explicitly constructed Config select upstream's standard headers (1..4).
type Parameters struct {
	H1, H2, H3, H4         string
	S1, S2, S3, S4         int
	HeaderProtectionKey    string `json:"-"`
	ContentPaddingAddition string
	RandomTrailers         bool
	DisableCookies         bool
}

// Peer authorizes exactly one public identity and one assigned IPv4 address.
// Keys use canonical standard base64; broad prefixes are deliberately forbidden.
type Peer struct {
	PublicKey string
	AllowedIP netip.Prefix
}

// Config is a complete immutable startup snapshot. ListenPort zero requests an
// ephemeral port. PrivateKey and PublicKey must be the matching persisted pair.
type Config struct {
	PrivateKey string `json:"-"`
	PublicKey  string
	ListenPort int
	TUN        virtualtun.Config
	Parameters Parameters
	Peers      []Peer
}

// LoadConfig reads existing identity and settings without repairing or
// writing them. The persisted snapshot must already be complete and
// consistent: a missing private key, a key that neither decrypts nor
// canonically decodes, and any key not deriving the recorded public key
// are rejected with fail-closed errors. Legacy plaintext private keys are
// accepted only when they strictly validate against the stored public key.
// The random_trailers and disable_cookies fields must be JSON booleans;
// any other JSON type is rejected instead of coerced. Missing identities
// are never generated.
func LoadConfig(ctx context.Context, db *database.DB, tunConfig virtualtun.Config, peers []Peer) (Config, error) {
	if db == nil {
		return Config{}, errors.New("clientawg: nil configuration database")
	}
	raw, found, err := db.GetSettingRaw(ctx, "vpn_config")
	if err != nil || !found || !raw.Valid || strings.TrimSpace(raw.String) == "null" {
		return Config{}, errors.New("clientawg: cannot load persisted VPN configuration")
	}
	// Read the stored snapshot directly: GetVPNConfig fills missing port and
	// subnet defaults, which would conceal an incomplete migration snapshot.
	// Flags are decoded through pointers so a present-but-non-boolean JSON
	// type (string/number/object) fails unmarshalling instead of being
	// silently coerced; an absent or null field decodes as nil and stays
	// false. models.VPNConfig deliberately does not carry these fields.
	var persisted struct {
		models.VPNConfig
		RandomTrailers *bool `json:"random_trailers"`
		DisableCookies *bool `json:"disable_cookies"`
	}
	if err := json.Unmarshal([]byte(raw.String), &persisted); err != nil {
		return Config{}, errors.New("clientawg: invalid persisted VPN configuration")
	}
	if persisted.ListenPort < 1 {
		return Config{}, errors.New("clientawg: persisted listen port is missing or invalid")
	}
	// Fail-closed identity resolution. A missing private key is rejected
	// outright. Otherwise decrypt it; only when decryption fails may a
	// legacy PLAINTEXT key be used, and even then only when it canonically
	// decodes. Derivation against the recorded public key happens once,
	// below, for both paths.
	if persisted.ServerPrivateKey == "" {
		return Config{}, errors.New("clientawg: portal public key has no private key")
	}
	private, err := security.DecryptCredential(persisted.ServerPrivateKey, db.SecretKey())
	if err != nil {
		if _, decodeErr := decodeKey(persisted.ServerPrivateKey); decodeErr != nil {
			return Config{}, errors.New("clientawg: invalid portal private key in vpn config")
		}
		private = persisted.ServerPrivateKey
	}
	// Derive from the decoded 32 raw bytes, never from the base64 text.
	rawPrivate, err := decodeKey(private)
	if err != nil {
		return Config{}, errors.New("clientawg: invalid portal private key in vpn config")
	}
	public, err := curve25519.X25519(rawPrivate, curve25519.Basepoint)
	if err != nil {
		return Config{}, errors.New("clientawg: invalid portal private key in vpn config")
	}
	// Exact string compare is safe: decodeKey has already proven the
	// private key canonical, and the stored public key must be canonical
	// base64-32 to have survived validate() on any prior accepted load.
	if base64.StdEncoding.EncodeToString(public) != persisted.ServerPublicKey {
		return Config{}, errors.New("clientawg: portal private key does not match stored public key")
	}
	cfg := Config{
		PrivateKey: private, PublicKey: persisted.ServerPublicKey, ListenPort: persisted.ListenPort,
		TUN: tunConfig, Peers: append([]Peer(nil), peers...),
		Parameters: Parameters{
			H1: persisted.H1.String(), H2: persisted.H2.String(), H3: persisted.H3.String(), H4: persisted.H4.String(),
			S1: persisted.S1, S2: persisted.S2, S3: persisted.S3, S4: persisted.S4,
			HeaderProtectionKey: persisted.HeaderProtectionKey, ContentPaddingAddition: persisted.ContentPaddingAddition,
			// Absent or null flag fields decode as false; a present
			// non-boolean type already failed unmarshalling above.
			RandomTrailers: persisted.RandomTrailers != nil && *persisted.RandomTrailers,
			DisableCookies: persisted.DisableCookies != nil && *persisted.DisableCookies,
		},
	}
	// Preserve the existing renderer's effective meaning of legacy boolean
	// padding aliases: "true"/"yes"/"1" -> "16-64", "false"/"0" -> "".
	// This changes no stored setting or client configuration.
	switch cfg.Parameters.ContentPaddingAddition {
	case "true", "yes", "1":
		cfg.Parameters.ContentPaddingAddition = "16-64"
	case "false", "0":
		cfg.Parameters.ContentPaddingAddition = ""
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func decodeKey(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("key must be canonical base64 encoding of 32 bytes")
	}
	var nonzero byte
	for _, b := range raw {
		nonzero |= b
	}
	if nonzero == 0 {
		return nil, errors.New("zero key is forbidden")
	}
	return raw, nil
}

func (c Config) validate() error {
	private, err := decodeKey(c.PrivateKey)
	if err != nil {
		return fmt.Errorf("clientawg: invalid portal private key: %w", err)
	}
	public, err := decodeKey(c.PublicKey)
	if err != nil {
		return fmt.Errorf("clientawg: invalid portal public key: %w", err)
	}
	derived, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil || string(public) != string(derived) {
		return errors.New("clientawg: portal keypair does not match")
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return errors.New("clientawg: invalid listen port")
	}
	if c.TUN.MTU < 1 || c.TUN.MTU > 65535 || c.TUN.InboundCapacity < 0 || c.TUN.OutboundCapacity < 0 || c.TUN.BatchSize < 0 {
		return errors.New("clientawg: invalid TUN configuration")
	}
	if err := c.Parameters.validate(); err != nil {
		return err
	}
	// Bound complete datagrams, not just uint16 UAPI fields. The engine's
	// fixed receive buffers and UDP payload limit must fit every configured
	// handshake and the largest TUN packet with encryption overhead/padding.
	const maxDatagram = 65507
	sizes := []int{device.MessageInitiationSize, device.MessageResponseSize, device.MessageCookieReplySize}
	for i, padding := range []int{c.Parameters.S1, c.Parameters.S2, c.Parameters.S3} {
		if padding+sizes[i] > maxDatagram {
			return fmt.Errorf("clientawg: S%d exceeds datagram capacity", i+1)
		}
	}
	trailing := device.PaddingMultiple - 1
	if c.Parameters.ContentPaddingAddition != "" {
		var addition device.UintRange
		_ = addition.FromString(c.Parameters.ContentPaddingAddition)
		trailing = max(trailing, int(addition.Hi()))
	}
	if c.TUN.MTU+c.Parameters.S4+device.MinMessageSize+trailing > maxDatagram {
		return errors.New("clientawg: MTU and transport padding exceed datagram capacity")
	}
	keys := make(map[string]bool, len(c.Peers))
	ips := make(map[netip.Prefix]bool, len(c.Peers))
	for i, peer := range c.Peers {
		if err := validatePeer(peer, c.PublicKey); err != nil {
			return fmt.Errorf("clientawg: peer %d: %w", i, err)
		}
		if keys[peer.PublicKey] {
			return fmt.Errorf("clientawg: peer %d: duplicate public key", i)
		}
		if ips[peer.AllowedIP] {
			return fmt.Errorf("clientawg: peer %d: duplicate assigned IP", i)
		}
		keys[peer.PublicKey], ips[peer.AllowedIP] = true, true
	}
	return nil
}

func validatePeer(p Peer, portalKey string) error {
	key, err := decodeKey(p.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	if p.PublicKey == portalKey {
		return errors.New("peer cannot use portal public key")
	}
	// Reject low-order points that cannot participate in a Curve25519 handshake.
	scalar := [32]byte{9}
	if _, err := curve25519.X25519(scalar[:], key); err != nil {
		return errors.New("invalid peer public key")
	}
	if !p.AllowedIP.IsValid() || !p.AllowedIP.Addr().Is4() || p.AllowedIP.Bits() != 32 || !p.AllowedIP.Addr().IsGlobalUnicast() {
		return errors.New("assigned IP must be a unicast IPv4 /32")
	}
	return nil
}

func (p Parameters) validate() error {
	headers := []string{p.H1, p.H2, p.H3, p.H4}
	ranges := make([]device.UintRange, len(headers))
	for i, header := range headers {
		if header == "" {
			header = strconv.Itoa(i + 1)
		}
		if err := ranges[i].FromString(header); err != nil {
			return fmt.Errorf("clientawg: invalid H%d", i+1)
		}
		if ranges[i].Lo() == 0 && ranges[i].Hi() == ^uint32(0) {
			return fmt.Errorf("clientawg: H%d range is too broad", i+1)
		}
		for j := 0; j < i; j++ {
			if ranges[i].Overlap(ranges[j]) {
				return errors.New("clientawg: header ranges overlap")
			}
		}
	}
	var hp device.HeaderCipherKey
	if p.HeaderProtectionKey != "" {
		raw, err := decodeKey(p.HeaderProtectionKey)
		if err != nil {
			return errors.New("clientawg: invalid header protection key")
		}
		if err := hp.FromHex(hex.EncodeToString(raw)); err != nil {
			return errors.New("clientawg: invalid header protection key")
		}
	}
	for i, padding := range []int{p.S1, p.S2, p.S3, p.S4} {
		if padding < 0 || padding > 65535 {
			return fmt.Errorf("clientawg: invalid S%d", i+1)
		}
		if !hp.IsZero() && padding < device.HeaderCipherNonceSize {
			return fmt.Errorf("clientawg: S%d cannot accommodate header protection", i+1)
		}
	}
	if p.ContentPaddingAddition != "" {
		var padding device.UintRange
		if err := padding.FromString(p.ContentPaddingAddition); err != nil || padding.Hi() > 65535 {
			return errors.New("clientawg: invalid content padding addition")
		}
	}
	return nil
}

func (c Config) ipc() string {
	private, _ := decodeKey(c.PrivateKey) // validated by NewDevice before resource creation
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\n", hex.EncodeToString(private), c.ListenPort)
	for i, h := range []string{c.Parameters.H1, c.Parameters.H2, c.Parameters.H3, c.Parameters.H4} {
		if h != "" {
			fmt.Fprintf(&b, "h%d=%s\n", i+1, h)
		}
	}
	for i, s := range []int{c.Parameters.S1, c.Parameters.S2, c.Parameters.S3, c.Parameters.S4} {
		fmt.Fprintf(&b, "s%d=%d\n", i+1, s)
	}
	if c.Parameters.HeaderProtectionKey != "" {
		raw, _ := decodeKey(c.Parameters.HeaderProtectionKey)
		fmt.Fprintf(&b, "header_protection_key=%s\n", hex.EncodeToString(raw))
	}
	if c.Parameters.ContentPaddingAddition != "" {
		fmt.Fprintf(&b, "content_padding_addition=%s\n", c.Parameters.ContentPaddingAddition)
	}
	fmt.Fprintf(&b, "random_trailers=%t\ndisable_cookies=%t\n", c.Parameters.RandomTrailers, c.Parameters.DisableCookies)
	for _, p := range c.Peers {
		b.WriteString(peerIPC(p))
	}
	return b.String()
}

func peerIPC(p Peer) string {
	key, _ := decodeKey(p.PublicKey)
	return "public_key=" + hex.EncodeToString(key) + "\nreplace_allowed_ips=true\nallowed_ip=" + p.AllowedIP.String() + "\n"
}
