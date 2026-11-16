package policy

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// This file defines the operator-facing upstream DNS configuration that the
// policy resolver feeds on (issue #824) and the pure validation the admin API
// applies before anything is persisted.
//
// Design constraints:
//   - A configuration entry is explicit: address, port and transport. The only
//     port default is the transport's own well-known one (853 for DoT), applied
//     before the record is written, so a stored entry always states the port it
//     dials and can never look like it targets one transport while it actually
//     targets another.
//   - The plain and DoT transports are implemented. An entry configured for DoH
//     is REJECTED here rather than accepted and quietly carried in plaintext: a
//     silent downgrade would be worse than an unimplemented option. The
//     transport field itself is part of the persisted contract, so the last
//     encrypted transport slots in without a schema change.
//   - The default pair lives in exactly one place (DefaultUpstreams). The
//     resolver's fallback and the DNS servers a generated client configuration
//     pushes both derive from it, so the two cannot drift apart again.
//   - Validation rejects loopback, multicast, unspecified and malformed input
//     before a record is written, so a rejected save cannot leave a partial
//     configuration behind.

// UpstreamTransport selects how the policy resolver carries a query to one
// upstream entry.
type UpstreamTransport string

const (
	// TransportPlain is DNS over UDP with TCP fallback on truncation.
	TransportPlain UpstreamTransport = "plain"
	// TransportDoT is DNS over TLS (RFC 7858). The resolver implements it with
	// the system trust store, chain and name verification, and an optional SPKI
	// pin; it never carries the query in plaintext.
	TransportDoT UpstreamTransport = "dot"
	// TransportDoH is DNS over HTTPS. Not implemented in this build, so it is
	// rejected rather than approximated.
	TransportDoH UpstreamTransport = "doh"
)

const (
	// MaxUpstreams bounds the persisted list. The resolver contacts at most one
	// alternate, so a longer list would be stored and never used.
	MaxUpstreams = 3
	// DefaultUpstreamPort is the port the default plain-DNS entries use.
	DefaultUpstreamPort = 53
	// DefaultDoTPort is the port a DoT entry uses when it states none.
	DefaultDoTPort = 853
	// maxUpstreamHostLen is the maximum length of a DNS name in presentation form.
	maxUpstreamHostLen = 253
	// maxUpstreamLabelLen is the maximum length of one DNS name label.
	maxUpstreamLabelLen = 63
)

// ErrUpstreamLoopback marks a loopback entry. The policy resolver allows
// loopback only through an explicit test-only seam, so the sentinel lets that
// seam distinguish "loopback" from "genuinely unusable".
var ErrUpstreamLoopback = errors.New("upstream is loopback")

// ErrUpstreamTransportUnsupported marks a transport this build deliberately
// refuses. Accepting it would mean silently carrying the query in another
// transport, which is exactly the downgrade the contract forbids.
var ErrUpstreamTransportUnsupported = errors.New("upstream transport is not supported in this build")

// Upstream is one persisted recursive-resolver entry.
//
// Address is an IPv4 literal, an IPv6 literal or a hostname. A hostname is
// resolved at dial time by the selected transport, so it stays a plain
// configuration string.
type Upstream struct {
	// Address is the IPv4/IPv6 literal or hostname of the resolver.
	Address string `json:"address"`
	// Port is explicit for plain DNS and defaults to DefaultDoTPort for DoT.
	Port int `json:"port"`
	// Transport is the empty string (plain) or one of the UpstreamTransport
	// values.
	Transport UpstreamTransport `json:"transport,omitempty"`
	// SPKIPin is the optional public-key pin for DoT: the SHA-256 digest of the
	// leaf certificate's SubjectPublicKeyInfo, encoded as standard base64
	// (RFC 4648 section 4, with padding, no line breaks). Empty means no pin.
	// An empty field keeps a slice-1 record valid, and the plain transport never
	// reads it because a pin is only meaningful for an encrypted transport.
	SPKIPin string `json:"spki_pin,omitempty"`
}

// EffectiveTransport reports the transport the entry selects, treating the
// empty value as plain so a minimal entry needs no transport field.
func (u Upstream) EffectiveTransport() UpstreamTransport {
	if u.Transport == "" {
		return TransportPlain
	}
	return u.Transport
}

// EffectivePort reports the port the entry dials, applying the transport's own
// default when the entry leaves it unset. It returns 0 for an entry that has no
// port and no default, which Validate rejects.
func (u Upstream) EffectivePort() int {
	if u.Port != 0 {
		return u.Port
	}
	if u.EffectiveTransport() == TransportDoT {
		return DefaultDoTPort
	}
	return 0
}

// WithDefaultPort returns the entry with its transport default applied when the
// port is unset, so a persisted record states the port it actually dials.
func (u Upstream) WithDefaultPort() Upstream {
	if u.Port == 0 {
		u.Port = u.EffectivePort()
	}
	return u
}

// SPKIPinDigest decodes the configured pin. Validate guarantees that a non-empty
// pin is well formed; callers still see the decode error rather than a silent
// "no pin", because an unverifiable pin must never weaken verification.
func (u Upstream) SPKIPinDigest() ([]byte, error) {
	if u.SPKIPin == "" {
		return nil, nil
	}
	digest, err := base64.StdEncoding.DecodeString(u.SPKIPin)
	if err != nil {
		return nil, fmt.Errorf("SPKI pin is not valid standard base64: %w", err)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("SPKI pin decodes to %d bytes, want a %d-byte SHA-256 digest", len(digest), sha256.Size)
	}
	return digest, nil
}

// HostPort renders the entry as a dial target ("host:port" / "[v6]:port").
func (u Upstream) HostPort() string {
	return net.JoinHostPort(u.Address, strconv.Itoa(u.EffectivePort()))
}

// String renders the entry for errors and operator-facing status.
func (u Upstream) String() string {
	if u.Transport == "" || u.Transport == TransportPlain {
		return u.HostPort()
	}
	return string(u.Transport) + "://" + u.HostPort()
}

// Validate reports whether one entry may be persisted or dialed. Errors are
// specific so the admin API can tell an operator exactly which rule failed.
func (u Upstream) Validate() error {
	if err := u.validateAddress(); err != nil {
		return err
	}
	transport := u.EffectiveTransport()
	switch transport {
	case TransportPlain, TransportDoT:
	case TransportDoH:
		return fmt.Errorf("upstream %q selects transport %q: %w", u.Address, u.Transport, ErrUpstreamTransportUnsupported)
	default:
		return fmt.Errorf("upstream %q has unknown transport %q", u.Address, u.Transport)
	}
	if err := u.validatePort(transport); err != nil {
		return err
	}
	return u.validateSPKIPin(transport)
}

// validatePort enforces an explicit port for plain DNS and the transport default
// for DoT.
func (u Upstream) validatePort(transport UpstreamTransport) error {
	if u.Port == 0 {
		if transport == TransportDoT {
			return nil
		}
		return fmt.Errorf("upstream %q requires an explicit port", u.Address)
	}
	if u.Port < 0 || u.Port > 65535 {
		return fmt.Errorf("upstream %q port %d is outside the valid range 1-65535", u.Address, u.Port)
	}
	return nil
}

// validateSPKIPin rejects a pin the resolver could not verify, and a pin on a
// transport that never presents a certificate.
func (u Upstream) validateSPKIPin(transport UpstreamTransport) error {
	if u.SPKIPin == "" {
		return nil
	}
	if transport != TransportDoT {
		return fmt.Errorf("upstream %q sets an SPKI pin but selects transport %q; a pin is only honored by DNS over TLS", u.Address, transport)
	}
	if _, err := u.SPKIPinDigest(); err != nil {
		return fmt.Errorf("upstream %q: %v", u.Address, err)
	}
	return nil
}

func (u Upstream) validateAddress() error {
	if u.Address == "" {
		return errors.New("upstream address is empty")
	}
	if strings.TrimSpace(u.Address) != u.Address {
		return fmt.Errorf("upstream address %q has leading or trailing whitespace", u.Address)
	}
	if ip, err := netip.ParseAddr(u.Address); err == nil {
		return validateUpstreamIPLiteral(ip)
	}
	// A string that looks like an IP literal but does not parse is malformed,
	// not a hostname: dialing "300.1.1.1" as a name would hide the typo.
	if strings.Contains(u.Address, ":") || isNumericDotted(u.Address) {
		return fmt.Errorf("upstream %q is not a valid IP literal", u.Address)
	}
	if err := validateUpstreamHostname(u.Address); err != nil {
		return fmt.Errorf("upstream %q is not a valid hostname: %v", u.Address, err)
	}
	return nil
}

// validateUpstreamIPLiteral rejects the address classes a resolver may never
// dial: loopback (the host's own stubs), multicast and unspecified.
func validateUpstreamIPLiteral(ip netip.Addr) error {
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("%w: %s", ErrUpstreamLoopback, ip)
	case ip.IsMulticast():
		return fmt.Errorf("upstream %s is multicast", ip)
	case ip.IsUnspecified():
		return fmt.Errorf("upstream %s is unspecified", ip)
	}
	return nil
}

// validateUpstreamHostname applies the DNS presentation rules the resolver
// relies on. "localhost" is refused because it is a loopback name.
func validateUpstreamHostname(host string) error {
	name := strings.TrimSuffix(host, ".")
	if name == "" {
		return errors.New("empty name")
	}
	if len(name) > maxUpstreamHostLen {
		return fmt.Errorf("longer than %d characters", maxUpstreamHostLen)
	}
	if strings.EqualFold(name, "localhost") {
		return fmt.Errorf("%w: %s", ErrUpstreamLoopback, host)
	}
	for _, label := range strings.Split(name, ".") {
		if err := validateUpstreamLabel(label); err != nil {
			return err
		}
	}
	return nil
}

// validateUpstreamLabel checks one hostname label.
func validateUpstreamLabel(label string) error {
	if label == "" {
		return errors.New("empty label")
	}
	if len(label) > maxUpstreamLabelLen {
		return fmt.Errorf("label %q is longer than %d characters", label, maxUpstreamLabelLen)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q starts or ends with a hyphen", label)
	}
	for _, r := range label {
		if !isUpstreamLabelRune(r) {
			return fmt.Errorf("label %q contains %q", label, r)
		}
	}
	return nil
}

// isUpstreamLabelRune reports whether r may appear in a hostname label.
func isUpstreamLabelRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	default:
		return r == '-'
	}
}

// isNumericDotted reports whether s consists only of digits and dots, which is
// how a mistyped IPv4 literal looks.
func isNumericDotted(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// DefaultUpstreams is the single definition of the default plain-DNS pair.
//
// AdGuard's public resolvers are the default because they answer from networks
// that block 1.1.1.1 and 8.8.8.8; a default that cannot resolve is indistinguishable
// from "no evidence" and silently disables policy routing.
//
// Both the policy resolver fallback and the DNS servers a generated client
// configuration pushes derive from this function, so an operator never sees the
// two disagree.
func DefaultUpstreams() []Upstream {
	return []Upstream{
		{Address: "94.140.14.14", Port: DefaultUpstreamPort, Transport: TransportPlain},
		{Address: "94.140.15.15", Port: DefaultUpstreamPort, Transport: TransportPlain},
	}
}

// EffectiveUpstreams returns the upstream list the resolver must use: the
// operator's validated list when one is configured, otherwise the defaults.
// Every entry carries its effective port, so a consumer never has to guess a
// transport default.
// The returned slice is owned by the caller.
func (s Settings) EffectiveUpstreams() []Upstream {
	if len(s.UpstreamDNS) == 0 {
		return DefaultUpstreams()
	}
	out := make([]Upstream, len(s.UpstreamDNS))
	for i, upstream := range s.UpstreamDNS {
		out[i] = upstream.WithDefaultPort()
	}
	return out
}

// validateUpstreams enforces the persisted-list contract.
func (s Settings) validateUpstreams() error {
	if len(s.UpstreamDNS) == 0 {
		return nil
	}
	if len(s.UpstreamDNS) > MaxUpstreams {
		return fmt.Errorf("%d upstream DNS entries exceed the maximum of %d", len(s.UpstreamDNS), MaxUpstreams)
	}
	seen := make(map[string]struct{}, len(s.UpstreamDNS))
	for i, u := range s.UpstreamDNS {
		if err := u.Validate(); err != nil {
			return fmt.Errorf("upstream DNS entry %d rejected: %w", i+1, err)
		}
		key := string(u.EffectiveTransport()) + "|" + strings.ToLower(u.HostPort())
		if _, dup := seen[key]; dup {
			return fmt.Errorf("upstream DNS entry %d duplicates an earlier entry", i+1)
		}
		seen[key] = struct{}{}
	}
	return nil
}
