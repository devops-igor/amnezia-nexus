package policy

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// This file defines the upstream DNS entry type and the default resolver pair
// that every generated client configuration renders its DNS servers from.
//
// Design constraints:
//   - An entry is explicit: address, port and transport. The only port default is
//     the transport's own well-known one (853 for DoT, 443 for DoH), applied where
//     a record states none, so an entry always states the port it dials and can
//     never look like it targets one transport while it actually targets another.
//   - Every transport the contract names is a known value: plain DNS, DoT and DoH.
//     A transport value this package does not know is rejected by Validate rather
//     than accepted and quietly carried in another transport, because a silent
//     downgrade would be worse than an unimplemented option.
//   - A DoH entry is addressed like every other entry (address, port,
//     transport). A DoH client requests https://<address>:<port>/dns-query, the
//     well-known RFC 8484 path, so there is no scheme or path to configure and no
//     way to express a plaintext HTTP endpoint.
//   - The default pair lives in exactly one place (DefaultUpstreams), and the DNS
//     servers a generated client configuration pushes derive from it, so the
//     renderer cannot drift from the definition it is meant to describe.
//   - Validation rejects loopback, multicast, unspecified and malformed input, so
//     the default pair this file ships is always an addressable, usable resolver.
//   - There is no operator-editable upstream list. The panel does not run a
//     resolver of its own and does not steer client DNS, so the only upstream
//     configuration this package carries is the built-in default.

// UpstreamTransport selects how a consumer carries a query to one upstream entry.
type UpstreamTransport string

const (
	// TransportPlain is DNS over UDP with TCP fallback on truncation.
	TransportPlain UpstreamTransport = "plain"
	// TransportDoT is DNS over TLS (RFC 7858): the system trust store, chain and
	// name verification, and an optional SPKI pin; it never carries the query in
	// plaintext.
	TransportDoT UpstreamTransport = "dot"
	// TransportDoH is DNS over HTTPS (RFC 8484), carried over HTTP/2 with the
	// system trust store, chain and name verification, and an optional SPKI pin.
	// It never carries the query in plaintext and never follows a redirect.
	TransportDoH UpstreamTransport = "doh"
)

const (
	// DefaultUpstreamPort is the port the default plain-DNS entries use.
	DefaultUpstreamPort = 53
	// DefaultDoTPort is the port a DoT entry uses when it states none.
	DefaultDoTPort = 853
	// DefaultDoHPort is the port a DoH entry uses when it states none.
	DefaultDoHPort = 443
	// maxUpstreamHostLen is the maximum length of a DNS name in presentation form.
	maxUpstreamHostLen = 253
	// maxUpstreamLabelLen is the maximum length of one DNS name label.
	maxUpstreamLabelLen = 63
)

// ErrUpstreamLoopback marks a loopback entry. Validation and any future consumer
// that deliberately admits a local resolver need the same distinction, so the
// sentinel stays separate from the message rather than only appearing in its text.
var ErrUpstreamLoopback = errors.New("upstream is loopback")

// Upstream is one recursive-resolver entry.
//
// Address is an IPv4 literal, an IPv6 literal or a hostname. A hostname is
// resolved at dial time by whichever consumer dials the entry, so it stays a
// plain configuration string.
type Upstream struct {
	// Address is the IPv4/IPv6 literal or hostname of the resolver.
	Address string `json:"address"`
	// Port is explicit for plain DNS. DoT defaults to DefaultDoTPort and DoH to
	// DefaultDoHPort when it is left unset.
	Port int `json:"port"`
	// Transport is the empty string (plain) or one of the UpstreamTransport
	// values.
	Transport UpstreamTransport `json:"transport,omitempty"`
	// SPKIPin is the optional public-key pin for DoT and DoH: the SHA-256 digest
	// of the leaf certificate's SubjectPublicKeyInfo, encoded as standard base64
	// (RFC 4648 section 4, with padding, no line breaks). Empty means no pin.
	// An empty field keeps a slice-1 record valid, and the plain transport never
	// reads it, so a pin on a plain entry is rejected instead of ignored.
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

// defaultPort is the well-known port a transport uses when an entry states
// none, or 0 for a transport that has no default and so requires an explicit one.
func (t UpstreamTransport) defaultPort() int {
	switch t {
	case TransportDoT:
		return DefaultDoTPort
	case TransportDoH:
		return DefaultDoHPort
	default:
		return 0
	}
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

// Validate reports whether one entry is an addressable, usable resolver. Errors
// are specific rather than a single "invalid entry", so a caller (a test or a
// future reader of this package) can tell exactly which rule failed.
func (u Upstream) Validate() error {
	transport := u.EffectiveTransport()
	if transport == TransportDoH {
		if err := u.validateDoHAddress(); err != nil {
			return err
		}
	}
	if err := u.validateAddress(); err != nil {
		return err
	}
	switch transport {
	case TransportPlain, TransportDoT, TransportDoH:
	default:
		return fmt.Errorf("upstream %q has unknown transport %q", u.Address, u.Transport)
	}
	if err := u.validatePort(transport); err != nil {
		return err
	}
	return u.validateSPKIPin(transport)
}

// validateDoHAddress rejects an address that is a URL rather than a host. A DoH
// entry is an address and a port, and the resolver always requests
// https://<address>:<port>/dns-query over TLS, so a scheme, path or query in the
// address could only be dropped silently or change where the query goes; both
// are refused with a message that says what to configure instead.
func (u Upstream) validateDoHAddress() error {
	if strings.ContainsAny(u.Address, "/?#@") {
		return fmt.Errorf("upstream %q is not a bare host: a doh entry is an address and a port, and the resolver requests https://<address>:<port>/dns-query itself", u.Address)
	}
	return nil
}

// validatePort enforces an explicit port for plain DNS and the transport default
// for DoT and DoH.
func (u Upstream) validatePort(transport UpstreamTransport) error {
	if u.Port == 0 {
		if transport.defaultPort() != 0 {
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
// transport that never presents a certificate. DoT and DoH both verify the leaf
// key, so both honor it.
func (u Upstream) validateSPKIPin(transport UpstreamTransport) error {
	if u.SPKIPin == "" {
		return nil
	}
	if transport == TransportPlain {
		return fmt.Errorf("upstream %q sets an SPKI pin but selects transport %q; a pin is only honored by the encrypted transports dot and doh", u.Address, transport)
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
// that block 1.1.1.1 and 8.8.8.8; a default that cannot resolve leaves a client
// with no DNS at all, which is worse than a slower one.
//
// The DNS servers a generated client configuration pushes are rendered from this
// function, so the definition and the profiles it produces cannot drift apart.
// Only plain-transport entries are suitable for that rendering: a DoT or DoH
// entry here would be written into a profile as a plain DNS directive, which is a
// silent downgrade for the client.
func DefaultUpstreams() []Upstream {
	return []Upstream{
		{Address: "94.140.14.14", Port: DefaultUpstreamPort, Transport: TransportPlain},
		{Address: "94.140.15.15", Port: DefaultUpstreamPort, Transport: TransportPlain},
	}
}
