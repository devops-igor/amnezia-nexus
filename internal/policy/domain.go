package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

type domainFlags uint8

const (
	domainExact           domainFlags = 1 << 0
	domainInclusiveSuffix domainFlags = 1 << 1
	domainDescendants     domainFlags = 1 << 2
)

// DomainMode defines how bare domain entries in a list are interpreted.
type DomainMode uint8

const (
	// DomainModeExact treats bare domains (e.g. "example.com") as matching only that exact apex.
	DomainModeExact DomainMode = iota + 1
	// DomainModeInclusiveSuffix treats bare domains as matching the apex and all subdomains.
	DomainModeInclusiveSuffix
)

var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(true),
	idna.ValidateLabels(true),
	idna.VerifyDNSLength(true),
	idna.BidiRule(),
)

// NormalizeDomain validates and canonicalizes a domain name to ASCII lowercase
// without a trailing dot, mapping IDN labels to Punycode.
func NormalizeDomain(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("empty domain name")
	}

	// Reject forbidden characters and schemes
	if strings.ContainsAny(name, " \t\r\n/:?#@\\_") {
		return "", errors.New("domain contains illegal characters or scheme")
	}
	if strings.HasSuffix(name, "..") || strings.Contains(name, "..") {
		return "", errors.New("domain contains empty label or multiple trailing dots")
	}

	a := name
	// Apply IDNA mapping if non-ASCII or contains Punycode prefix
	if strings.IndexFunc(name, func(r rune) bool { return r > 127 }) >= 0 ||
		strings.Contains(strings.ToLower(name), "xn--") {
		var err error
		a, err = idnaProfile.ToASCII(name)
		if err != nil {
			return "", fmt.Errorf("IDNA normalization failed: %w", err)
		}
	}

	a = strings.ToLower(strings.TrimSuffix(a, "."))
	if a == "" || len(a) > 253 {
		return "", errors.New("domain length must be between 1 and 253 octets")
	}

	labels := strings.Split(a, ".")
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return "", errors.New("label length must be between 1 and 63 octets")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("label cannot start or end with a hyphen")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", errors.New("label contains non-LDH character")
			}
		}
	}

	if _, err := netip.ParseAddr(a); err == nil {
		return "", errors.New("domain cannot be an IP literal")
	}

	return a, nil
}

// ParseDomainRule parses a raw domain rule with optional leading prefix (*. or .)
// and applies the configured default DomainMode for bare domains.
// If the raw rule is an IPv4 literal, isIP is returned as true with the parsed address.
func ParseDomainRule(raw string, defaultMode DomainMode) (base string, flags domainFlags, isIP bool, ip netip.Addr, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, false, netip.Addr{}, errors.New("empty domain rule")
	}

	// Check if this is an IP literal
	if addr, parseErr := netip.ParseAddr(raw); parseErr == nil {
		addr = addr.Unmap()
		if addr.Is4() {
			return "", 0, true, addr, nil
		}
		return "", 0, false, netip.Addr{}, errors.New("IPv6 literals are not supported in domain rules")
	}

	if strings.HasPrefix(raw, "*.") {
		baseRaw := raw[2:]
		if baseRaw == "" || strings.HasPrefix(baseRaw, "*") || strings.HasPrefix(baseRaw, ".") {
			return "", 0, false, netip.Addr{}, errors.New("invalid wildcard prefix")
		}
		if strings.Contains(baseRaw, "*") {
			return "", 0, false, netip.Addr{}, errors.New("wildcard '*' only permitted as leading '*.'")
		}
		norm, normErr := NormalizeDomain(baseRaw)
		if normErr != nil {
			return "", 0, false, netip.Addr{}, normErr
		}
		return norm, domainDescendants, false, netip.Addr{}, nil
	}

	if strings.HasPrefix(raw, ".") {
		baseRaw := raw[1:]
		if baseRaw == "" || strings.HasPrefix(baseRaw, "*") || strings.HasPrefix(baseRaw, ".") {
			return "", 0, false, netip.Addr{}, errors.New("invalid suffix prefix")
		}
		if strings.Contains(baseRaw, "*") {
			return "", 0, false, netip.Addr{}, errors.New("wildcard '*' only permitted as leading '*.'")
		}
		norm, normErr := NormalizeDomain(baseRaw)
		if normErr != nil {
			return "", 0, false, netip.Addr{}, normErr
		}
		return norm, domainInclusiveSuffix, false, netip.Addr{}, nil
	}

	if strings.Contains(raw, "*") {
		return "", 0, false, netip.Addr{}, errors.New("wildcard '*' only permitted as leading '*.'")
	}

	norm, normErr := NormalizeDomain(raw)
	if normErr != nil {
		return "", 0, false, netip.Addr{}, normErr
	}

	if defaultMode == DomainModeInclusiveSuffix {
		return norm, domainInclusiveSuffix, false, netip.Addr{}, nil
	}
	return norm, domainExact, false, netip.Addr{}, nil
}
