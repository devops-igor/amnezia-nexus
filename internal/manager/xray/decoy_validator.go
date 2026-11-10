package xray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/xray/scanner"
)

// DefaultDecoyDomain is the default camouflage domain used for REALITY inbounds.
// It is a multi-region CDN endpoint (Microsoft AS8075), so it satisfies the
// geo/ASN alignment rule below on any hosting provider.
const DefaultDecoyDomain = "www.microsoft.com"

// decoyValidationTimeout bounds DNS work performed while validating a decoy.
// AGENTS.md forbids unbounded external calls; a resolver that never answers must
// not be able to stall an install.
const decoyValidationTimeout = 5 * time.Second

// lookupIP is the resolver seam used by ValidateDecoyDomainContext. Tests
// override it to stay hermetic.
var lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

// IsBlacklistedDecoyDomain returns true if the candidate domain matches known censor-targeted domains
// such as Apple Private Relay gateways or Telegram Web CDN endpoints.
func IsBlacklistedDecoyDomain(domain string) bool {
	return scanner.IsBlacklistedDecoyDomain(domain)
}

// ValidateDecoyDomain checks a candidate REALITY camouflage domain against DPI censor blacklists
// and verifies ASN/hosting proximity against the target server using GeoDB.
//
// It exists for callers that have no context to thread (tests, legacy paths). Production code
// paths must use ValidateDecoyDomainContext so the DNS lookups are bounded.
func ValidateDecoyDomain(domain string, serverIP string, geoDB *scanner.GeoDB) error {
	ctx, cancel := context.WithTimeout(context.Background(), decoyValidationTimeout)
	defer cancel()
	return ValidateDecoyDomainContext(ctx, domain, serverIP, geoDB)
}

// ValidateDecoyDomainContext is ValidateDecoyDomain with a caller-supplied context. All DNS
// lookups derive from ctx, so an install that is canceled or deadline-bounded also stops
// waiting on the resolver.
//
// Failure policy (deliberate, see DEV_OWNED_REPAIR.md):
//   - blacklist matches always fail;
//   - a domain that cannot be given an address fails, because an unresolvable decoy cannot
//     camouflage anything and would produce a REALITY inbound that never negotiates;
//   - ASN/geo misalignment fails.
//
// The previous implementation returned nil when resolution failed, which silently accepted
// unverifiable decoys.
func ValidateDecoyDomainContext(ctx context.Context, domain string, serverIP string, geoDB *scanner.GeoDB) error {
	cleanDomain := strings.ToLower(strings.TrimSpace(domain))
	cleanDomain = strings.TrimSuffix(cleanDomain, ".")
	if cleanDomain == "" {
		return errors.New("decoy domain cannot be empty")
	}

	// 1. Censor-Target Blacklist Check (deterministic, no network involved).
	if IsBlacklistedDecoyDomain(cleanDomain) {
		return fmt.Errorf("decoy domain %q is blacklisted as a known censor target", domain)
	}

	// 2. Load GeoDB if not supplied.
	if geoDB == nil {
		var err error
		geoDB, err = scanner.DefaultGeoDB()
		if err != nil {
			return fmt.Errorf("load default geodb: %w", err)
		}
	}

	// 3. Resolve the candidate to IPv4.
	candIP, err := resolveIPv4(ctx, cleanDomain)
	if err != nil {
		return fmt.Errorf("resolve decoy domain %q: %w", domain, err)
	}
	if candIP == nil {
		return fmt.Errorf("decoy domain %q did not resolve to an IPv4 address", domain)
	}

	// 4. ASN Validation: reject Apple AS714 (censor-targeted Anycast).
	candASN, _, candFound := geoDB.Lookup(candIP)
	if candFound && candASN == 714 {
		return fmt.Errorf("decoy domain %q belongs to Apple AS714 which is targeted by DPI egress blocking", domain)
	}

	// 5. Server Alignment: verify geo/ASN alignment if a server address is provided.
	if serverIP == "" {
		return nil
	}
	sIP, err := resolveIPv4(ctx, normalizeHostPort(serverIP))
	if err != nil {
		return fmt.Errorf("resolve server address %q: %w", serverIP, err)
	}
	if sIP == nil {
		// An unparseable/unresolvable server address means alignment cannot be checked.
		// Treat that as a validation failure rather than silently skipping the check.
		return fmt.Errorf("server address %q did not resolve to an IPv4 address", serverIP)
	}

	passed, _, _, _, _, reason := geoDB.ValidateGeoProximity(sIP, candIP)
	if !passed {
		return fmt.Errorf("decoy domain %q failed geo/ASN alignment with server %s: %s", domain, serverIP, reason)
	}
	return nil
}

// resolveIPv4 returns the first IPv4 address for value, which may be an IP literal or a
// hostname. A nil result with a nil error means the value resolved to no IPv4 address.
func resolveIPv4(ctx context.Context, value string) (net.IP, error) {
	if ip := net.ParseIP(value); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, nil
	}
	ips, err := lookupIP(ctx, "ip4", value)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, nil
}

// normalizeHostPort strips a port from host:port input, tolerating bare hosts.
func normalizeHostPort(value string) string {
	trimmed := strings.TrimSpace(value)
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")
}
