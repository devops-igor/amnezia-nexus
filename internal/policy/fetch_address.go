package policy

import (
	"errors"
	"fmt"
	"net/netip"
)

var (
	// ErrBlockedIP indicates an address is prohibited by SSRF defense policies.
	ErrBlockedIP = errors.New("IP address is blocked by SSRF defense policy")
)

var deniedPrefixes = []string{
	"0.0.0.0/8",        // Current network (only valid as source address)
	"10.0.0.0/8",       // Private-use networks (RFC 1918)
	"100.64.0.0/10",    // Shared Address Space / CGNAT (RFC 6598) - contains Alibaba metadata 100.100.100.200
	"127.0.0.0/8",      // Loopback (RFC 1122)
	"169.254.0.0/16",   // Link-Local (RFC 3927) - contains AWS/GCP/Azure metadata 169.254.169.254
	"172.16.0.0/12",    // Private-use networks (RFC 1918)
	"192.0.0.0/24",     // IETF Protocol Assignments (RFC 6890)
	"192.0.2.0/24",     // Documentation / TEST-NET-1 (RFC 5737)
	"192.88.99.0/24",   // 6to4 Relay Anycast (RFC 7526)
	"192.168.0.0/16",   // Private-use networks (RFC 1918)
	"198.18.0.0/15",    // Network Interconnect Device Benchmark Testing (RFC 2544)
	"198.51.100.0/24",  // Documentation / TEST-NET-2 (RFC 5737)
	"203.0.113.0/24",   // Documentation / TEST-NET-3 (RFC 5737)
	"224.0.0.0/4",      // Multicast (RFC 5771)
	"240.0.0.0/4",      // Reserved for Future Use (RFC 1112) / Broadcast
	"168.63.129.16/32", // Azure WireServer / Host Protected Services
}

var deniedRangesIndex ipv4Index

func init() {
	prefixes := make([]netip.Prefix, 0, len(deniedPrefixes))
	for _, s := range deniedPrefixes {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}
	deniedRangesIndex = newIPv4Index(prefixes)
}

// ValidateFetchIP checks an IP address against the strict SSRF blocklist.
// IPv6 addresses, loopback, private networks, link-local, cloud metadata,
// CGNAT, documentation, benchmark, and reserved ranges are rejected.
func ValidateFetchIP(addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid IP address", ErrBlockedIP)
	}
	if !addr.Is4() {
		return fmt.Errorf("%w: IPv6 address %s is not permitted for rule downloads", ErrBlockedIP, addr)
	}
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: special-use address %s", ErrBlockedIP, addr)
	}
	if deniedRangesIndex.match(addr) {
		return fmt.Errorf("%w: address %s is in prohibited network range", ErrBlockedIP, addr)
	}
	return nil
}
