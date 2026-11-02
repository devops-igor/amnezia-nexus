package policy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type ipRange struct {
	lo uint32
	hi uint32
}

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func prefixToRange(p netip.Prefix) ipRange {
	p = p.Masked()
	lo := addrToU32(p.Addr())
	bits := p.Bits()
	if bits == 0 {
		return ipRange{lo: 0, hi: ^uint32(0)}
	}
	span := (uint32(1) << uint(32-bits)) - 1
	hi := lo | span
	return ipRange{lo: lo, hi: hi}
}

// ParseIPv4Rule parses a CIDR prefix (e.g. "198.51.100.0/24") or single IPv4 address
// (e.g. "198.51.100.1", treated as /32). IPv6 addresses are rejected.
func ParseIPv4Rule(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, errors.New("empty IPv4 rule")
	}

	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR prefix %q: %w", raw, err)
		}
		addr := p.Addr().Unmap()
		if !addr.Is4() {
			return netip.Prefix{}, errors.New("IPv6 CIDR prefixes are not supported in IPv4 rules")
		}
		return netip.PrefixFrom(addr, p.Bits()).Masked(), nil
	}

	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 address %q: %w", raw, err)
	}
	a = a.Unmap()
	if !a.Is4() {
		return netip.Prefix{}, errors.New("IPv6 addresses are not supported in IPv4 rules")
	}
	return netip.PrefixFrom(a, 32), nil
}

// mergeRanges sorts intervals by lo, and merges contiguous or overlapping intervals.
func mergeRanges(ranges []ipRange) []ipRange {
	if len(ranges) <= 1 {
		return ranges
	}

	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].lo == ranges[j].lo {
			return ranges[i].hi < ranges[j].hi
		}
		return ranges[i].lo < ranges[j].lo
	})

	out := make([]ipRange, 0, len(ranges))
	for _, r := range ranges {
		if len(out) == 0 {
			out = append(out, r)
			continue
		}
		last := &out[len(out)-1]
		// Use uint64 to avoid overflow when last.hi == 0xffffffff
		if uint64(r.lo) <= uint64(last.hi)+1 {
			if r.hi > last.hi {
				last.hi = r.hi
			}
		} else {
			out = append(out, r)
		}
	}
	return out
}

type ipv4Index struct {
	ranges []ipRange
}

func newIPv4Index(prefixes []netip.Prefix) ipv4Index {
	raw := make([]ipRange, 0, len(prefixes))
	for _, p := range prefixes {
		if p.Addr().Is4() {
			raw = append(raw, prefixToRange(p))
		}
	}
	return ipv4Index{ranges: mergeRanges(raw)}
}

func (idx ipv4Index) match(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.Is4() {
		return false
	}
	n := addrToU32(addr)
	i := sort.Search(len(idx.ranges), func(j int) bool {
		return idx.ranges[j].lo > n
	})
	if i > 0 && n <= idx.ranges[i-1].hi {
		return true
	}
	return false
}
