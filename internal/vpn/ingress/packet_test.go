package ingress

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// buildPacket builds a minimal IPv4 packet with the given source address and
// total length (totalLength >= 20).
func buildPacket(t *testing.T, src netip.Addr, totalLength int) []byte {
	t.Helper()
	if totalLength < ipv4HeaderLen {
		t.Fatalf("totalLength %d below IPv4 minimum header", totalLength)
	}
	pkt := make([]byte, totalLength)
	pkt[0] = 0x45 // version 4, IHL 5
	pkt[8] = 64   // TTL
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLength))
	src4 := src.As4()
	copy(pkt[12:16], src4[:])
	return pkt
}

func TestParseIPv4Source(t *testing.T) {
	src := netip.MustParseAddr("10.40.0.7")
	other := netip.MustParseAddr("10.40.0.9")

	tests := []struct {
		name   string
		packet []byte
		wantIP netip.Addr
		wantOK bool
	}{
		{"minimal header", buildPacket(t, src, 20), src, true},
		{"payload beyond header", buildPacket(t, src, 40), src, true},
		{"nil packet", nil, netip.Addr{}, false},
		{"zero length", []byte{}, netip.Addr{}, false},
		{"19 bytes", make([]byte, 19), netip.Addr{}, false},
		{"truncated header", make([]byte, 12), netip.Addr{}, false},
		{"IPv6 version nibble", []byte{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, netip.Addr{}, false},
		{"version nibble zero", make([]byte, 20), netip.Addr{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseIPv4Source(tt.packet)
			if ok != tt.wantOK {
				t.Fatalf("ParseIPv4Source ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.wantIP {
				t.Fatalf("ParseIPv4Source src = %v, want %v", got, tt.wantIP)
			}
			if ok && got.Is4() != true { // every accepted result is 4-byte IPv4
				t.Fatalf("ParseIPv4Source src %v is not 4-byte", got)
			}
		})
	}

	// The last packet proves the source field is read, not just the version
	// nibble: same shape as "minimal header" but a different source address.
	pkt := buildPacket(t, other, 20)
	if got, ok := ParseIPv4Source(pkt); !ok || got != other {
		t.Fatalf("ParseIPv4Source src = %v (%v), want %v", got, ok, other)
	}
}

// TestParseIPv4SourceFuzzSeeds pins the malformed corpus the fuzz target
// starts from; running the fuzzer grows it, the unit suite stays deterministic.
func TestParseIPv4SourceFuzzSeeds(t *testing.T) {
	for _, pkt := range [][]byte{
		nil,
		make([]byte, 19),
		make([]byte, 20),
		buildPacket(t, netip.MustParseAddr("10.40.0.7"), 20),
		{0x46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0}, // IHL 6, options never read
		{0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},             // 16 bytes
	} {
		src, ok := ParseIPv4Source(pkt)
		if ok && !src.IsValid() {
			t.Fatalf("ParseIPv4Source(% x) returned invalid address with ok", pkt)
		}
	}
}

func FuzzParseIPv4Source(f *testing.F) {
	for _, pkt := range [][]byte{
		nil,
		make([]byte, 19),
		make([]byte, 20),
		buildPacket(&testing.T{}, netip.MustParseAddr("10.40.0.7"), 20),
	} {
		f.Add(pkt)
	}
	f.Fuzz(func(t *testing.T, pkt []byte) {
		src, ok := ParseIPv4Source(pkt)
		if !ok {
			return
		}
		if len(pkt) < ipv4HeaderLen || pkt[0]>>4 != 4 {
			t.Fatalf("accepted packet len=%d ver=%d despite guards", len(pkt), pkt[0]>>4)
		}
		if !src.IsValid() || !src.Is4() || src.Unmap() != src {
			t.Fatalf("accepted non-4-byte address %v", src)
		}
		if src.String() != netip.AddrFrom4(src.As4()).String() {
			t.Fatalf("address %v does not round-trip", src)
		}
	})
}

func TestDropSentinelsAreDistinct(t *testing.T) {
	sentinels := []error{ErrDropMalformed, ErrDropUnmapped, ErrDropMismatch, ErrAdmissionRejected, ErrAdmissionContract}
	seen := make(map[string]bool, len(sentinels))
	for _, s := range sentinels {
		msg := s.Error()
		if seen[msg] {
			t.Fatalf("sentinel %q is not distinct", msg)
		}
		seen[msg] = true
	}
	err := dropError(ErrDropUnmapped, ReasonUnmappedSource)
	if !errors.Is(err, ErrDropUnmapped) {
		t.Fatalf("dropError loses its sentinel: %v", err)
	}
}
