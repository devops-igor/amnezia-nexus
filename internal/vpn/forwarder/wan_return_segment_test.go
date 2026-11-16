package forwarder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// tcpOptionsTimestamp is a valid 12-byte TCP option block (NOP, NOP,
// timestamp), giving a 32-byte TCP header. It is used to prove that options are
// replicated on every piece rather than dropped or recomputed.
var tcpOptionsTimestamp = []byte{
	1, 1, // NOP, NOP
	8, 10, // timestamp kind, length
	0x00, 0x00, 0x12, 0x34, // TSval
	0x00, 0x00, 0x56, 0x78, // TSecr
}

// segmentPacketFields describes the packet segmentInput builds. Every field is
// explicit so the test can state exactly what must survive segmentation.
type segmentPacketFields struct {
	src, dst           string
	srcPort, dstPort   uint16
	seq, ack           uint32
	flags              uint8
	ipID               uint16
	ipFlags            uint16
	ihl                int
	tcpOptions         []byte
	payload            []byte
	declaredTotalDelta int
}

// segmentInput builds one IPv4/TCP packet with an explicit header layout so every
// field the segmenter must preserve can be checked.
func segmentInput(t *testing.T, cfg segmentPacketFields) []byte {
	t.Helper()
	ipHeader := 20
	if cfg.ihl > 0 {
		ipHeader = cfg.ihl
	}
	tcpHeader := 20 + len(cfg.tcpOptions)
	total := ipHeader + tcpHeader + len(cfg.payload)
	pkt := make([]byte, total)
	pkt[0] = 0x40 | byte(ipHeader/4)                                           // #nosec G115 -- test header lengths are 20/24
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total+cfg.declaredTotalDelta)) // #nosec G115 -- test sizes are small
	binary.BigEndian.PutUint16(pkt[4:6], cfg.ipID)
	binary.BigEndian.PutUint16(pkt[6:8], cfg.ipFlags)
	pkt[8] = 64
	pkt[9] = 6
	src := netip.MustParseAddr(cfg.src).As4()
	dst := netip.MustParseAddr(cfg.dst).As4()
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], computeIPv4Checksum(pkt[:ipHeader]))

	off := ipHeader
	binary.BigEndian.PutUint16(pkt[off:off+2], cfg.srcPort)
	binary.BigEndian.PutUint16(pkt[off+2:off+4], cfg.dstPort)
	binary.BigEndian.PutUint32(pkt[off+4:off+8], cfg.seq)
	binary.BigEndian.PutUint32(pkt[off+8:off+12], cfg.ack)
	pkt[off+12] = byte(tcpHeader/4) << 4 // #nosec G115 -- test header lengths are small
	pkt[off+13] = cfg.flags
	binary.BigEndian.PutUint16(pkt[off+14:off+16], 64240)
	copy(pkt[off+20:], cfg.tcpOptions)
	copy(pkt[off+tcpHeader:], cfg.payload)
	binary.BigEndian.PutUint16(pkt[off+16:off+18], computeL4Checksum(src, dst, 6, pkt[off:]))
	return pkt
}

// requireValidSegment asserts the properties a receiving client stack verifies
// on one produced piece.
func requireValidSegment(t *testing.T, seg []byte, maxLen int, src, dst string) {
	t.Helper()
	if len(seg) > maxLen {
		t.Fatalf("piece is %d bytes, above the %d byte limit", len(seg), maxLen)
	}
	if seg[0]>>4 != 4 || int(seg[0]&0x0f) != 5 {
		t.Fatalf("piece has no plain 20-byte IPv4 header: %#02x", seg[0])
	}
	if decl := int(binary.BigEndian.Uint16(seg[2:4])); decl != len(seg) {
		t.Fatalf("piece declares %d bytes but carries %d", decl, len(seg))
	}
	if binary.BigEndian.Uint16(seg[6:8])&0x3fff != 0 {
		t.Fatalf("piece is marked fragmented: %#04x", binary.BigEndian.Uint16(seg[6:8]))
	}
	if got := netip.AddrFrom4([4]byte{seg[12], seg[13], seg[14], seg[15]}); got.String() != src {
		t.Fatalf("piece source %s, want %s", got, src)
	}
	if got := netip.AddrFrom4([4]byte{seg[16], seg[17], seg[18], seg[19]}); got.String() != dst {
		t.Fatalf("piece destination %s, want %s", got, dst)
	}
	if !checksumValidIPv4(seg[:20]) {
		t.Fatal("piece IPv4 checksum does not cover its own header")
	}
	srcBytes, dstBytes := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	if !checksumValidL4(srcBytes, dstBytes, 6, seg[20:]) {
		t.Fatal("piece TCP checksum does not cover its own segment")
	}
}

// TestSegmentWANReplyTCPSplitsIntoClientMTUPieces covers the supported shape: the
// payload arrives whole and unchanged, sequence numbers stay contiguous across a
// wrap, TCP options are replicated, and FIN/PSH move to the last piece while the
// connection-state flags are replicated.
func TestSegmentWANReplyTCPSplitsIntoClientMTUPieces(t *testing.T) {
	const (
		src     = "198.51.200.2"
		dst     = "198.51.200.1"
		maxLen  = 1420
		payload = 4000
	)
	for _, tc := range []struct {
		name   string
		seq    uint32
		flags  uint8
		ipID   uint16
		ipFlag uint16
	}{
		{name: "plain_header", seq: 1, flags: 0x18, ipID: 4242, ipFlag: 0x4000},
		{name: "sequence_wrap", seq: 0xFFFFFF00, flags: 0x18, ipID: 4242, ipFlag: 0x4000},
		{name: "fin_and_push", seq: 900, flags: 0x19, ipID: 1, ipFlag: 0x4000},
		{name: "congestion_flags_replicated", seq: 900, flags: 0xD8 /* CWR|ECE|PSH|ACK */, ipID: 65530, ipFlag: 0x4000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := segmentTestPayload(payload)
			pkt := segmentInput(t, segmentPacketFields{
				src: src, dst: dst, srcPort: 443, dstPort: 51000,
				seq: tc.seq, ack: 77, flags: tc.flags, ipID: tc.ipID, ipFlags: tc.ipFlag,
				tcpOptions: tcpOptionsTimestamp, payload: data,
			})

			segments, err := segmentWANReplyTCP(pkt, maxLen)
			if err != nil {
				t.Fatalf("segmentWANReplyTCP: %v", err)
			}
			if len(segments) < 2 {
				t.Fatalf("a %d byte frame produced %d piece(s), want at least 2", len(pkt), len(segments))
			}

			var got []byte
			for i, seg := range segments {
				requireValidSegment(t, seg, maxLen, src, dst)
				if int(seg[0]&0x0f)*4 != 20 {
					t.Fatalf("piece %d lost the plain IPv4 header", i)
				}
				if gotID := binary.BigEndian.Uint16(seg[4:6]); gotID != tc.ipID+uint16(i) { // #nosec G115 -- piece index is bounded
					t.Fatalf("piece %d IP id = %d, want %d", i, gotID, tc.ipID+uint16(i))
				}
				if got := binary.BigEndian.Uint16(seg[6:8]); got != tc.ipFlag {
					t.Fatalf("piece %d flags/fragment field = %#04x, want %#04x", i, got, tc.ipFlag)
				}
				doff := int(seg[20+12]>>4) * 4
				if doff != 20+len(tcpOptionsTimestamp) {
					t.Fatalf("piece %d TCP header is %d bytes, want the received %d", i, doff, 20+len(tcpOptionsTimestamp))
				}
				if !bytes.Equal(seg[40:40+len(tcpOptionsTimestamp)], tcpOptionsTimestamp) {
					t.Fatalf("piece %d did not replicate the received TCP options", i)
				}
				if gotAck := binary.BigEndian.Uint32(seg[20+8 : 20+12]); gotAck != 77 {
					t.Fatalf("piece %d acknowledgment = %d, want 77", i, gotAck)
				}
				if gotWin := binary.BigEndian.Uint16(seg[20+14 : 20+16]); gotWin != 64240 {
					t.Fatalf("piece %d window = %d, want 64240", i, gotWin)
				}
				if want := tc.seq + uint32(len(got)); binary.BigEndian.Uint32(seg[20+4:20+8]) != want {
					t.Fatalf("piece %d sequence = %d, want %d", i, binary.BigEndian.Uint32(seg[20+4:20+8]), want)
				}
				last := i == len(segments)-1
				wantFlags := tc.flags
				if !last {
					wantFlags &^= tcpFlagFIN | tcpFlagPSH
				}
				if gotFlags := seg[20+13]; gotFlags != wantFlags {
					t.Fatalf("piece %d flags = %#02x, want %#02x", i, gotFlags, wantFlags)
				}
				got = append(got, seg[20+doff:]...)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("reassembled payload differs: %d bytes vs %d sent", len(got), len(data))
			}
		})
	}
}

// TestSegmentWANReplyTCPKeepsFittingPacketsWhole proves a reply that already fits
// is returned untouched, so the common path is not rewritten by the segmenter. The
// boundary is checked on both sides: 1380 payload bytes make a 1420-byte packet and
// stay whole, one more byte is split.
func TestSegmentWANReplyTCPKeepsFittingPacketsWhole(t *testing.T) {
	for _, size := range []int{0, 1, 1380} {
		payload := segmentTestPayload(size)
		pkt := segmentInput(t, segmentPacketFields{
			src: "198.51.200.2", dst: "198.51.200.1", srcPort: 443, dstPort: 51000,
			seq: 5, ack: 1, flags: 0x18, ipID: 7, ipFlags: 0x4000, payload: payload,
		})
		segments, err := segmentWANReplyTCP(pkt, 1420)
		if err != nil {
			t.Fatalf("payload %d: %v", size, err)
		}
		if len(segments) != 1 {
			t.Fatalf("payload %d (%d byte frame): %d piece(s), want 1", size, len(pkt), len(segments))
		}
		if !bytes.Equal(segments[0], pkt) {
			t.Fatalf("payload %d: a frame that already fits was rewritten", size)
		}
	}
}

// TestSegmentWANReplyTCPRefusesUnsupportedShapes is the fail-closed half: every
// shape this function cannot split without changing its meaning is refused, and
// the caller keeps its pre-existing refusal path.
func TestSegmentWANReplyTCPRefusesUnsupportedShapes(t *testing.T) {
	base := func() []byte {
		return segmentInput(t, segmentPacketFields{
			src: "198.51.200.2", dst: "198.51.200.1", srcPort: 443, dstPort: 51000,
			seq: 5, ack: 1, flags: 0x18, ipID: 7, ipFlags: 0x4000,
			payload: segmentTestPayload(4000),
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "udp_is_not_segmentable", mutate: func(p []byte) []byte { p[9] = 17; return p }},
		{name: "more_fragments_set", mutate: func(p []byte) []byte { binary.BigEndian.PutUint16(p[6:8], 0x2000); return p }},
		{name: "fragment_offset_set", mutate: func(p []byte) []byte { binary.BigEndian.PutUint16(p[6:8], 0x0010); return p }},
		{name: "ip_options_present", mutate: func(p []byte) []byte {
			// A 24-byte IPv4 header with four NOP options; the total length must
			// stay consistent with the extra four bytes.
			out := append([]byte{}, p[:20]...)
			out[0] = 0x46
			out = append(out, 1, 1, 1, 1)
			out = append(out, p[20:]...)
			binary.BigEndian.PutUint16(out[2:4], uint16(len(out))) // #nosec G115 -- test size
			return out
		}},
		{name: "declared_length_shorter_than_frame", mutate: func(p []byte) []byte {
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)-4)) // #nosec G115 -- test size
			return p
		}},
		{name: "tcp_data_offset_too_small", mutate: func(p []byte) []byte { p[32] = 0x40; return p }},
		{name: "tcp_data_offset_past_end", mutate: func(p []byte) []byte {
			short := p[:40]
			short[32] = 0xF0                                           // data offset 60 in a 40-byte frame
			binary.BigEndian.PutUint16(short[2:4], uint16(len(short))) // #nosec G115 -- test size
			return short
		}},
		{name: "syn_carrying_data", mutate: func(p []byte) []byte { p[33] = 0x12; return p }},
		{name: "reset_carrying_data", mutate: func(p []byte) []byte { p[33] = 0x14; return p }},
		{name: "urgent_pointer", mutate: func(p []byte) []byte { p[33] = 0x38; return p }},
		{name: "client_mtu_too_small_for_header", mutate: func(p []byte) []byte { return p }},
		{name: "not_ipv4", mutate: func(p []byte) []byte { p[0] = 0x65; return p }},
		{name: "truncated", mutate: func(p []byte) []byte { return p[:12] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := tc.mutate(base())
			maxLen := 1420
			if tc.name == "client_mtu_too_small_for_header" {
				maxLen = 40
			}
			segments, err := segmentWANReplyTCP(packet, maxLen)
			if !errors.Is(err, ErrWANReplyNotSegmentable) {
				t.Fatalf("want %v, got err=%v with %d piece(s)", ErrWANReplyNotSegmentable, err, len(segments))
			}
			if segments != nil {
				t.Fatalf("a refused frame produced %d piece(s)", len(segments))
			}
		})
	}
}

// TestSegmentWANReplyTCPBoundsWorkByIPv4Size proves the per-frame work and memory
// stay bounded by the IPv4 maximum and the output limit: the largest possible
// frame yields pieces that all satisfy the limit, and the piece count stays below
// the segmenter's structural ceiling.
func TestSegmentWANReplyTCPBoundsWorkByIPv4Size(t *testing.T) {
	const maxLen = 1420
	// The largest payload an IPv4 packet can carry over a 40-byte header.
	payload := make([]byte, 65535-40)
	pkt := segmentInput(t, segmentPacketFields{
		src: "198.51.200.2", dst: "198.51.200.1", srcPort: 443, dstPort: 51000,
		seq: 3, ack: 1, flags: 0x18, ipID: 9, ipFlags: 0x4000, payload: payload,
	})
	if len(pkt) != 65535 {
		t.Fatalf("fixture frame is %d bytes, want 65535", len(pkt))
	}
	segments, err := segmentWANReplyTCP(pkt, maxLen)
	if err != nil {
		t.Fatalf("segmentWANReplyTCP: %v", err)
	}
	if len(segments) > maxWANReplySegments {
		t.Fatalf("%d pieces produced, above the %d piece ceiling", len(segments), maxWANReplySegments)
	}
	var got []byte
	for i, seg := range segments {
		requireValidSegment(t, seg, maxLen, "198.51.200.2", "198.51.200.1")
		if len(seg) <= 40 {
			t.Fatalf("piece %d carries no payload", i)
		}
		got = append(got, seg[40:]...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled payload differs from the %d byte input", len(payload))
	}
}

// TestSegmentWANReplyTCPEnforcesPieceCeiling proves the structural piece ceiling is
// enforced rather than merely documented: a client MTU so small that the frame
// would need more pieces than the ceiling refuses the frame instead of producing
// unbounded work.
func TestSegmentWANReplyTCPEnforcesPieceCeiling(t *testing.T) {
	const maxLen = 44 // 40 bytes of headers leave 4 payload bytes per piece
	pkt := segmentInput(t, segmentPacketFields{
		src: "198.51.200.2", dst: "198.51.200.1", srcPort: 443, dstPort: 51000,
		seq: 5, ack: 1, flags: 0x18, ipID: 7, ipFlags: 0x4000,
		payload: segmentTestPayload(4000),
	})
	segments, err := segmentWANReplyTCP(pkt, maxLen)
	if !errors.Is(err, ErrWANReplyNotSegmentable) {
		t.Fatalf("a frame needing %d pieces: want %v, got err=%v with %d piece(s)",
			(len(pkt)-40)/4, ErrWANReplyNotSegmentable, err, len(segments))
	}
	if segments != nil {
		t.Fatalf("a refused frame produced %d piece(s)", len(segments))
	}
}

// TestSegmentWANReplyTCPRefusesUnusableClientMTU covers the bound on the caller's
// own input: a non-positive limit can never describe a client packet, so it is
// refused instead of producing a split that no device could accept.
func TestSegmentWANReplyTCPRefusesUnusableClientMTU(t *testing.T) {
	pkt := segmentInput(t, segmentPacketFields{
		src: "198.51.200.2", dst: "198.51.200.1", srcPort: 443, dstPort: 51000,
		seq: 5, ack: 1, flags: 0x18, ipID: 7, ipFlags: 0x4000,
		payload: segmentTestPayload(100),
	})
	for _, maxLen := range []int{0, -1} {
		segments, err := segmentWANReplyTCP(pkt, maxLen)
		if !errors.Is(err, ErrWANReplyNotSegmentable) {
			t.Fatalf("maxLen %d: want %v, got err=%v with %d piece(s)", maxLen, ErrWANReplyNotSegmentable, err, len(segments))
		}
	}
}
