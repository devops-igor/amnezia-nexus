package forwarder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// This file is the real-consumer regression for the two TCP semantic defects the
// owner reproduced on the published build:
//
//   - option validation: a data-bearing segment's option area was cloned onto
//     every piece without being parsed, so an invalid length, an option that
//     overruns the header, non-zero bytes after EOL, and options that are
//     per-segment (MD5) or unsupported (MPTCP) were all silently normalized;
//   - CWR placement: the whole flag byte was cloned, so CWR was repeated on
//     every piece instead of appearing only on the first generated data piece.
//
// Each test drives the production consumer (`HandleWANReply`) where the defect is
// observable as delivered packets or a counted refusal, and the normalizer
// directly where the exact output must be inspected.

// segmentReplyTCPOptions builds one inbound WAN reply frame whose TCP header
// carries the given option bytes.
func segmentReplyTCPOptions(src, dst netip.Addr, srcPort, dstPort uint16, seq uint32, flags uint8, options, payload []byte) []byte {
	tcpHeader := 20 + len(options)
	pkt := make([]byte, 20+tcpHeader+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt))) // #nosec G115 -- bounded by the test payload
	binary.BigEndian.PutUint16(pkt[4:6], 31337)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 6
	srcBytes, dstBytes := src.As4(), dst.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(pkt[10:12], computeIPv4Checksum(pkt[:20]))

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], 1)
	pkt[32] = byte(tcpHeader/4) << 4 // #nosec G115 -- test header lengths are small
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 64240)
	copy(pkt[40:], options)
	copy(pkt[20+tcpHeader:], payload)
	binary.BigEndian.PutUint16(pkt[36:38], computeL4Checksum(srcBytes, dstBytes, 6, pkt[20:]))
	return pkt
}

// TestSegmentWANReplyTCPRefusesUnsafeOptions covers the option contract directly:
// every shape whose meaning cannot survive replication is refused, and the one
// common, segment-independent shape (timestamp with NOP padding) is still split
// with its option bytes intact.
func TestSegmentWANReplyTCPRefusesUnsafeOptions(t *testing.T) {
	const maxLen = 1420
	remote := netip.MustParseAddr("198.51.100.2")
	hostWAN := netip.MustParseAddr("198.51.100.1")

	for _, tc := range []struct {
		name        string
		options     []byte
		reservedBit bool
	}{
		{"invalid_option_length_one", []byte{8, 1, 0, 0}, false},
		{"option_overruns_header", []byte{8, 10, 0, 0}, false},
		{"nonzero_bytes_after_eol", []byte{0, 30, 4, 1}, false},
		{"segment_specific_md5", append([]byte{19, 18}, make([]byte, 18)...), false},
		{"unsupported_mptcp", []byte{30, 4, 0, 0}, false},
		{"unsupported_unknown_kind", []byte{99, 4, 0, 0}, false},
		{"option_length_zero", []byte{8, 0, 0, 0}, false},
		{"truncated_option", []byte{1, 8, 10, 0}, false},
		{"timestamp_truncated_after_nops", []byte{1, 1, 1, 8}, false},
		{"reserved_header_bits_set", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := segmentReplyTCPOptions(remote, hostWAN, 443, 45000, 7, 0x18, tc.options, bytes.Repeat([]byte{7}, 4000))
			if tc.reservedBit {
				pkt[32] |= 0x01 // RFC 9293 reserved bits must be zero
			}
			pieces, err := segmentWANReplyTCP(pkt, maxLen)
			if !errors.Is(err, ErrWANReplyNotSegmentable) {
				t.Fatalf("options %x: want %v, got err=%v with %d piece(s)", tc.options, ErrWANReplyNotSegmentable, err, len(pieces))
			}
			if pieces != nil {
				t.Fatalf("options %x: a refused frame produced %d piece(s)", tc.options, len(pieces))
			}
		})
	}

	t.Run("legitimate_timestamp_still_split", func(t *testing.T) {
		pkt := segmentReplyTCPOptions(remote, hostWAN, 443, 45000, 7, 0x18, tcpOptionsTimestamp, bytes.Repeat([]byte{7}, 4000))
		pieces, err := segmentWANReplyTCP(pkt, maxLen)
		if err != nil || len(pieces) < 2 {
			t.Fatalf("a legitimate timestamp segment was not split: err=%v pieces=%d", err, len(pieces))
		}
		for i, piece := range pieces {
			requireValidSegment(t, piece, maxLen, remote.String(), hostWAN.String())
			doff := int(piece[32]>>4) * 4
			if doff != 20+len(tcpOptionsTimestamp) {
				t.Fatalf("piece %d TCP header is %d bytes, want %d", i, doff, 20+len(tcpOptionsTimestamp))
			}
			if !bytes.Equal(piece[40:40+len(tcpOptionsTimestamp)], tcpOptionsTimestamp) {
				t.Fatalf("piece %d did not carry the received timestamp option", i)
			}
		}
	})
}

// TestSegmentWANReplyTCPCWROnlyOnFirstPiece covers the congestion-flag contract:
// CWR is a single-segment signal (RFC 3168 §6.1.2, the sender sets it on the first
// new data segment after reducing its window), so a normalized run may carry it on
// exactly the first generated piece, while ECE/ACK stay on every piece and
// FIN/PSH stay on the last.
func TestSegmentWANReplyTCPCWROnlyOnFirstPiece(t *testing.T) {
	const maxLen = 1420
	remote := netip.MustParseAddr("198.51.100.2")
	hostWAN := netip.MustParseAddr("198.51.100.1")

	for _, tc := range []struct {
		name      string
		flags     uint8
		wantFirst uint8
		wantMid   uint8
		wantLast  uint8
	}{
		{
			name:      "cwr_ece_push_ack",
			flags:     0xd8, // CWR|ECE|PSH|ACK
			wantFirst: 0xd0, // ECE|ACK: CWR belongs to this piece only
			wantMid:   0x50,
			wantLast:  0x58,
		},
		{
			name:      "cwr_with_push_and_fin",
			flags:     0x99, // CWR|ACK|PSH|FIN
			wantFirst: 0x90,
			wantMid:   0x10,
			wantLast:  0x19, // CWR cleared, PSH|FIN on the last piece
		},
		{
			name:      "ece_only_replicates",
			flags:     0x58, // ECE|PSH|ACK
			wantFirst: 0x50,
			wantMid:   0x50,
			wantLast:  0x58,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := segmentReplyTCPOptions(remote, hostWAN, 443, 45000, 7, tc.flags, tcpOptionsTimestamp, bytes.Repeat([]byte{7}, 4000))
			pieces, err := segmentWANReplyTCP(pkt, maxLen)
			if err != nil || len(pieces) < 3 {
				t.Fatalf("flags %#02x: err=%v pieces=%d, want at least 3 pieces", tc.flags, err, len(pieces))
			}
			running := uint32(7)
			for i, piece := range pieces {
				requireValidSegment(t, piece, maxLen, remote.String(), hostWAN.String())
				if got := binary.BigEndian.Uint32(piece[20+4 : 20+8]); got != running {
					t.Fatalf("piece %d sequence = %d, want %d", i, got, running)
				}
				doff := int(piece[32]>>4) * 4
				running += uint32(len(piece) - 20 - doff)
				want := tc.wantMid
				switch i {
				case 0:
					want = tc.wantFirst
				case len(pieces) - 1:
					want = tc.wantLast
				}
				if got := piece[33]; got != want {
					t.Fatalf("piece %d flags = %#02x, want %#02x", i, got, want)
				}
			}
		})
	}
}

// TestHandleWANReplyRefusesUnsafeOptions is the production-path half of the option
// finding: an oversized reply carrying an option shape that cannot be replicated is
// refused as a whole — nothing reaches the client, and the refusal is counted once.
func TestHandleWANReplyRefusesUnsafeOptions(t *testing.T) {
	remote := netip.MustParseAddr("93.184.216.34")
	for _, tc := range []struct {
		name    string
		options []byte
	}{
		{"segment_specific_md5", append([]byte{19, 18}, make([]byte, 18)...)},
		{"nonzero_bytes_after_eol", []byte{0, 30, 4, 1}},
		{"unsupported_mptcp", []byte{30, 4, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostIsolationHarness(t, DirectEgressConfig{})
			h.allowDirect(remote)
			dispatchSegmentTestSYN(h, remote)
			natPort := h.natPort()

			before := len(h.capture.getPackets())
			reply := segmentReplyTCPOptions(remote, h.hostWAN, 80, natPort, 1_000_000, 0x18, tc.options, segmentTestPayload(4000))
			if err := h.dem.HandleWANReply(reply); !errors.Is(err, ErrPacketTooLarge) {
				t.Fatalf("options %x: want the pre-existing %v refusal, got %v", tc.options, ErrPacketTooLarge, err)
			}
			if got := len(h.capture.getPackets()); got != before {
				t.Fatalf("%d piece(s) reached the client for an option shape that cannot be replicated", got-before)
			}
			if got := h.fwd.DropsPacketTooLarge(); got != 1 {
				t.Fatalf("oversized-frame drop count = %d, want exactly 1", got)
			}
			if got := h.dem.DirectDrops(); got != 1 {
				t.Fatalf("direct egress drop count = %d, want exactly 1", got)
			}
		})
	}
}

// TestHandleWANReplyCWRPlacementDelivered is the production-path half of the CWR
// finding: the flags actually delivered to the client place CWR on the first piece
// only, keep ECE/ACK on every piece, and keep PSH on the last one.
func TestHandleWANReplyCWRPlacementDelivered(t *testing.T) {
	const (
		remotePort = uint16(80)
		clientPort = uint16(12345)
	)
	remote := netip.MustParseAddr("93.184.216.34")

	h := newHostIsolationHarness(t, DirectEgressConfig{})
	h.allowDirect(remote)
	dispatchSegmentTestSYN(h, remote)
	natPort := h.natPort()

	reply := segmentReplyTCPOptions(remote, h.hostWAN, remotePort, natPort, 5_000_000, 0xd8, tcpOptionsTimestamp, segmentTestPayload(4000))
	if err := h.dem.HandleWANReply(reply); err != nil {
		t.Fatalf("legitimate conventional-ECN reply refused: %v", err)
	}
	replies := collectReplies(t, h.capture.getPackets(), h.client, clientPort)
	if len(replies) < 3 {
		t.Fatalf("delivered %d piece(s), want at least 3", len(replies))
	}
	for i, r := range replies {
		last := i == len(replies)-1
		if got := r.flags & 0x80; (got != 0) != (i == 0) {
			t.Fatalf("piece %d flags %#02x: CWR must appear on the first piece only", i, r.flags)
		}
		if r.flags&0x40 == 0 {
			t.Fatalf("piece %d flags %#02x: ECE was lost", i, r.flags)
		}
		if r.flags&0x10 == 0 {
			t.Fatalf("piece %d flags %#02x: ACK was lost", i, r.flags)
		}
		if got := r.flags&0x08 != 0; got != last {
			t.Fatalf("piece %d flags %#02x: PSH belongs on the last piece only", i, r.flags)
		}
	}
	if drops := h.fwd.DropsPacketTooLarge(); drops != 0 {
		t.Fatalf("%d piece(s) were refused as too large", drops)
	}
}
