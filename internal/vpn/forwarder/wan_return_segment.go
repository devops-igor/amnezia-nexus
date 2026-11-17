package forwarder

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrWANReplyNotSegmentable reports an inbound WAN reply that is larger than the
// client MTU but cannot be split into TCP segments without changing its meaning.
// The reply is refused and counted as a drop, exactly as every oversized reply
// was refused before segmentation existed: the caller never approximates a shape
// this file does not support.
var ErrWANReplyNotSegmentable = errors.New("forwarder: wan reply cannot be segmented safely")

// TCP flag bits the segmenter must interpret.
const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagURG = 0x20
	tcpFlagCWR = 0x80
)

// tcpMinHeaderBytes is the smallest TCP header, with no options.
const tcpMinHeaderBytes = 20

// TCP option kinds and the timestamp option's fixed length. Only these are part
// of the supported contract documented on planWANReplySegment.
const (
	tcpOptEOL       = 0
	tcpOptNOP       = 1
	tcpOptTimestamp = 8
	tcpTimestampLen = 10
)

// maxWANReplySegments bounds the pieces one received frame can produce. An IPv4
// packet carries at most 65515 payload bytes, and a client-MTU-sized piece always
// carries at least clientMTU - maxHeaderBytes bytes, so the real bound is far
// below this ceiling; it exists so the emitting loop can never be unbounded by
// construction rather than by arithmetic a future edit might break.
const maxWANReplySegments = 64

// wanSegmentPlan is the validated description of one reply the segmenter can
// split. Everything the emitting loop needs is computed once, so that loop stays a
// bounded copy that cannot re-interpret the packet.
type wanSegmentPlan struct {
	headerLen  int
	totalLen   int
	payloadLen int
	maxPayload int
	seq        uint32
	ipID       uint16
	srcIP      [4]byte
	dstIP      [4]byte
	flags      uint8
}

// planWANReplySegment validates one received IPv4/TCP reply and returns the
// dimensions a split needs, or the reason it must be refused.
//
// Why this exists: the WAN capture socket returns frames assembled by the
// receiving host's aggregation offload (GRO) or sized by the remote path MTU, so a
// reply can be several kilobytes even though the client's plaintext MTU is
// smaller. The client device refuses anything above its MTU, and queue admission
// refuses anything above MaxClientQueuePacketBytes, so such a frame used to be
// discarded whole while the remote endpoint kept retransmitting.
//
// Supported input is deliberately narrow, and every refusal below is a distinct
// safety rule rather than defensive noise:
//
//   - TCP only. UDP has no transport-level segmentation, so an oversized UDP
//     reply is refused rather than fragmented or truncated.
//   - IPv4 without options. IP options describe the received datagram, not the
//     pieces produced from it, so an option-bearing frame is refused instead of
//     replicated.
//   - No fragmentation, and no trailing bytes past the declared IP length: a
//     frame whose payload extent is ambiguous is not guessed at.
//   - No SYN, RST or URG. A SYN that carries data starts the sequence space and
//     carries connection state; a RST is a whole-connection signal; the urgent
//     pointer is an offset into the received payload and would point into the
//     wrong piece.
//   - A client MTU that can carry the received header, since no piece can be
//     smaller than that header.
//   - A TCP option area drawn from the supported contract only: NOP, EOL
//     followed by zero padding, and Timestamp. Anyone replicating a received
//     options area onto several pieces is asserting that every option still
//     means the same thing on each piece, and that is only true for options that
//     describe the connection or the sender's clock rather than this segment.
//     MSS and window scale exist only on a SYN, SACK blocks describe received
//     ranges, MD5 covers this segment's exact bytes, and MPTCP is a different
//     transport; all of them are refused instead of being cloned into pieces
//     where their meaning would be wrong. The reserved bits of the header must
//     also be zero, as the segment is about to be rebuilt from this header.
func planWANReplySegment(packet []byte, maxLen int) (wanSegmentPlan, error) {
	var plan wanSegmentPlan
	if maxLen <= 0 {
		return plan, ErrWANReplyNotSegmentable
	}
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return plan, ErrWANReplyNotSegmentable
	}
	// An IPv4 header with options (IHL > 5) describes the received datagram, not
	// the pieces produced from it, and IHL < 5 is malformed.
	if int(packet[0]&0x0f) != 5 {
		return plan, ErrWANReplyNotSegmentable
	}
	const ihl = 20
	plan.totalLen = int(binary.BigEndian.Uint16(packet[2:4]))
	if plan.totalLen != len(packet) {
		return plan, ErrWANReplyNotSegmentable
	}
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return plan, ErrWANReplyNotSegmentable
	}
	if packet[9] != 6 {
		return plan, ErrWANReplyNotSegmentable
	}
	dataOffset := int(packet[ihl+12]>>4) * 4
	if dataOffset < tcpMinHeaderBytes || ihl+dataOffset > plan.totalLen {
		return plan, ErrWANReplyNotSegmentable
	}
	plan.flags = packet[ihl+13]
	if plan.flags&(tcpFlagSYN|tcpFlagRST|tcpFlagURG) != 0 {
		return plan, ErrWANReplyNotSegmentable
	}
	// RFC 9293 leaves these four header bits reserved; a segment that sets them
	// is not a shape this normalizer may rebuild.
	if packet[ihl+12]&0x0f != 0 {
		return plan, fmt.Errorf("%w: reserved TCP header bits are set", ErrWANReplyNotSegmentable)
	}
	if err := validateWANTCPOptions(packet[ihl+20 : ihl+dataOffset]); err != nil {
		return plan, err
	}
	plan.headerLen = ihl + dataOffset
	plan.payloadLen = plan.totalLen - plan.headerLen
	plan.maxPayload = maxLen - plan.headerLen
	if plan.maxPayload <= 0 {
		return plan, ErrWANReplyNotSegmentable
	}
	plan.seq = binary.BigEndian.Uint32(packet[ihl+4 : ihl+8])
	plan.ipID = binary.BigEndian.Uint16(packet[4:6])
	plan.srcIP = [4]byte{packet[12], packet[13], packet[14], packet[15]}
	plan.dstIP = [4]byte{packet[16], packet[17], packet[18], packet[19]}
	return plan, nil
}

// validateWANTCPOptions applies the supported option contract to one received
// option area (the bytes between the fixed header and the payload).
//
// The contract is deliberately narrow: NOP, a single EOL whose remaining bytes
// are zero padding, and the Timestamp option. Each is legal on a data-bearing
// segment and means the same thing on every piece produced from it, so cloning
// them is a faithful description. Every other kind is refused, including shapes
// such as MD5 whose value covers the exact segment bytes and would therefore be
// wrong on every piece after the first.
func validateWANTCPOptions(options []byte) error {
	for i := 0; i < len(options); {
		switch options[i] {
		case tcpOptEOL:
			// Everything after EOL is padding and must be zero.
			for _, b := range options[i+1:] {
				if b != 0 {
					return fmt.Errorf("%w: non-zero bytes after the end-of-options marker", ErrWANReplyNotSegmentable)
				}
			}
			return nil
		case tcpOptNOP:
			i++
		case tcpOptTimestamp:
			if i+2 > len(options) {
				return fmt.Errorf("%w: truncated timestamp option", ErrWANReplyNotSegmentable)
			}
			if options[i+1] != tcpTimestampLen {
				return fmt.Errorf("%w: timestamp option length %d, want %d", ErrWANReplyNotSegmentable, options[i+1], tcpTimestampLen)
			}
			if i+tcpTimestampLen > len(options) {
				return fmt.Errorf("%w: timestamp option overruns the header", ErrWANReplyNotSegmentable)
			}
			i += tcpTimestampLen
		default:
			return fmt.Errorf("%w: unsupported TCP option kind %d", ErrWANReplyNotSegmentable, options[i])
		}
	}
	return nil
}

// segmentWANReplyTCP splits one inbound IPv4/TCP packet into packets no longer
// than maxLen bytes, and returns a single unchanged packet when it already fits.
//
// What the produced pieces mean:
//
//   - The received TCP header is replicated on every piece, including its options
//     (timestamps and SACK information stay valid for both). The sequence number
//     advances by the payload already emitted, so the remote endpoint's byte
//     stream is preserved exactly.
//   - FIN and PSH move to the last piece, because both describe the end of the
//     byte run the remote endpoint sent; ACK and ECE are replicated because they
//     describe the connection's current acknowledgment and ECN state. CWR is not
//     replicated: it marks the first data segment after the sender reduced its
//     congestion window, so only the first generated piece carries it.
//   - The IPv4 identification field advances by one per piece, as a segmenting
//     device does; DF and the fragment fields are otherwise preserved.
//   - Every produced packet carries freshly computed IPv4 and TCP checksums over
//     its own bytes. The received checksum field is never copied and never
//     trusted: with receive checksum offload it may be a hardware placeholder,
//     and in any case a piece's checksum covers a different length than the
//     aggregate's. Recomputing is the same rule the DNAT step already follows for
//     every reply, so segmentation adds no new trust in the received bytes.
func segmentWANReplyTCP(packet []byte, maxLen int) ([][]byte, error) {
	plan, err := planWANReplySegment(packet, maxLen)
	if err != nil {
		return nil, err
	}
	if plan.totalLen <= maxLen {
		// Already small enough for the client device: return it untouched rather
		// than rebuilding a packet that needs no change.
		return [][]byte{packet}, nil
	}
	// plan.maxPayload > 0 and plan.totalLen > maxLen together guarantee
	// plan.payloadLen > 0: the header cannot exceed the frame it describes, so a
	// frame larger than the client MTU always carries at least one payload byte
	// in every admissible split.

	segments := make([][]byte, 0, (plan.payloadLen+plan.maxPayload-1)/plan.maxPayload)
	for offset := 0; offset < plan.payloadLen; offset += plan.maxPayload {
		end := offset + plan.maxPayload
		if end > plan.payloadLen {
			end = plan.payloadLen
		}
		if len(segments) == maxWANReplySegments {
			return nil, ErrWANReplyNotSegmentable
		}
		seg := make([]byte, plan.headerLen+(end-offset))
		copy(seg, packet[:plan.headerLen])
		copy(seg[plan.headerLen:], packet[plan.headerLen+offset:plan.headerLen+end])
		binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))                // #nosec G115 -- len(seg) <= maxLen <= MaxClientQueuePacketBytes.
		binary.BigEndian.PutUint16(seg[4:6], plan.ipID+uint16(len(segments))) // #nosec G115 -- len(segments) < maxWANReplySegments.
		binary.BigEndian.PutUint32(seg[20+4:20+8], plan.seq+uint32(offset))   // #nosec G115 -- offset <= 65535.
		// CWR is a single-segment signal: the sender sets it on the first new data
		// segment after it reduced its congestion window (RFC 3168 section 6.1.2),
		// so only the first generated piece carries it. ECE describes the
		// connection's current ECN state and is replicated. FIN and PSH describe
		// the end of the run and belong to the last piece.
		segFlags := plan.flags
		if offset > 0 {
			segFlags &^= tcpFlagCWR
		}
		if end < plan.payloadLen {
			segFlags &^= tcpFlagFIN | tcpFlagPSH
		}
		seg[20+13] = segFlags
		binary.BigEndian.PutUint16(seg[10:12], 0)
		binary.BigEndian.PutUint16(seg[10:12], computeIPv4Checksum(seg[:20]))
		binary.BigEndian.PutUint16(seg[20+16:20+18], 0)
		binary.BigEndian.PutUint16(seg[20+16:20+18], computeL4Checksum(plan.srcIP, plan.dstIP, 6, seg[20:]))
		segments = append(segments, seg)
	}
	return segments, nil
}
