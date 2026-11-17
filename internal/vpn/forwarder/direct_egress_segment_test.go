//go:build linux

package forwarder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// directSegmentClientMTU is the plaintext MTU the portal client device enforces
// on every return packet it injects. It is read from the same definition the
// portal device is configured with, so this expectation cannot drift away from
// the gate it describes: the return path must deliver pieces that satisfy
// exactly that gate.
const directSegmentClientMTU = virtualtun.DefaultMTU

// segmentReplyTCP builds one inbound WAN reply frame: an IPv4/TCP packet from the
// remote endpoint to the host WAN address, carrying payload bytes.
func segmentReplyTCP(src, dst netip.Addr, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	pkt := make([]byte, 20+20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt))) // #nosec G115 -- bounded by the test payload
	binary.BigEndian.PutUint16(pkt[4:6], 4242)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 63
	pkt[9] = 6
	srcBytes, dstBytes := src.As4(), dst.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(pkt[10:12], computeIPv4Checksum(pkt[:20]))

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], ack)
	pkt[32] = 0x50
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 64240)
	copy(pkt[40:], payload)
	binary.BigEndian.PutUint16(pkt[36:38], computeL4Checksum(srcBytes, dstBytes, 6, pkt[20:]))
	return pkt
}

// segmentTestPayload returns deterministic bytes so a delivered stream can be
// compared with what the remote endpoint sent.
func segmentTestPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*7 + i/251)
	}
	return p
}

// dispatchSegmentTestSYN allocates the direct-NAT binding for one TCP flow by
// sending the client's SYN through the authentic forwarder.
func dispatchSegmentTestSYN(h *hostIsolationHarness, remote netip.Addr) {
	_ = h.fwd.RouteClientToBackend(h.peerKey, buildTestIPv4TCPPacket(h.client, remote, 12345, 80, 0x02, nil))
}

// deliveredReply is one packet that reached the owning peer's return path.
type deliveredReply struct {
	packet  []byte
	payload []byte
	seq     uint32
	flags   uint8
}

// collectReplies decodes the TCP payload of every captured return packet and
// validates each one the way a client stack would: IPv4 shape, an IPv4 header
// checksum that sums to zero over the header, and a TCP checksum that sums to
// zero over the pseudo-header plus the segment.
func collectReplies(t *testing.T, pkts [][]byte, wantDst netip.Addr, wantPort uint16) []deliveredReply {
	t.Helper()
	out := make([]deliveredReply, 0, len(pkts))
	for i, p := range pkts {
		if len(p) < 40 || p[0]>>4 != 4 {
			t.Fatalf("reply %d is not an IPv4 packet: %d bytes", i, len(p))
		}
		ihl := int(p[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(p[2:4]))
		if ihl != 20 || total != len(p) {
			t.Fatalf("reply %d: ihl=%d total=%d len=%d, want 20/%d/%d", i, ihl, total, len(p), len(p), len(p))
		}
		if p[9] != 6 {
			t.Fatalf("reply %d: protocol %d, want TCP", i, p[9])
		}
		if binary.BigEndian.Uint16(p[6:8]) != 0x4000 {
			t.Fatalf("reply %d: flags/fragment field = %#04x, want DF with no fragment offset", i, binary.BigEndian.Uint16(p[6:8]))
		}
		if checksumValidIPv4(p[:ihl]) == false {
			t.Fatalf("reply %d: IPv4 header checksum was not recomputed for the delivered segment", i)
		}
		dst := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
		if dst != wantDst {
			t.Fatalf("reply %d: destination %s, want the owning client %s", i, dst, wantDst)
		}
		if gotPort := binary.BigEndian.Uint16(p[22:24]); gotPort != wantPort {
			t.Fatalf("reply %d: destination port %d, want the client port %d", i, gotPort, wantPort)
		}
		src := netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]})
		if !checksumValidL4(src.As4(), dst.As4(), p[9], p[ihl:]) {
			t.Fatalf("reply %d: TCP checksum does not cover the delivered segment", i)
		}
		doff := int(p[ihl+12]>>4) * 4
		if doff < 20 || ihl+doff > len(p) {
			t.Fatalf("reply %d: TCP data offset %d is invalid for a %d byte segment", i, doff, len(p))
		}
		out = append(out, deliveredReply{
			packet:  p,
			payload: p[ihl+doff:],
			seq:     binary.BigEndian.Uint32(p[ihl+4 : ihl+8]),
			flags:   p[ihl+13],
		})
	}
	return out
}

// checksumValidIPv4 reports whether an IPv4 header already containing its
// checksum sums to zero, which is the property a receiver verifies. It is
// deliberately a property check, not a call to the producer's own checksum
// routine.
func checksumValidIPv4(header []byte) bool {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}

// checksumValidL4 reports whether a transport segment already containing its
// checksum sums to zero over the IPv4 pseudo-header, which is the property a
// receiver verifies.
func checksumValidL4(src, dst [4]byte, protocol uint8, segment []byte) bool {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(protocol)
	sum += uint32(len(segment)) // #nosec G115 -- test payloads are far below 64 KiB
	for i := 0; i+1 < len(segment); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(segment[i : i+2]))
	}
	if len(segment)%2 != 0 {
		sum += uint32(segment[len(segment)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}

// TestDirectEgress_OversizedTCPReplyReachesTheClientInMTUSizedPieces is the repair
// oracle for the measured defect: the WAN reader returns frames larger than the
// client MTU (aggregation offload or a path-MTU mismatch) and the queue admission
// guard refused every one of them, so a download stalled while the remote endpoint
// retransmitted.
//
// The assertions are on delivered packets and their contents, not on elapsed time
// or on a helper's return value: every piece must satisfy the client MTU gate, the
// concatenated payload must be byte-identical to what the remote endpoint sent, and
// the oversized-frame drop counter must not move.
func TestDirectEgress_OversizedTCPReplyReachesTheClientInMTUSizedPieces(t *testing.T) {
	const (
		remotePort = uint16(80)
		clientPort = uint16(12345)
		firstSeq   = uint32(1_000_000)
	)
	remote := netip.MustParseAddr("93.184.216.34")

	for _, tc := range []struct {
		name        string
		payloadLen  int
		wantPieces  int
		description string
	}{
		{"one_byte_payload", 1, 1, "a normal small reply keeps its single packet"},
		{"exactly_client_mtu", directSegmentClientMTU - 40, 1, "a reply of exactly the client MTU needs no split"},
		{"one_byte_over_client_mtu", directSegmentClientMTU - 39, 2, "one byte over the client MTU is delivered as two pieces"},
		{"aggregated_burst", 4000, 3, "a measured oversized aggregate is delivered in client-MTU pieces"},
		{"maximum_ipv4_payload", 60000, 44, "the largest possible frame stays bounded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostIsolationHarness(t, DirectEgressConfig{})
			h.allowDirect(remote)
			if err := h.fwd.RouteClientToBackend(h.peerKey, buildTestIPv4TCPPacket(h.client, remote, clientPort, remotePort, 0x02, nil)); err != nil {
				t.Fatalf("client SYN dispatch: %v", err)
			}
			natPort := h.natPort()

			payload := segmentTestPayload(tc.payloadLen)
			reply := segmentReplyTCP(remote, h.hostWAN, remotePort, natPort, firstSeq, 1, 0x18 /* PSH|ACK */, payload)
			bytesBefore := h.dem.DirectBytes()

			if err := h.dem.HandleWANReply(reply); err != nil {
				t.Fatalf("%s: legitimate direct TCP reply refused: %v", tc.description, err)
			}

			pkts := h.capture.getPackets()
			if len(pkts) != tc.wantPieces {
				t.Fatalf("%s: delivered %d packet(s), want %d (frame %d bytes, client MTU %d)",
					tc.description, len(pkts), tc.wantPieces, len(reply), directSegmentClientMTU)
			}
			replies := collectReplies(t, pkts, h.client, clientPort)
			for i, r := range replies {
				if len(r.packet) > directSegmentClientMTU {
					t.Fatalf("piece %d is %d bytes, above the %d byte client MTU gate", i, len(r.packet), directSegmentClientMTU)
				}
			}

			var got []byte
			for i, r := range replies {
				if want := firstSeq + uint32(len(got)); r.seq != want {
					t.Fatalf("piece %d: sequence %d, want %d", i, r.seq, want)
				}
				last := i == len(replies)-1
				if last && r.flags&0x18 != 0x18 {
					t.Fatalf("last piece: flags %#02x, want PSH and ACK preserved", r.flags)
				}
				if !last && r.flags&0x08 != 0 {
					t.Fatalf("piece %d: PSH set before the end of the burst", i)
				}
				if !last && r.flags&0x01 != 0 {
					t.Fatalf("piece %d: FIN set before the end of the burst", i)
				}
				got = append(got, r.payload...)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("delivered payload differs from what the remote endpoint sent: got %d bytes, want %d", len(got), len(payload))
			}
			if drops := h.fwd.DropsPacketTooLarge(); drops != 0 {
				t.Fatalf("%d piece(s) were refused as too large; the delivered pieces do not satisfy the admission guard", drops)
			}
			if drops := h.dem.DirectDrops(); drops != 0 {
				t.Fatalf("%d direct reply packet(s) were counted as dropped", drops)
			}
			var delivered int64
			for _, r := range replies {
				delivered += int64(len(r.packet))
			}
			if got := h.dem.DirectBytes() - bytesBefore; got != delivered {
				t.Fatalf("direct egress byte accounting = %d, want the %d bytes actually delivered", got, delivered)
			}
		})
	}
}

// TestDirectEgress_UnsupportedOversizedReplyStillRefusedOnce proves the repair did
// not widen what the reply path accepts. Shapes the segmenter cannot split safely
// keep the pre-repair outcome: one refusal and exactly one counted drop, never a
// best-effort approximation.
func TestDirectEgress_UnsupportedOversizedReplyStillRefusedOnce(t *testing.T) {
	remote := netip.MustParseAddr("93.184.216.34")
	for _, tc := range []struct {
		name     string
		dispatch func(h *hostIsolationHarness)
		build    func(h *hostIsolationHarness, natPort uint16) []byte
	}{
		{
			name: "udp_cannot_be_segmented",
			dispatch: func(h *hostIsolationHarness) {
				_ = h.fwd.RouteClientToBackend(h.peerKey, buildTestIPv4UDPPacket(h.client, remote, 12345, 53, []byte("q")))
			},
			build: func(h *hostIsolationHarness, natPort uint16) []byte {
				return buildTestIPv4UDPPacket(remote, h.hostWAN, 53, natPort, segmentTestPayload(4000))
			},
		},
		{
			name:     "tcp_urgent_pointer",
			dispatch: func(h *hostIsolationHarness) { dispatchSegmentTestSYN(h, remote) },
			build: func(h *hostIsolationHarness, natPort uint16) []byte {
				return segmentReplyTCP(remote, h.hostWAN, 80, natPort, 7, 1, 0x18|0x20, segmentTestPayload(4000))
			},
		},
		{
			name:     "tcp_syn_with_payload",
			dispatch: func(h *hostIsolationHarness) { dispatchSegmentTestSYN(h, remote) },
			build: func(h *hostIsolationHarness, natPort uint16) []byte {
				return segmentReplyTCP(remote, h.hostWAN, 80, natPort, 7, 0, 0x02, segmentTestPayload(4000))
			},
		},
		{
			name:     "tcp_reset_with_payload",
			dispatch: func(h *hostIsolationHarness) { dispatchSegmentTestSYN(h, remote) },
			build: func(h *hostIsolationHarness, natPort uint16) []byte {
				return segmentReplyTCP(remote, h.hostWAN, 80, natPort, 7, 1, 0x14, segmentTestPayload(4000))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostIsolationHarness(t, DirectEgressConfig{})
			h.allowDirect(remote)
			tc.dispatch(h)
			natPort := h.natPort()

			before := len(h.capture.getPackets())
			err := h.dem.HandleWANReply(tc.build(h, natPort))
			if !errors.Is(err, ErrPacketTooLarge) {
				t.Fatalf("oversized unsupported reply: want %v, got %v", ErrPacketTooLarge, err)
			}
			if got := len(h.capture.getPackets()); got != before {
				t.Fatalf("%d packet(s) reached the client for an unsupported oversized reply", got-before)
			}
			if got := h.fwd.DropsPacketTooLarge(); got != 1 {
				t.Fatalf("oversized-frame drop count = %d, want exactly 1", got)
			}
			if got := h.dem.DirectDrops(); got != 1 {
				t.Fatalf("direct egress drop count = %d, want exactly 1 for the refused frame", got)
			}
		})
	}
}

// TestDirectEgress_OversizedReplyKeepsSessionOwnershipChecks proves the split is
// not a way around the reply filters: an oversized frame that fails the NAT,
// session or ownership checks delivers nothing at all.
func TestDirectEgress_OversizedReplyKeepsSessionOwnershipChecks(t *testing.T) {
	remote := netip.MustParseAddr("93.184.216.34")
	spoofed := netip.MustParseAddr("93.184.216.99")

	t.Run("remote_endpoint_mismatch", func(t *testing.T) {
		h := newHostIsolationHarness(t, DirectEgressConfig{})
		h.allowDirect(remote)
		if err := h.fwd.RouteClientToBackend(h.peerKey, buildTestIPv4TCPPacket(h.client, remote, 12345, 80, 0x02, nil)); err != nil {
			t.Fatalf("client SYN dispatch: %v", err)
		}
		natPort := h.natPort()

		before := len(h.capture.getPackets())
		err := h.dem.HandleWANReply(segmentReplyTCP(spoofed, h.hostWAN, 80, natPort, 9, 1, 0x18, segmentTestPayload(4000)))
		if err == nil {
			t.Fatal("an oversized reply from the wrong remote endpoint was accepted")
		}
		if got := len(h.capture.getPackets()); got != before {
			t.Fatalf("%d oversized spoofed packet(s) reached a client", got-before)
		}
		if drops := h.fwd.DropsPacketTooLarge(); drops != 0 {
			t.Fatalf("spoofed reply was not refused by the NAT filter (%d too-large drops)", drops)
		}
	})

	t.Run("closed_return_path", func(t *testing.T) {
		h := newHostIsolationHarness(t, DirectEgressConfig{})
		h.allowDirect(remote)
		if err := h.fwd.RouteClientToBackend(h.peerKey, buildTestIPv4TCPPacket(h.client, remote, 12345, 80, 0x02, nil)); err != nil {
			t.Fatalf("client SYN dispatch: %v", err)
		}
		natPort := h.natPort()
		h.capture.path.Close()

		before := len(h.capture.getPackets())
		err := h.dem.HandleWANReply(segmentReplyTCP(remote, h.hostWAN, 80, natPort, 9, 1, 0x18, segmentTestPayload(4000)))
		if !errors.Is(err, ErrReturnPathClosed) {
			t.Fatalf("oversized reply on a closed return path: want %v, got %v", ErrReturnPathClosed, err)
		}
		if got := len(h.capture.getPackets()); got != before {
			t.Fatalf("%d packet(s) reached a closed return path", got-before)
		}
	})
}

// TestDirectWANReplyGuardUnchanged proves the queue admission guard was not raised:
// an oversized frame handed straight to the delivery admission is still refused and
// still counted, so the repair works by fitting the pieces below the guard rather
// than by relaxing it.
func TestDirectWANReplyGuardUnchanged(t *testing.T) {
	h := newHostIsolationHarness(t, DirectEgressConfig{})
	oversized := make([]byte, MaxClientQueuePacketBytes+1)
	err := h.fwd.DeliverDirectWANReply(h.peerKey, h.session, 0, h.capture.path, oversized)
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("admission of a %d byte frame: want %v, got %v", len(oversized), ErrPacketTooLarge, err)
	}
	if got := h.fwd.DropsPacketTooLarge(); got != 1 {
		t.Fatalf("oversized admission drop count = %d, want 1", got)
	}
	if got := len(h.capture.getPackets()); got != 0 {
		t.Fatalf("%d oversized frame(s) were delivered past the admission guard", got)
	}
}

// TestDirectEgress_SegmentedReplyPartialFailureIsCountedPerPiece covers the
// delivery failure of one piece of an already-admitted frame: the refused piece is
// counted once, the rest of the burst is still delivered, and the byte accounting
// stays equal to what actually arrived.
func TestDirectEgress_SegmentedReplyPartialFailureIsCountedPerPiece(t *testing.T) {
	const (
		remotePort = uint16(80)
		clientPort = uint16(12345)
	)
	remote := netip.MustParseAddr("93.184.216.34")
	hostWAN := netip.MustParseAddr("203.0.113.50")
	client := netip.MustParseAddr("10.100.0.2")

	var mu sync.Mutex
	attempts := 0
	var delivered []int
	path := NewReturnPath(func(_, _ string, pkt []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts == 2 {
			return 0, errors.New("client device write failed")
		}
		delivered = append(delivered, len(pkt))
		return len(pkt), nil
	})

	wanDev := newMockPacketDev()
	fwd := NewForwarder(nil, "10.100.0.0/16", 8)
	dem := NewDirectEgressManager(DirectEgressConfig{HostWANIP: hostWAN, WANDevice: wanDev}, fwd)
	t.Cleanup(func() {
		fwd.UnregisterSession("peer")
		_ = dem.Close()
	})
	fwd.SetDirectEgress(dem)
	fwd.SetPBREnabled(true)
	cache := newTestRouteCache()
	fwd.SetRouteCache(cache)
	fwd.RegisterSessionWithReturnPath("sess", "conn", "peer", client.String(), 1, path)
	cache.Set("sess", remote, policy.Direct)

	if err := fwd.RouteClientToBackend("peer", buildTestIPv4TCPPacket(client, remote, clientPort, remotePort, 0x02, nil)); err != nil {
		t.Fatalf("client SYN dispatch: %v", err)
	}
	wanPkts := wanDev.getPackets()
	if len(wanPkts) != 1 {
		t.Fatalf("expected one WAN packet for the SYN, got %d", len(wanPkts))
	}
	natPort := binary.BigEndian.Uint16(wanPkts[0][20:22])
	bytesBefore := dem.DirectBytes()

	reply := segmentReplyTCP(remote, hostWAN, remotePort, natPort, 1000, 1, 0x18, segmentTestPayload(4000))
	if err := dem.HandleWANReply(reply); err == nil {
		t.Fatal("the refused piece was not reported to the caller")
	}

	mu.Lock()
	got := append([]int(nil), delivered...)
	total := attempts
	mu.Unlock()
	if total != 3 {
		t.Fatalf("the frame produced %d delivery attempts, want 3 pieces", total)
	}
	if len(got) != 2 {
		t.Fatalf("%d pieces were delivered past the refused one, want 2", len(got))
	}
	if drops := dem.DirectDrops(); drops != 1 {
		t.Fatalf("direct drop count = %d, want exactly 1 for the refused piece", drops)
	}
	if drops := fwd.DropsPacketTooLarge(); drops != 0 {
		t.Fatalf("the pieces were refused as too large (%d), not by the client write", drops)
	}
	var sum int64
	for _, n := range got {
		sum += int64(n)
	}
	if delta := dem.DirectBytes() - bytesBefore; delta != sum {
		t.Fatalf("byte accounting = %d, want the %d bytes actually delivered", delta, sum)
	}
}
