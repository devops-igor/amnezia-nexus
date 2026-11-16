package forwarder

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
)

// oversizedReturnPacket builds a well-formed IPv4/UDP reply of exactly size
// bytes addressed to dest. It has the shape a stack produces for an aggregated
// read — a total length above the queue bound with a self-consistent header —
// not a malformed frame, so the size gate is what refuses it.
func oversizedReturnPacket(dest string, size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	p[9] = 17 // UDP
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	binary.BigEndian.PutUint16(p[24:26], uint16(size-20))
	ip := netip.MustParseAddr(dest).As4()
	copy(p[16:20], ip[:])
	return p
}

// newOversizedReturnFixture registers one route whose return path accepts every
// write, so a refusal can only come from the size gate under test.
func newOversizedReturnFixture(t *testing.T) (*Forwarder, *ReturnPath) {
	t.Helper()
	f := NewForwarder(nil, "10.100.0.0/16", 8)
	path := NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
	if _, err := f.TryRegisterSessionWithReturnPath("s", "c", "peer", "10.100.0.2", 7, 0, 0, path); err != nil {
		t.Fatalf("register session: %v", err)
	}
	return f, path
}

// assertAttribution checks the split, its agreement with the aggregate counter
// and the return-drop total, so a discrepancy cannot hide in one of them.
func assertAttribution(t *testing.T, f *Forwarder, want OversizedReturnAttribution) {
	t.Helper()
	got := f.OversizedReturnStats()
	if got != want {
		t.Fatalf("attribution = %+v, want %+v", got, want)
	}
	if aggregate := f.DropsPacketTooLarge(); aggregate != want.BackendCount+want.DirectCount {
		t.Fatalf("aggregate oversized drops = %d, want %d (sum of producers)",
			aggregate, want.BackendCount+want.DirectCount)
	}
}

func TestBackendOversizedReturnIsAttributedToBackendProducer(t *testing.T) {
	f, _ := newOversizedReturnFixture(t)

	packet := oversizedReturnPacket("10.100.0.2", 2040)
	if err := f.RouteBackendToClient(7, packet, "10.100.0.2"); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("backend oversized reply: got %v, want ErrPacketTooLarge", err)
	}

	assertAttribution(t, f, OversizedReturnAttribution{BackendCount: 1, BackendMaxBytes: 2040})
	if _, _, total := f.DropStats(); total != 1 {
		t.Fatalf("return drop total = %d, want 1: the refusal must be booked exactly once", total)
	}
	if got := f.DropsPacketTooLarge(); got != 1 {
		t.Fatalf("aggregate oversized drops = %d, want 1", got)
	}
}

func TestDirectWANOversizedReturnIsAttributedToDirectProducer(t *testing.T) {
	f, path := newOversizedReturnFixture(t)
	hostWAN := netip.MustParseAddr("203.0.113.50")
	wanDev := newMockPacketDev()
	dem := NewDirectEgressManager(DirectEgressConfig{HostWANIP: hostWAN, WANDevice: wanDev}, f)
	t.Cleanup(func() { _ = dem.Close() })

	clientIP := netip.MustParseAddr("10.100.0.2")
	target := netip.MustParseAddr("93.184.216.34")
	syn := buildTestIPv4TCPPacket(clientIP, target, 51234, 80, 0x02, nil)
	if err := dem.RouteTCPDirect("peer", syn, path); err != nil {
		t.Fatalf("RouteTCPDirect: %v", err)
	}
	wanPackets := wanDev.getPackets()
	if len(wanPackets) != 1 {
		t.Fatalf("expected 1 forwarded packet, got %d", len(wanPackets))
	}
	natPort := binary.BigEndian.Uint16(wanPackets[0][20:22])

	// Positive control: a reply inside the bound is delivered and books no
	// oversized rejection, so the counter cannot be a write counter in disguise.
	accepted := buildTestIPv4TCPPacket(target, hostWAN, 80, natPort, 0x12, nil)
	if err := dem.HandleWANReply(accepted); err != nil {
		t.Fatalf("accepted direct reply: %v", err)
	}
	assertAttribution(t, f, OversizedReturnAttribution{})

	// The real oversized counterexample: an aggregated reply above the bound,
	// refused on the direct WAN return path and attributed to it alone.
	oversized := buildTestIPv4TCPPacket(target, hostWAN, 80, natPort, 0x12, make([]byte, 2000))
	if err := dem.HandleWANReply(oversized); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("direct oversized reply: got %v, want ErrPacketTooLarge", err)
	}
	assertAttribution(t, f, OversizedReturnAttribution{DirectCount: 1, DirectMaxBytes: uint64(len(oversized))})
	if _, _, total := f.DropStats(); total != 1 {
		t.Fatalf("return drop total = %d, want 1", total)
	}
}

func TestOversizedReturnSizeMetadataTracksLargestRefusalOnly(t *testing.T) {
	f, _ := newOversizedReturnFixture(t)
	dest := "10.100.0.2"

	// Accepted at the bound: no rejection, therefore no size metadata.
	if err := f.RouteBackendToClient(7, oversizedReturnPacket(dest, MaxClientQueuePacketBytes), dest); err != nil {
		t.Fatalf("reply at the bound must be accepted: %v", err)
	}
	assertAttribution(t, f, OversizedReturnAttribution{})

	for _, size := range []int{2000, 4096, 1601} {
		if err := f.RouteBackendToClient(7, oversizedReturnPacket(dest, size), dest); !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("reply of %d bytes: got %v, want ErrPacketTooLarge", size, err)
		}
	}

	// The maximum is the largest refused size and never decreases, so a later
	// smaller refusal cannot make the observation look milder than it was.
	assertAttribution(t, f, OversizedReturnAttribution{BackendCount: 3, BackendMaxBytes: 4096})
}

func TestStartResetsOversizedReturnAttribution(t *testing.T) {
	f, path := newOversizedReturnFixture(t)
	if err := f.RouteBackendToClient(7, oversizedReturnPacket("10.100.0.2", 2040), "10.100.0.2"); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("backend oversized reply: %v", err)
	}
	if err := f.DeliverDirectWANReply("peer", "", 0, path, oversizedReturnPacket("10.100.0.2", 3000)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("direct oversized reply: %v", err)
	}
	assertAttribution(t, f, OversizedReturnAttribution{
		BackendCount: 1, BackendMaxBytes: 2040, DirectCount: 1, DirectMaxBytes: 3000,
	})

	f.Start(t.Context())

	// Lifecycle reset drops the counts AND the sizes with the other drop
	// counters, so a post-restart window never reports a pre-restart maximum.
	assertAttribution(t, f, OversizedReturnAttribution{})

	if err := f.RouteBackendToClient(7, oversizedReturnPacket("10.100.0.2", 1800), "10.100.0.2"); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("post-reset backend oversized reply: %v", err)
	}
	assertAttribution(t, f, OversizedReturnAttribution{BackendCount: 1, BackendMaxBytes: 1800})
}

func TestOversizedReturnAttributionIsConsistentUnderConcurrentProducers(t *testing.T) {
	f, path := newOversizedReturnFixture(t)
	dest := "10.100.0.2"
	const perProducer = 100

	var wg sync.WaitGroup
	for i := range perProducer {
		size := 1600 + i%100
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = f.RouteBackendToClient(7, oversizedReturnPacket(dest, size), dest)
		}()
		go func() {
			defer wg.Done()
			_ = f.DeliverDirectWANReply("peer", "", 0, path, oversizedReturnPacket(dest, size))
		}()
	}
	wg.Wait()

	assertAttribution(t, f, OversizedReturnAttribution{
		BackendCount: perProducer, BackendMaxBytes: 1699,
		DirectCount: perProducer, DirectMaxBytes: 1699,
	})
	if _, _, total := f.DropStats(); total != 2*perProducer {
		t.Fatalf("return drop total = %d, want %d", total, 2*perProducer)
	}
}

func TestNilForwarderOversizedReturnStats(t *testing.T) {
	var f *Forwarder
	if got := f.OversizedReturnStats(); got != (OversizedReturnAttribution{}) {
		t.Fatalf("nil forwarder attribution = %+v, want zero", got)
	}
}
