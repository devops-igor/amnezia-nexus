package vpn

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// oversizedReturnPacket mirrors the reply shape the forwarder's size gate
// refuses: a self-consistent IPv4 header whose total length exceeds the queue
// bound, addressed to dest.
func oversizedReturnPacket(dest string, size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	binary.BigEndian.PutUint16(p[24:26], uint16(size-20))
	ip := netip.MustParseAddr(dest).As4()
	copy(p[16:20], ip[:])
	return p
}

// TestDropCategoriesSplitOversizedReturnsByProducer drives both real return
// producers and reads the split back through the production diagnostics
// assembly, then through the published JSON contract.
func TestDropCategoriesSplitOversizedReturnsByProducer(t *testing.T) {
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
	if _, err := fwd.TryRegisterSessionWithReturnPath("s", "c", "peer", "10.100.0.2", 7, 0, 0, path); err != nil {
		t.Fatalf("register session: %v", err)
	}

	if err := fwd.RouteBackendToClient(7, oversizedReturnPacket("10.100.0.2", 2040), "10.100.0.2"); !errors.Is(err, forwarder.ErrPacketTooLarge) {
		t.Fatalf("backend oversized reply: %v", err)
	}
	if err := fwd.DeliverDirectWANReply("peer", "", 0, path, oversizedReturnPacket("10.100.0.2", 4096)); !errors.Is(err, forwarder.ErrPacketTooLarge) {
		t.Fatalf("direct oversized reply: %v", err)
	}

	svc := &Service{forwarder: fwd}
	drops := svc.collectDropCategories()

	if drops.ReturnPacketTooLarge != 2 {
		t.Fatalf("return_packet_too_large = %d, want 2", drops.ReturnPacketTooLarge)
	}
	if drops.ReturnPacketTooLargeBackend != 1 || drops.ReturnPacketTooLargeBackendMaxBytes != 2040 {
		t.Fatalf("backend split = (%d, %d bytes), want (1, 2040)",
			drops.ReturnPacketTooLargeBackend, drops.ReturnPacketTooLargeBackendMaxBytes)
	}
	if drops.ReturnPacketTooLargeDirect != 1 || drops.ReturnPacketTooLargeDirectMaxBytes != 4096 {
		t.Fatalf("direct split = (%d, %d bytes), want (1, 4096)",
			drops.ReturnPacketTooLargeDirect, drops.ReturnPacketTooLargeDirectMaxBytes)
	}

	// The split partitions the aggregate loss, so it must never be added to it.
	if got := drops.ReturnPacketTooLargeBackend + drops.ReturnPacketTooLargeDirect; got != drops.ReturnPacketTooLarge {
		t.Fatalf("split total = %d, aggregate = %d: produced counters drifted", got, drops.ReturnPacketTooLarge)
	}
	if drops.ReturnTotalDrops != 2 || drops.TotalDrops != 2 {
		t.Fatalf("conservation lost: return_total=%d total=%d, want 2 and 2",
			drops.ReturnTotalDrops, drops.TotalDrops)
	}

	// The rate surface tracks DISJOINT loss reasons only. Publishing the split
	// as extra reasons would double-count every rejected reply in the rates.
	svc.sampleDropRates(0, time.Unix(1000, 0), &drops, 0)
	var rateSum float64
	for reason, rate := range drops.ReasonRates {
		rateSum += rate
		if reason == "return_packet_too_large_backend" || reason == "return_packet_too_large_direct" ||
			reason == "return_packet_too_large_backend_max_bytes" || reason == "return_packet_too_large_direct_max_bytes" {
			t.Fatalf("split key %q leaked into the loss-reason rates", reason)
		}
	}
	if rateSum != drops.TotalDropRatePps {
		t.Fatalf("reason rates sum to %v, published total drop rate is %v", rateSum, drops.TotalDropRatePps)
	}

	// Published contract: the keys an administrator reads on /api/vpn/status.
	raw, err := json.Marshal(Status{DropCategories: drops})
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	var decoded struct {
		DropCategories map[string]any `json:"drop_categories"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	for key, want := range map[string]float64{
		"return_packet_too_large":                   2,
		"return_packet_too_large_backend":           1,
		"return_packet_too_large_direct":            1,
		"return_packet_too_large_backend_max_bytes": 2040,
		"return_packet_too_large_direct_max_bytes":  4096,
	} {
		got, ok := decoded.DropCategories[key]
		if !ok {
			t.Fatalf("status JSON is missing drop_categories.%s: %s", key, raw)
		}
		if got != want {
			t.Fatalf("drop_categories.%s = %v, want %v", key, got, want)
		}
	}

	// Privacy bound: nothing but numbers is published for the split, so no
	// peer, session, address or payload can appear in those fields.
	for key := range map[string]struct{}{
		"return_packet_too_large_backend":           {},
		"return_packet_too_large_direct":            {},
		"return_packet_too_large_backend_max_bytes": {},
		"return_packet_too_large_direct_max_bytes":  {},
	} {
		if _, isNumber := decoded.DropCategories[key].(float64); !isNumber {
			t.Fatalf("drop_categories.%s is not a bounded number: %v", key, decoded.DropCategories[key])
		}
	}
}
