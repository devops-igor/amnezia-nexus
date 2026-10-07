package vpn

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// realVtunBackendDevice is a BackendDevice backed by a REAL
// virtualtun.VirtualTUN — not a synthetic counter.
//
// It exists because the fixture the round-2 regressions used
// (testBackendDevice.dropCount) carries a single integer with no direction and
// no reason, so it cannot detect the defect this rework fixes: an integer
// total is exactly what the diagnostics layer used to publish as
// "client_backend_device_queue_full", whether the loss was client->backend or
// backend->client and whatever actually caused it. These regressions drive the
// real queue-full, oversized and shutdown paths of a real VirtualTUN and read
// the resulting axes back out through the production DeviceStats capability.
type realVtunBackendDevice struct {
	vtun *virtualtun.VirtualTUN
}

// newRealVtunBackendDevice builds a device whose VirtualTUN queues are one
// packet deep, so both directions saturate immediately and a test can produce
// inbound and outbound loss independently.
func newRealVtunBackendDevice(t *testing.T, name string) *realVtunBackendDevice {
	t.Helper()
	vt, err := virtualtun.New(virtualtun.Config{
		Name:             name,
		MTU:              1340,
		InboundCapacity:  1,
		OutboundCapacity: 1,
	})
	if err != nil {
		t.Fatalf("real VirtualTUN construction failed: %v", err)
	}
	t.Cleanup(func() { _ = vt.Close() })
	return &realVtunBackendDevice{vtun: vt}
}

func (d *realVtunBackendDevice) DeviceStats() virtualtun.StatsSnapshot { return d.vtun.Stats() }
func (d *realVtunBackendDevice) DroppedPackets() uint64                { return d.vtun.DroppedPackets() }
func (d *realVtunBackendDevice) LastHandshakeTime() time.Time          { return time.Time{} }
func (d *realVtunBackendDevice) CreatedAt() time.Time                  { return time.Time{} }
func (d *realVtunBackendDevice) IsClosed() bool                        { return false }

// Write is the production client->backend direction: AWGClientDevice.Write
// calls VirtualTUN.InjectInbound.
func (d *realVtunBackendDevice) Write(p []byte) (int, error) {
	if err := d.vtun.InjectInbound(p); err != nil {
		// Production treats a queue-full injection as accepted-but-dropped so
		// the forwarder does not tear down the tunnel over one lost packet.
		return len(p), nil
	}
	return len(p), nil
}

// Read is the production backend->client return direction:
// VirtualTUN.ReceiveOutbound feeds AWGClientDevice.Read.
func (d *realVtunBackendDevice) Read(p []byte) (int, error) {
	pkt, err := d.vtun.ReceiveOutbound()
	if err != nil {
		return 0, err
	}
	if len(pkt) > len(p) {
		// Oversized: the real Read path drops rather than truncates.
		d.vtun.RecordDrop()
		return 0, nil
	}
	return copy(p, pkt), nil
}

func (d *realVtunBackendDevice) Close() error { return d.vtun.Close() }

// deviceStatsForService installs the device as the service's only backend
// device and returns the service ready for a status sample.
func deviceStatsForService(t *testing.T) (*Service, *realVtunBackendDevice) {
	t.Helper()
	svc, _, _, _, _ := setupTestVPNService(t, setupTestDB(t))
	dev := newRealVtunBackendDevice(t, "backend-device-drop-axes")
	svc.backendDevices = map[int64]BackendDevice{1: dev}
	return svc, dev
}

// TestBackendDeviceDropDirectionUsesRealVirtualTUN is the core regression for
// finding 1: inbound and outbound loss on a REAL backend VirtualTUN must land
// in DIFFERENT populations.
//
// The topology it pins:
//
//	client -> backend : AWGClientDevice.Write -> VirtualTUN.Inbound
//	backend -> client : VirtualTUN.Outbound   -> AWGClientDevice.Read
//
// An outbound drop is backend->Nexus RETURN traffic. Before this rework it was
// added to client_total_drops as client_backend_device_queue_full, so return
// loss was reported as client-originated loss.
func TestBackendDeviceDropDirectionUsesRealVirtualTUN(t *testing.T) {
	svc, dev := deviceStatsForService(t)

	// Inbound (client -> backend): the 1-packet queue accepts the first
	// packet and refuses the next three as queue-full.
	if err := dev.vtun.InjectInbound([]byte("in-1")); err != nil {
		t.Fatalf("first inbound packet must be accepted: %v", err)
	}
	for range 3 {
		if err := dev.vtun.InjectInbound([]byte("in-2")); err == nil {
			t.Fatal("saturated inbound queue must refuse the packet")
		}
	}

	// Outbound (backend -> client): VirtualTUN.Write feeds the outbound queue,
	// which is also 1 deep. Read nothing, so it saturates the same way.
	if _, err := dev.vtun.Write([][]byte{[]byte("out-1")}, 0); err != nil {
		t.Fatalf("first outbound packet must be accepted: %v", err)
	}
	if _, err := dev.vtun.Write([][]byte{[]byte("out-2")}, 0); err != nil {
		t.Fatalf("outbound Write must report the drop as processed, not an error: %v", err)
	}

	var status Status
	svc.populateOperationalDiagnostics(&status)
	d := status.DropCategories

	// 3 inbound queue-full losses are client-originating.
	if d.ClientBackendDeviceQueueFull != 3 {
		t.Errorf("client_backend_device_queue_full=%d, want 3 inbound queue-full losses", d.ClientBackendDeviceQueueFull)
	}
	// 1 outbound queue-full loss is RETURN traffic and must not be in the
	// client population at all.
	if d.ReturnBackendDeviceQueueFull != 1 {
		t.Errorf("return_backend_device_queue_full=%d, want 1 outbound queue-full loss", d.ReturnBackendDeviceQueueFull)
	}
	if d.ClientTotalDrops != 3 {
		t.Errorf("client_total_drops=%d, want 3: return loss must not inflate the client population", d.ClientTotalDrops)
	}
	if d.ReturnTotalDrops != 1 {
		t.Errorf("return_total_drops=%d, want 1", d.ReturnTotalDrops)
	}
	if d.TotalDrops != 4 {
		t.Errorf("total_drops=%d, want 4", d.TotalDrops)
	}

	// Every reason population is disjoint and sums to the total.
	assertDisjointDropReasons(t, d)
}

// TestBackendDeviceNonQueueReasonIsNotReportedAsQueueFull pins the second half
// of finding 1: a shutdown drain is not queue-full loss, and an oversized read
// is not queue-full loss. Before this rework both were folded into
// client_backend_device_queue_full, so an operator reading that key could not
// tell a saturated queue from a device that was being retired.
func TestBackendDeviceNonQueueReasonIsNotReportedAsQueueFull(t *testing.T) {
	t.Run("shutdown drain is its own reason", func(t *testing.T) {
		svc, dev := deviceStatsForService(t)
		// Queue one packet in each direction, then close: Close drains both
		// queues and accounts each drained packet as a SHUTDOWN drop.
		if err := dev.vtun.InjectInbound([]byte("in-1")); err != nil {
			t.Fatalf("inbound enqueue failed: %v", err)
		}
		if _, err := dev.vtun.Write([][]byte{[]byte("out-1")}, 0); err != nil {
			t.Fatalf("outbound enqueue failed: %v", err)
		}
		if err := dev.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var status Status
		svc.populateOperationalDiagnostics(&status)
		d := status.DropCategories

		if d.ClientBackendDeviceShutdown != 1 || d.ReturnBackendDeviceShutdown != 1 {
			t.Errorf("shutdown drops not attributed per direction: client=%d return=%d",
				d.ClientBackendDeviceShutdown, d.ReturnBackendDeviceShutdown)
		}
		if d.ClientBackendDeviceQueueFull != 0 || d.ReturnBackendDeviceQueueFull != 0 {
			t.Errorf("a shutdown drain was reported as queue-full loss: client=%d return=%d",
				d.ClientBackendDeviceQueueFull, d.ReturnBackendDeviceQueueFull)
		}
		if d.ClientBackendDeviceOversized != 0 {
			t.Errorf("a shutdown drain was reported as oversized loss: %d", d.ClientBackendDeviceOversized)
		}
		assertDisjointDropReasons(t, d)
	})

	t.Run("oversized read is its own reason", func(t *testing.T) {
		svc, dev := deviceStatsForService(t)
		// Queue one inbound packet of 64 bytes, then read it into a 1-byte
		// destination. The real Read path drops an oversized packet rather
		// than truncating it, and that drop is INBOUND by construction: Read
		// drains the inbound queue.
		if err := dev.vtun.InjectInbound(make([]byte, 64)); err != nil {
			t.Fatalf("inbound enqueue failed: %v", err)
		}
		// VirtualTUN.Read is the AWG engine's read path: it drains the
		// INBOUND queue, so the oversized drop it takes is inbound by
		// construction. A 1-byte destination cannot hold the 64-byte packet.
		if _, err := dev.vtun.Read([][]byte{make([]byte, 1)}, []int{1}, 0); err != nil {
			t.Fatalf("oversized read must not error: %v", err)
		}

		var status Status
		svc.populateOperationalDiagnostics(&status)
		d := status.DropCategories

		if d.ClientBackendDeviceOversized != 1 {
			t.Errorf("client_backend_device_oversized=%d, want 1", d.ClientBackendDeviceOversized)
		}
		if d.ClientBackendDeviceQueueFull != 0 {
			t.Errorf("an oversized read was reported as queue-full loss: %d", d.ClientBackendDeviceQueueFull)
		}
		if d.ReturnBackendDeviceQueueFull != 0 || d.ReturnBackendDeviceShutdown != 0 {
			t.Errorf("an inbound oversized read leaked into the return population: %+v", d)
		}
		assertDisjointDropReasons(t, d)
	})
}

// TestBackendDeviceExternalRecordDropAttribution pins the decision that
// StatsSnapshot.Sum() cannot answer on its own.
//
// RecordDrop/RecordDropN raise DropsTotal and NOTHING else: no direction
// bucket, no reason bucket. A consumer that populated reason rates by summing
// buckets would silently under-report by exactly the external amount, and one
// that distributed the remainder across the directional buckets would invent a
// direction the recording API never supplied. The decision under test is:
// attribute it to the client-originating population, under its own key, so it
// stays visible and TotalDrops stays truthful.
func TestBackendDeviceExternalRecordDropAttribution(t *testing.T) {
	svc, dev := deviceStatsForService(t)

	// Produce a REAL queue-full loss first, so the snapshot contains both a
	// measured internal drop and an external one and the test can prove the
	// remainder is separated rather than merged.
	//
	// The device's inbound queue is one packet deep, so packet 1 is admitted
	// and packet 2 is genuinely refused with ErrQueueFull. Assert the refusal
	// itself: if this queue ever became deeper than one packet the loss below
	// would not happen, and the external-vs-internal split this test pins
	// would silently become vacuous.
	if err := dev.vtun.InjectInbound([]byte("in-1")); err != nil {
		t.Fatalf("first inbound packet must be admitted: %v", err)
	}
	if err := dev.vtun.InjectInbound([]byte("in-2")); !errors.Is(err, virtualtun.ErrQueueFull) {
		t.Fatalf("second inbound packet onto a 1-deep queue: err=%v, want %v: the queue-full loss this test measures would not exist",
			err, virtualtun.ErrQueueFull)
	}
	// One internal loss happened above; add three more recorded externally.
	dev.vtun.RecordDrop()
	dev.vtun.RecordDropN(2)

	snap := dev.vtun.Stats()
	if snap.DropsTotal != 4 {
		t.Fatalf("DropsTotal=%d, want 4 (1 internal + 3 external)", snap.DropsTotal)
	}
	if snap.Sum() != 1 {
		t.Fatalf("Sum()=%d, want 1: external drops must be excluded from the reason buckets", snap.Sum())
	}
	if snap.ExternalDrops() != 3 {
		t.Fatalf("ExternalDrops()=%d, want 3: the remainder must be visible, not dropped", snap.ExternalDrops())
	}

	var status Status
	svc.populateOperationalDiagnostics(&status)
	d := status.DropCategories

	if d.ClientBackendDeviceQueueFull != 1 {
		t.Errorf("client_backend_device_queue_full=%d, want only the 1 measured queue-full loss", d.ClientBackendDeviceQueueFull)
	}
	if d.ClientBackendDeviceExternal != 3 {
		t.Errorf("client_backend_device_external=%d, want 3", d.ClientBackendDeviceExternal)
	}
	if d.ReturnTotalDrops != 0 {
		t.Errorf("reason-less external drops were given a return direction: %d", d.ReturnTotalDrops)
	}
	assertDisjointDropReasons(t, d)
}

// TestBackendDeviceUnattributedLossIsReportedNotDropped pins the fallback: a
// device that cannot report the axes still contributes real loss, so it is
// published under its own key instead of disappearing from the total.
func TestBackendDeviceUnattributedLossIsReportedNotDropped(t *testing.T) {
	svc, _, _, _, _ := setupTestVPNService(t, setupTestDB(t))
	opaque := &noStatsDevice{}
	opaque.dropped.Add(9)
	svc.backendDevices = map[int64]BackendDevice{1: opaque}

	var status Status
	svc.populateOperationalDiagnostics(&status)
	d := status.DropCategories

	if d.BackendDeviceUnattributed != 9 {
		t.Errorf("backend_device_unattributed=%d, want 9", d.BackendDeviceUnattributed)
	}
	if d.ClientBackendDeviceQueueFull != 0 || d.ClientBackendDeviceExternal != 0 {
		t.Errorf("unattributable loss was spread into a reason bucket: %+v", d)
	}
	// Direction-neutral (issue #429 review round 3, blocker 3): the loss is
	// real, so it must appear in the total, but in NEITHER directional total.
	if d.ClientTotalDrops != 0 || d.ReturnTotalDrops != 0 {
		t.Errorf("directionless loss was attributed to a direction: client=%d return=%d",
			d.ClientTotalDrops, d.ReturnTotalDrops)
	}
	if d.TotalDrops != 9 {
		t.Errorf("total_drops=%d, want 9: loss conservation requires the unattributed loss in the total", d.TotalDrops)
	}
	assertDisjointDropReasons(t, d)
}

// TestRetiredDeviceDropsKeepTheirDirectionAndReason pins the retired-device
// treatment under round 5, finding 1: retirement is a TRANSFER of the device's
// real direction x reason breakdown, so the loss keeps both the direction and
// the reason it was measured with. The retired-directionless bucket keeps its
// own key (there is no direction to publish it under), and a retirement can
// neither shrink the lifetime total nor relabel a loss.
func TestRetiredDeviceDropsGetTheirOwnKey(t *testing.T) {
	svc, dev := deviceStatsForService(t)
	if err := dev.vtun.InjectInbound([]byte("in-1")); err != nil {
		t.Fatalf("inbound enqueue failed: %v", err)
	}
	if err := dev.vtun.InjectInbound([]byte("in-2")); !errors.Is(err, virtualtun.ErrQueueFull) {
		t.Fatalf("second inbound packet onto a 1-deep queue: err=%v, want %v: retirement below folds one real queue-full loss into the accumulator, and without it this test would pin nothing",
			err, virtualtun.ErrQueueFull)
	}
	// Retire the device the way retirement does: transfer its direction x
	// reason breakdown into the accumulator and drop it from the map.
	svc.mu.Lock()
	svc.retiredBackendDeviceDrops.addInto(snapshotBackendDeviceDrops(dev))
	svc.backendDevices = map[int64]BackendDevice{}
	svc.mu.Unlock()

	var status Status
	svc.populateOperationalDiagnostics(&status)
	d := status.DropCategories

	// The loss was measured as INBOUND queue-full loss, so it stays in the
	// inbound queue-full key: same direction, same reason, same value.
	if d.ClientBackendDeviceQueueFull != 1 {
		t.Errorf("client_backend_device_queue_full=%d, want 1: retirement must preserve the reason the loss was measured with; %+v",
			d.ClientBackendDeviceQueueFull, d)
	}
	if d.ClientBackendDeviceExternal != 0 || d.ClientBackendDeviceOversized != 0 ||
		d.ClientBackendDeviceShutdown != 0 || d.BackendDeviceUnattributed != 0 {
		t.Errorf("retired loss was reclassified into a bucket it was never measured in: %+v", d)
	}
	if d.ReturnBackendDeviceQueueFull != 0 || d.ReturnBackendDeviceShutdown != 0 {
		t.Errorf("a client-direction loss moved into the return population: %+v", d)
	}
	if d.TotalDrops != 1 {
		t.Errorf("total_drops=%d, want 1: retirement must preserve the lifetime total", d.TotalDrops)
	}
	assertDisjointDropReasons(t, d)
}

// assertDisjointDropReasons is the machine-checked form of the ownership
// invariant every one of the tests above must preserve: the published reason
// key set sums, per direction, to the published direction total, and the two
// direction totals sum to the overall total. Nothing is counted twice and
// nothing is silently dropped.
func assertDisjointDropReasons(t *testing.T, d DropCategoryBreakdown) {
	t.Helper()
	client := map[string]uint64{
		"client_malformed":                 d.ClientMalformed,
		"client_unmapped_source":           d.ClientUnmappedSource,
		"client_mismatch":                  d.ClientMismatch,
		"client_rejected":                  d.ClientRejected,
		"client_backend_queue_full":        d.ClientBackendQueueFull,
		"client_rate_limited":              d.ClientRateLimited,
		"client_no_healthy_backend":        d.ClientNoHealthyBackend,
		"client_virtualtun_drops":          d.ClientVirtualTUNDrops,
		"client_backend_device_queue_full": d.ClientBackendDeviceQueueFull,
		"client_backend_device_oversized":  d.ClientBackendDeviceOversized,
		"client_backend_device_shutdown":   d.ClientBackendDeviceShutdown,
		"client_backend_device_external":   d.ClientBackendDeviceExternal,
	}
	ret := map[string]uint64{
		"return_malformed":                 d.ReturnMalformed,
		"return_unmapped":                  d.ReturnUnmapped,
		"return_mismatch":                  d.ReturnMismatch,
		"return_injection_errors":          d.ReturnInjectionErrors,
		"return_virtualtun_drops":          d.ReturnVirtualTUNDrops,
		"return_queue_full":                d.ReturnQueueFull,
		"return_packet_too_large":          d.ReturnPacketTooLarge,
		"return_backend_device_queue_full": d.ReturnBackendDeviceQueueFull,
		"return_backend_device_shutdown":   d.ReturnBackendDeviceShutdown,
	}
	var clientSum, returnSum uint64
	for key, v := range client {
		clientSum += v
		if _, clash := ret[key]; clash {
			t.Fatalf("reason %q is published in both directions: populations are not disjoint", key)
		}
	}
	for _, v := range ret {
		returnSum += v
	}
	if clientSum != d.ClientTotalDrops {
		t.Errorf("client reasons sum to %d but client_total_drops=%d", clientSum, d.ClientTotalDrops)
	}
	if returnSum != d.ReturnTotalDrops {
		t.Errorf("return reasons sum to %d but return_total_drops=%d", returnSum, d.ReturnTotalDrops)
	}
	// backend_device_unattributed is the direction-neutral population: real
	// loss, so it is conserved in the total, but owned by neither direction
	// (issue #429 review round 3, blocker 3).
	if d.ClientTotalDrops+d.ReturnTotalDrops+d.BackendDeviceUnattributed != d.TotalDrops {
		t.Errorf("total_drops=%d but client(%d)+return(%d)+neutral(%d)=%d",
			d.TotalDrops, d.ClientTotalDrops, d.ReturnTotalDrops, d.BackendDeviceUnattributed,
			d.ClientTotalDrops+d.ReturnTotalDrops+d.BackendDeviceUnattributed)
	}
	// return_injection_tun_drops documents an OWNERSHIP OVERLAP with the
	// return VirtualTUN bucket, not an additional loss reason, so it is
	// excluded from the sum above. It must therefore never be counted into a
	// total either.
	if d.ReturnInjectionTUNDrops > d.ReturnTotalDrops {
		t.Errorf("return_injection_tun_drops=%d exceeds return_total_drops=%d: an overlap was counted as loss",
			d.ReturnInjectionTUNDrops, d.ReturnTotalDrops)
	}
}

// noStatsDevice is a BackendDevice that deliberately does NOT implement
// backendDeviceStatsProvider, standing in for a device whose loss has no
// direction or reason to report (a plain socket, an older device). It must be
// a standalone type rather than one embedding testBackendDevice, which would
// promote DeviceStats and satisfy the interface by accident.
type noStatsDevice struct {
	dropped atomic.Uint64
}

func (d *noStatsDevice) Read(_ []byte) (int, error) { return 0, nil }
func (d *noStatsDevice) Write(p []byte) (int, error) {
	return len(p), nil
}
func (d *noStatsDevice) Close() error                 { return nil }
func (d *noStatsDevice) LastHandshakeTime() time.Time { return time.Time{} }
func (d *noStatsDevice) CreatedAt() time.Time         { return time.Time{} }
func (d *noStatsDevice) DroppedPackets() uint64       { return d.dropped.Load() }
func (d *noStatsDevice) IsClosed() bool               { return false }

// compile-time guard: the production device DOES report the axes, so the
// fallback path is reachable only for devices that genuinely cannot.
var _ backendDeviceStatsProvider = (*realVtunBackendDevice)(nil)
