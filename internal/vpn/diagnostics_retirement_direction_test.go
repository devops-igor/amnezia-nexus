package vpn

import (
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// The regressions in this file cover round-5 finding 1: backend retirement must
// not reclassify loss.
//
// The defect they pin is a direction INVERSION, not a labelling nicety. Before
// the fix each retirement site folded the device's whole aggregate into one
// scalar that the breakdown published on the CLIENT side. Five outbound
// (backend->client, i.e. RETURN) queue-full losses therefore reported as
// client_total_drops=0 / return_total_drops=5 while the device was live, and as
// client_total_drops=5 / return_total_drops=0 after the backend was disabled.
// Worse, the rate trackers compute client and return deltas INDEPENDENTLY, so
// the same five historical drops were published as five NEW active drops at the
// instant of retirement while TotalDrops never moved at all.
//
// The scenario below is the reviewer's, exactly: create RETURN-direction drops
// on a live device, prime diagnostics, retire the backend through the real
// production path (DisableBackend), sample again.

// retireDirectionFixture builds a service whose single backend device is a REAL
// VirtualTUN (so its direction x reason axes exist) with both queues drained,
// so retirement itself introduces no NEW shutdown loss and every delta observed
// across the retirement is attributable to reclassification alone.
func retireDirectionFixture(t *testing.T) (*Service, int64, *realVtunBackendDevice) {
	t.Helper()
	svc, serverA, _, _, _ := setupTestVPNService(t, setupTestDB(t))
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatalf("pool sync failed: %v", err)
	}
	tun, err := svc.pool.GetTunnel(serverA)
	if err != nil {
		t.Fatalf("backend tunnel lookup failed: %v", err)
	}
	dev := newRealVtunBackendDevice(t, "retire-direction")
	svc.SetBackendDeviceForTest(tun.ID, dev)
	return svc, serverA, dev
}

// produceReturnQueueFullDrops creates n OUTBOUND (backend -> client) queue-full
// losses on dev and leaves both queues empty, so the device's totals are exactly
// the n return-direction losses the assertions below are about.
//
// The outbound queue is one packet deep, so writes 2..n+1 are refused. The first
// packet is then drained by hand: leaving it queued would make the retirement's
// Close() account it as a SHUTDOWN drop, which is a genuinely new loss event and
// would mask the reclassification this test is about.
func produceReturnQueueFullDrops(t *testing.T, dev *realVtunBackendDevice, n int) {
	t.Helper()
	if n < 1 {
		t.Fatalf("the scenario needs at least one return drop, got %d", n)
	}
	for i := range n + 1 {
		if _, err := dev.vtun.Write([][]byte{[]byte("out")}, 0); err != nil {
			t.Fatalf("outbound write %d errored: %v", i, err)
		}
	}
	// Exactly n refused writes, and the one admitted packet is still queued.
	if got := dev.vtun.Stats().OutboundQueueFullDrops; got != uint64(n) {
		t.Fatalf("fixture produced %d outbound queue-full drops, want %d", got, n)
	}
	if _, err := dev.vtun.ReceiveOutbound(); err != nil {
		t.Fatalf("draining the admitted outbound packet failed: %v", err)
	}
	if s := dev.vtun.Stats(); s.InboundDepth != 0 || s.OutboundDepth != 0 {
		t.Fatalf("fixture left packets queued (in=%d out=%d): retirement would book a shutdown drop",
			s.InboundDepth, s.OutboundDepth)
	}
}

// assertNoRetirementRateSpike is the machine-checked form of "retirement must
// not look like fresh loss": every published rate, aggregate and per-reason,
// must be zero after retirement.
func assertNoRetirementRateSpike(t *testing.T, label string, d DropCategoryBreakdown) {
	t.Helper()
	if d.ClientDropRatePps != 0 || d.ReturnDropRatePps != 0 || d.TotalDropRatePps != 0 {
		t.Errorf("%s: retirement published a non-zero aggregate drop rate (client=%v return=%v total=%v); "+
			"the loss is historical, so every rate must stay 0",
			label, d.ClientDropRatePps, d.ReturnDropRatePps, d.TotalDropRatePps)
	}
	for key, rate := range d.ReasonRates {
		if rate != 0 {
			t.Errorf("%s: retirement published reason %s at rate %v; the loss is historical, so every rate must stay 0",
				label, key, rate)
		}
	}
	if !d.RatesAvailable {
		t.Errorf("%s: rates unavailable: the retirement sample was throttled, so the zero-rate assertion is vacuous", label)
	}
}

// TestRetirementPreservesReturnDirectionAndRate is the round-5 finding-1
// regression, in the reviewer's exact scenario.
func TestRetirementPreservesReturnDirectionAndRate(t *testing.T) {
	const drops = 5
	svc, serverA, dev := retireDirectionFixture(t)
	produceReturnQueueFullDrops(t, dev, drops)

	// Step 2: sample and prime while the backend is still live.
	before, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatalf("pre-retirement status failed: %v", err)
	}
	beforeDrops := before.DropCategories
	if beforeDrops.ReturnBackendDeviceQueueFull != drops {
		t.Fatalf("live return_backend_device_queue_full=%d, want %d: the fixture did not produce return-direction loss",
			beforeDrops.ReturnBackendDeviceQueueFull, drops)
	}
	if beforeDrops.ClientBackendDeviceQueueFull != 0 {
		t.Fatalf("live client_backend_device_queue_full=%d, want 0: return loss must not sit in the client population",
			beforeDrops.ClientBackendDeviceQueueFull)
	}
	if beforeDrops.ClientTotalDrops != 0 || beforeDrops.ReturnTotalDrops != drops || beforeDrops.TotalDrops != drops {
		t.Fatalf("live client/return/total = %d/%d/%d, want 0/%d/%d",
			beforeDrops.ClientTotalDrops, beforeDrops.ReturnTotalDrops, beforeDrops.TotalDrops, drops, drops)
	}

	// Step 3: retire through the real production path.
	time.Sleep(250 * time.Millisecond) // clear the 200ms rate-tracker's throttle
	if err := svc.DisableBackend(t.Context(), serverA); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	// Step 4: sample again, after the rate trackers have recomputed.
	time.Sleep(250 * time.Millisecond)
	after, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatalf("post-retirement status failed: %v", err)
	}
	afterDrops := after.DropCategories

	// The reason is STILL the return reason. Before the fix this key was zero
	// after retirement and the same five losses appeared on the client side.
	if afterDrops.ReturnBackendDeviceQueueFull != drops {
		t.Errorf("return_backend_device_queue_full=%d after retirement, want %d: retirement reclassified return loss",
			afterDrops.ReturnBackendDeviceQueueFull, drops)
	}
	if afterDrops.ClientBackendDeviceQueueFull != 0 || afterDrops.ClientBackendDeviceOversized != 0 ||
		afterDrops.ClientBackendDeviceShutdown != 0 {
		t.Errorf("return loss moved into a client-direction key after retirement: %+v", afterDrops)
	}

	// Direction totals and the lifetime total are each unchanged by retirement
	// alone: no packets were lost, they were only re-bucketed.
	if afterDrops.ClientTotalDrops != beforeDrops.ClientTotalDrops {
		t.Errorf("client_total_drops %d -> %d across retirement; retirement must not change it",
			beforeDrops.ClientTotalDrops, afterDrops.ClientTotalDrops)
	}
	if afterDrops.ReturnTotalDrops != beforeDrops.ReturnTotalDrops {
		t.Errorf("return_total_drops %d -> %d across retirement; retirement must not change it",
			beforeDrops.ReturnTotalDrops, afterDrops.ReturnTotalDrops)
	}
	if afterDrops.TotalDrops != beforeDrops.TotalDrops {
		t.Errorf("total_drops %d -> %d across retirement; the lifetime total must be preserved exactly",
			beforeDrops.TotalDrops, afterDrops.TotalDrops)
	}

	// The heart of the blocker: no fresh-looking drop may appear.
	assertNoRetirementRateSpike(t, "after retirement", afterDrops)

	// The fleet summary keeps the lifetime total (the original purpose of the
	// accumulator must not regress).
	if after.Backends.TotalDrops != before.Backends.TotalDrops {
		t.Errorf("fleet total_drops %d -> %d across retirement; retirement must preserve lifetime loss",
			before.Backends.TotalDrops, after.Backends.TotalDrops)
	}
	assertDisjointDropReasons(t, afterDrops)
}

// TestRetirementNeverInventsClientLoss pins the general form of the invariant:
// whatever a retiring device lost, the client population after retirement is
// the client population before it. Retirement is a transfer between two views of
// the SAME loss, so a client-direction figure can never grow across it.
func TestRetirementNeverInventsClientLoss(t *testing.T) {
	svc, serverA, dev := retireDirectionFixture(t)
	produceReturnQueueFullDrops(t, dev, 3)

	// Add client-direction loss too, so the fixture covers both populations.
	if err := dev.vtun.InjectInbound([]byte("in")); err != nil {
		t.Fatalf("inbound enqueue failed: %v", err)
	}
	for range 2 {
		if err := dev.vtun.InjectInbound([]byte("in")); err == nil {
			t.Fatal("saturated inbound queue must refuse the packet")
		}
	}
	// Drain so Close() at retirement books no shutdown loss.
	if _, err := dev.vtun.Read([][]byte{make([]byte, 8)}, []int{8}, 0); err != nil {
		t.Fatalf("draining the admitted inbound packet failed: %v", err)
	}

	before, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatalf("pre-retirement status failed: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if err := svc.DisableBackend(t.Context(), serverA); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	after, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatalf("post-retirement status failed: %v", err)
	}

	b, a := before.DropCategories, after.DropCategories
	if a.ClientBackendDeviceQueueFull != 2 || a.ReturnBackendDeviceQueueFull != 3 {
		t.Errorf("per-direction per-reason keys changed across retirement: client_qf=%d return_qf=%d, want 2/3",
			a.ClientBackendDeviceQueueFull, a.ReturnBackendDeviceQueueFull)
	}
	if a.ClientTotalDrops != b.ClientTotalDrops || a.ReturnTotalDrops != b.ReturnTotalDrops || a.TotalDrops != b.TotalDrops {
		t.Errorf("totals changed across retirement: client %d->%d return %d->%d total %d->%d",
			b.ClientTotalDrops, a.ClientTotalDrops, b.ReturnTotalDrops, a.ReturnTotalDrops, b.TotalDrops, a.TotalDrops)
	}
	assertNoRetirementRateSpike(t, "both directions", a)
	assertDisjointDropReasons(t, a)
}

// TestRetiredDeviceTotalIsSumOfDirections pins the accumulator's own contract:
// the retired lifetime population must equal the sum of the device's real
// direction x reason fields, with nothing invented and nothing lost. Before the
// fix this was a single scalar with no directions to check.
func TestRetiredDeviceTotalIsSumOfDirections(t *testing.T) {
	svc, _, _, _, _ := setupTestVPNService(t, setupTestDB(t))
	dev := newRealVtunBackendDevice(t, "retired-total")
	produceReturnQueueFullDrops(t, dev, 4)

	snap := dev.DeviceStats()
	if snap.Sum()+snap.ExternalDrops() != snap.DropsTotal {
		t.Fatalf("fixture snapshot is not self-consistent: sum=%d external=%d total=%d",
			snap.Sum(), snap.ExternalDrops(), snap.DropsTotal)
	}

	stats := snapshotBackendDeviceDrops(dev)
	if stats.ReturnQueueFull != 4 {
		t.Errorf("snapshotBackendDeviceDrops ReturnQueueFull=%d, want 4", stats.ReturnQueueFull)
	}
	if stats.Total() != dev.DroppedPackets() {
		t.Errorf("structured snapshot total=%d but DroppedPackets()=%d: the retired accumulator would not preserve lifetime loss",
			stats.Total(), dev.DroppedPackets())
	}
	_ = svc
}

// compile-time guard: the device used by every test in this file reports the
// axes the retirement snapshot reads.
var _ backendDeviceStatsProvider = (*realVtunBackendDevice)(nil)

// compile-time guard: the snapshot this file asserts on really does expose the
// external counter the finding-2 rework introduces.
var _ = func() bool {
	var s virtualtun.StatsSnapshot
	return s.ExternalDrops() == 0
}()
