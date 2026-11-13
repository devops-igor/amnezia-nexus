package tunnel

// The attachment-failure preservation verdict must be bound to the device
// attached at COMMIT time, not the one that answered the canary. A device
// replaced during the canary exchange must not lend its verdict to its
// replacement (issue #794 group A).

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// swapDuringProbeDevice replaces the prober's device from inside its own canary
// call, modelling a re-attach that lands between the probe and the verdict.
type swapDuringProbeDevice struct {
	prober  *HealthProber
	tunnelO int64
	stamp   time.Time
	swapTo  *admissionEvidenceDevice
	done    bool
}

func (d *swapDuringProbeDevice) Read([]byte) (int, error)    { return 0, nil }
func (d *swapDuringProbeDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *swapDuringProbeDevice) Close() error                { return nil }
func (d *swapDuringProbeDevice) CreatedAt() time.Time        { return d.stamp }

func (d *swapDuringProbeDevice) ProbeCanary(_ context.Context, _ time.Duration) error {
	if !d.done {
		// A different device is attached while this one is answering.
		d.prober.RegisterDevice(d.tunnelO, d.swapTo)
		d.done = true
	}
	return nil
}

// TestHookPreservationRejectsDeviceReplacedDuringProbe pins the identity guard:
// the canary succeeded, but on a device that is no longer the attached one, so
// the verdict must not authorize preservation.
func TestHookPreservationRejectsDeviceReplacedDuringProbe(t *testing.T) {
	old := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	newer := old.Add(time.Hour)

	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)
	sid, err := db.CreateServer(ctx, &models.Server{Name: "swap-during-probe", Host: "192.0.2.211"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, sid, "192.0.2.211:51820", "swap-pubkey")
	if err != nil {
		t.Fatal(err)
	}
	hp := NewHealthProber(pool, db, DefaultHealthConfig())
	hp.SetNowFuncForTest(func() time.Time { return old })
	hp.SetCanaryProbeFunc(nil)

	// The replacement device has a different identity stamp.
	replacement := &admissionEvidenceDevice{created: newer}
	answering := &swapDuringProbeDevice{prober: hp, tunnelO: tun.ID, stamp: old, swapTo: replacement}
	hp.RegisterDevice(tun.ID, answering)

	cur, err := pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	if hp.hookFailurePreservedByInnerEvidence(ctx, cur) {
		t.Fatal("a verdict produced by a device that was replaced during the probe authorised preservation")
	}

	// Control: with the SAME device answering and still attached, the same
	// evidence does authorise preservation, so the assertion above is not vacuous.
	stable := &stableCanaryDevice{stamp: old}
	hp.RegisterDevice(tun.ID, stable)
	if !hp.hookFailurePreservedByInnerEvidence(ctx, cur) {
		t.Fatal("stable same-device canary success did not authorise preservation")
	}
}

// stableCanaryDevice answers the packet canary synchronously and reports a fixed
// identity stamp, so the evidence it records is admissible for itself.
type stableCanaryDevice struct {
	stamp time.Time
}

func (d *stableCanaryDevice) Read([]byte) (int, error)    { return 0, nil }
func (d *stableCanaryDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *stableCanaryDevice) Close() error                { return nil }
func (d *stableCanaryDevice) CreatedAt() time.Time        { return d.stamp }

func (d *stableCanaryDevice) RegisterCanaryResponseHook(hook CanaryResponseHook) func() {
	// Answer any ICMP echo request immediately with a matched reply.
	return func() {}
}

func (d *stableCanaryDevice) ProbeCanary(context.Context, time.Duration) error { return nil }
