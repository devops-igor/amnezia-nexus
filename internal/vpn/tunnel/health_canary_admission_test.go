package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// admissionEvidenceDevice is a canary-capable device that also reports a device
// generation, which is what binds canary evidence to one physical backend
// device. created is settable so a fixture can model a re-attach on the same
// tunnel ID.
type admissionEvidenceDevice struct {
	created time.Time
	closed  bool
}

var (
	_ DeviceGeneration      = (*admissionEvidenceDevice)(nil)
	_ CanaryResponseDemuxer = (*admissionEvidenceDevice)(nil)
)

func (d *admissionEvidenceDevice) Read([]byte) (int, error) { return 0, errors.New("not implemented") }
func (d *admissionEvidenceDevice) Write(p []byte) (int, error) {
	return len(p), nil
}
func (d *admissionEvidenceDevice) Close() error         { d.closed = true; return nil }
func (d *admissionEvidenceDevice) CreatedAt() time.Time { return d.created }
func (d *admissionEvidenceDevice) RegisterCanaryResponseHook(CanaryResponseHook) func() {
	return func() {}
}

// admissionEvidenceFixture builds a pool + prober + one enabled handshake_blocked
// tunnel with a device attached, plus a clock the fixture controls.
func admissionEvidenceFixture(t *testing.T) (*HealthProber, *Pool, *models.BackendTunnel, *admissionEvidenceDevice, *time.Time) {
	t.Helper()
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)
	sid, err := db.CreateServer(ctx, &models.Server{Name: "evidence", Host: "192.0.2.41"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, sid, "192.0.2.41:51820", "evidence-public-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatus(ctx, sid, models.TunnelStatusHandshakeBlocked, 12); err != nil {
		t.Fatal(err)
	}
	dev := &admissionEvidenceDevice{created: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
	hp := NewHealthProber(pool, db, DefaultHealthConfig())
	hp.RegisterDevice(tun.ID, dev)

	clock := dev.created
	hp.SetNowFuncForTest(func() time.Time { return clock })
	return hp, pool, tun, dev, &clock
}

// probeEvidence runs one real canary observation and returns its error.
func probeEvidence(hp *HealthProber, tun *models.BackendTunnel, success bool) error {
	hp.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		if success {
			return nil
		}
		return errors.New("inner path lost")
	})
	return hp.ProbeCanary(context.Background(), tun)
}

func currentEvidenceTunnel(t *testing.T, pool *Pool, serverID int64) *models.BackendTunnel {
	t.Helper()
	cur, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	return cur
}

// TestCanaryAdmissibleRequiresRecordedSuccess pins the whole admission oracle:
// only fresh evidence from THIS tunnel generation and THIS device authorises a
// new admission, and no failure may have happened since.
func TestCanaryAdmissibleRequiresRecordedSuccess(t *testing.T) {
	t.Run("fresh success admits", func(t *testing.T) {
		hp, pool, tun, dev, _ := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		if !hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("fresh same-device success did not authorise admission")
		}
	})

	t.Run("never probed refuses", func(t *testing.T) {
		hp, pool, tun, dev, _ := admissionEvidenceFixture(t)
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		if hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("an unprobed backend was admitted on absent evidence")
		}
	})

	t.Run("failure since success refuses", func(t *testing.T) {
		hp, pool, tun, dev, _ := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		// One transient inner failure: below the confirmation threshold, so the
		// status label stays handshake_blocked — the case a badge-based
		// admission would get wrong.
		if err := probeEvidence(hp, tun, false); err == nil {
			t.Fatal("fixture: canary failure reported success")
		}
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		if cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: label changed to %q, want handshake_blocked for the transient case", cur.Status)
		}
		if hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("a backend whose inner canary just failed was admitted")
		}
	})

	t.Run("stale evidence refuses", func(t *testing.T) {
		hp, pool, tun, dev, clock := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		hp.mu.RLock()
		bound := hp.maxCanaryEvidenceAgeLocked()
		hp.mu.RUnlock()
		// One nanosecond past the derived bound is stale; just inside is fresh.
		*clock = dev.created.Add(bound)
		if !hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("evidence exactly at the derived bound was refused")
		}
		*clock = dev.created.Add(bound + time.Nanosecond)
		if hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("evidence past the derived freshness bound was admitted")
		}
	})

	t.Run("clock going backwards refuses", func(t *testing.T) {
		hp, pool, tun, dev, clock := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		*clock = dev.created.Add(-time.Hour)
		if hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("evidence with a negative age was treated as fresh")
		}
	})

	t.Run("replaced device refuses", func(t *testing.T) {
		hp, pool, tun, _, _ := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		// Same tunnel ID, same server: only the device object is new (a
		// credential replacement or a detach/re-attach).
		reattached := &admissionEvidenceDevice{created: time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC)}
		if hp.CanaryAdmissible(cur, reattached.CreatedAt()) {
			t.Fatal("evidence produced by a replaced device authorised the new device")
		}
	})

	t.Run("replaced tunnel generation refuses", func(t *testing.T) {
		hp, pool, tun, dev, _ := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		ctx := context.Background()
		if err := pool.RemoveTunnel(ctx, tun.ServerID); err != nil {
			t.Fatalf("remove tunnel: %v", err)
		}
		replacement, err := pool.AddTunnel(ctx, tun.ServerID, "192.0.2.41:51820", "replacement-key")
		if err != nil {
			t.Fatalf("re-add tunnel: %v", err)
		}
		if replacement.ID == tun.ID {
			t.Fatalf("fixture: replacement reused tunnel id %d", tun.ID)
		}
		if hp.CanaryAdmissible(replacement, dev.CreatedAt()) {
			t.Fatal("evidence from a retired tunnel generation authorised its replacement")
		}
	})

	t.Run("disabled tunnel refuses", func(t *testing.T) {
		hp, pool, tun, dev, _ := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		if err := pool.SetTunnelEnabled(context.Background(), tun.ServerID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("disable: %v", err)
		}
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		if hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("an administratively disabled backend was admitted")
		}
	})

	t.Run("device without a generation refuses", func(t *testing.T) {
		hp, pool, tun, _, _ := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		if hp.CanaryAdmissible(cur, time.Time{}) {
			t.Fatal("unverifiable evidence (no device generation) was accepted")
		}
	})
}

// TestCanaryAdmissibleClearedByResetAndDisable pins every writer that must
// withdraw admission authority, so a reset or an administrative disable cannot
// leave earlier evidence standing.
func TestCanaryAdmissibleClearedByResetAndDisable(t *testing.T) {
	ctx := context.Background()

	t.Run("ResetFailCount clears", func(t *testing.T) {
		hp, pool, tun, dev, _ := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		hp.ResetFailCount(tun.ServerID)
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		if hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("ResetFailCount left earlier evidence standing")
		}
	})

	t.Run("MarkAdminDisabled clears", func(t *testing.T) {
		hp, pool, tun, dev, _ := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		hp.MarkAdminDisabled(tun.ServerID)
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		if hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("MarkAdminDisabled left earlier evidence standing")
		}
	})

	t.Run("re-enable requires fresh evidence", func(t *testing.T) {
		hp, pool, tun, dev, _ := admissionEvidenceFixture(t)
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary: %v", err)
		}
		if err := pool.SetTunnelEnabled(ctx, tun.ServerID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("disable: %v", err)
		}
		hp.MarkAdminDisabled(tun.ServerID)
		if err := pool.SetTunnelEnabled(ctx, tun.ServerID, true, models.DisableReasonNone); err != nil {
			t.Fatalf("re-enable: %v", err)
		}
		cur := currentEvidenceTunnel(t, pool, tun.ServerID)
		if hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("a re-enabled backend inherited pre-disable evidence")
		}
		if err := probeEvidence(hp, tun, true); err != nil {
			t.Fatalf("canary after re-enable: %v", err)
		}
		cur = currentEvidenceTunnel(t, pool, tun.ServerID)
		if !hp.CanaryAdmissible(cur, dev.CreatedAt()) {
			t.Fatal("fresh evidence after re-enable did not restore admission authority")
		}
	})
}

// TestCanaryEvidenceBoundDerivesFromConfiguredCadence proves the freshness bound
// is derived from the existing probe configuration rather than being an
// independent product timer: changing Interval/Timeout moves it, and an
// unconfigured prober falls back to the documented defaults.
func TestCanaryEvidenceBoundDerivesFromConfiguredCadence(t *testing.T) {
	cases := []struct {
		name string
		cfg  HealthConfig
		want time.Duration
	}{
		{"defaults", DefaultHealthConfig(), 15 * time.Second},
		{"short cadence", HealthConfig{Interval: 2 * time.Second, Timeout: 500 * time.Millisecond}, 2900 * time.Millisecond},
		{"unset falls back", HealthConfig{}, 15 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hp := NewHealthProber(nil, nil, tc.cfg)
			hp.mu.RLock()
			got := hp.maxCanaryEvidenceAgeLocked()
			hp.mu.RUnlock()
			if got != tc.want {
				t.Fatalf("evidence bound = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCanarySuccessIgnoredForStaleObservation proves the new record obeys the
// same generation fencing as the failure history: a superseded observation must
// never create admission authority.
func TestCanarySuccessIgnoredForStaleObservation(t *testing.T) {
	hp, pool, tun, dev, _ := admissionEvidenceFixture(t)
	// A newer observation is accepted while an older one is still in flight.
	if err := probeEvidence(hp, tun, false); err == nil {
		t.Fatal("fixture: expected the first canary to fail")
	}
	staleSequence := uint64(1)
	cur := currentEvidenceTunnel(t, pool, tun.ServerID)
	if err := hp.acceptCanaryObservation(cur, staleSequence, true, dev.CreatedAt()); !errors.Is(err, ErrStaleStateVersion) {
		t.Fatalf("stale observation accepted: %v", err)
	}
	if hp.CanaryAdmissible(cur, dev.CreatedAt()) {
		t.Fatal("a superseded canary success created admission authority")
	}
}
