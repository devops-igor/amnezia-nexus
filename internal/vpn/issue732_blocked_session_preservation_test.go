package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// issue732SweepObservation is the real backend/session/route state read back
// after one scheduled orchestrator health sweep.
type issue732SweepObservation struct {
	sourceID        int64
	targetID        int64
	sourceStatus    string
	sessionTunnelID int64 // in-memory SessionManager assignment
	dbSessionTunnel int64 // durable row assignment
	routeOnSource   bool  // live forwarder route
	routeOnTarget   bool
	sourceConns     int
	targetConns     int
	canaryCalls     int
}

// issue732CanaryDevice is the injected inner data-plane verdict for one backend.
type issue732CanaryDevice struct {
	fail        bool
	canaryCalls int
}

func (d *issue732CanaryDevice) Read([]byte) (int, error)     { return 0, nil }
func (d *issue732CanaryDevice) Write(p []byte) (int, error)  { return len(p), nil }
func (d *issue732CanaryDevice) Close() error                 { return nil }
func (d *issue732CanaryDevice) IsClosed() bool               { return false }
func (d *issue732CanaryDevice) CreatedAt() time.Time         { return time.Now() }
func (d *issue732CanaryDevice) LastHandshakeTime() time.Time { return time.Now() }
func (d *issue732CanaryDevice) DroppedPackets() uint64       { return 0 }

func (d *issue732CanaryDevice) ProbeCanary(context.Context, time.Duration) error {
	d.canaryCalls++
	if d.fail {
		return errors.New("simulated inner data-plane loss")
	}
	return nil
}

// issue732ObsoleteCanaryDevice answers with evidence that belongs to a
// superseded tunnel generation: the probe ran, but its verdict is not usable
// evidence about the current backend either way.
type issue732ObsoleteCanaryDevice struct {
	canaryCalls int
}

func (d *issue732ObsoleteCanaryDevice) Read([]byte) (int, error)     { return 0, nil }
func (d *issue732ObsoleteCanaryDevice) Write(p []byte) (int, error)  { return len(p), nil }
func (d *issue732ObsoleteCanaryDevice) Close() error                 { return nil }
func (d *issue732ObsoleteCanaryDevice) IsClosed() bool               { return false }
func (d *issue732ObsoleteCanaryDevice) CreatedAt() time.Time         { return time.Now() }
func (d *issue732ObsoleteCanaryDevice) LastHandshakeTime() time.Time { return time.Now() }
func (d *issue732ObsoleteCanaryDevice) DroppedPackets() uint64       { return 0 }

func (d *issue732ObsoleteCanaryDevice) ProbeCanary(context.Context, time.Duration) error {
	d.canaryCalls++
	return tunnel.ErrStaleStateVersion
}

// issue732InnerProbe is the injectable inner verdict for a fixture.
type issue732InnerProbe interface {
	BackendDevice
	issue732CanaryCounter
}

type issue732CanaryCounter interface {
	probeCalls() int
}

// issue732SweepFixture pins everything except the two real inputs under test:
// the outer probe RTT and the inner data-plane verdict. Backend classification,
// status CAS, session migration, forwarder route movement and connection
// counters all run through production code.
type issue732SweepFixture struct {
	svc       *Service
	orch      *orchestrator.Orchestrator
	source    *models.BackendTunnel
	target    *models.BackendTunnel
	peer      ingressTestPeer
	sess      *models.VPNSession
	inner     issue732InnerProbe
	innerBase *issue732CanaryDevice
}

const issue732PinnedThresholdMS = 500

// newIssue732SweepFixture seeds one handshake_blocked (or active) source
// backend that carries an established, admitted session plus a live forwarder
// route, a healthy same-protocol sibling, a pinned persisted health threshold
// and a real orchestrator wired to the real VPN service.
func newIssue732SweepFixture(t *testing.T, startStatus string, outerRTT time.Duration, inner issue732InnerProbe, base *issue732CanaryDevice) *issue732SweepFixture {
	t.Helper()
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sid, other, _, _ := setupTestVPNService(t, db)
	svc.SetCanaryProbeFunc(nil)

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("sync pool from db: %v", err)
	}
	if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusDisabled, 0); err != nil {
		t.Fatalf("disable sibling backend: %v", err)
	}
	source, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatalf("read source tunnel: %v", err)
	}
	target, err := svc.pool.GetTunnel(other)
	if err != nil {
		t.Fatalf("read target tunnel: %v", err)
	}

	svc.SetBackendDeviceForTest(source.ID, inner)
	svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})

	peer := seedIngressPeer(t, db, "issue732", "issue732-peer", "10.100.3.132")
	sess, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("create ingress session: %v", err)
	}
	if sess.BackendTunnelID != source.ID {
		t.Fatalf("precondition: session admitted on backend %d, want source %d", sess.BackendTunnelID, source.ID)
	}
	if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusActive, 0); err != nil {
		t.Fatalf("activate target backend: %v", err)
	}
	if startStatus != models.TunnelStatusActive {
		if err := svc.pool.SetTunnelStatus(ctx, sid, startStatus, 0); err != nil {
			t.Fatalf("set source status %s: %v", startStatus, err)
		}
	}
	if !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatal("precondition: live forwarder route must start on the source backend")
	}
	pre, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatalf("re-read source tunnel: %v", err)
	}
	if pre.Status != startStatus {
		t.Fatalf("precondition: source status %q, want %q", pre.Status, startStatus)
	}
	if pre.ActiveConnections <= 0 {
		t.Fatalf("precondition: source must carry the established session (active_connections=%d)", pre.ActiveConnections)
	}

	// The orchestrator reads HealthThresholdMS from the persisted VPN config, not
	// from the Service config, so pin it and read it back. Without the pin a
	// slower sample can sit under an inherited 2000ms default and the test would
	// be vacuously green.
	cfgDB, err := db.GetVPNConfig(ctx)
	if err != nil || cfgDB == nil {
		t.Fatalf("read vpn config: %v", err)
	}
	cfgDB.HealthThresholdMS = issue732PinnedThresholdMS
	if err := db.SaveVPNConfig(ctx, cfgDB); err != nil {
		t.Fatalf("persist vpn config: %v", err)
	}
	pinned, err := db.GetVPNConfig(ctx)
	if err != nil || pinned == nil {
		t.Fatalf("re-read vpn config: %v", err)
	}
	if pinned.HealthThresholdMS != issue732PinnedThresholdMS {
		t.Fatalf("threshold pin failed: persisted %d, want %d", pinned.HealthThresholdMS, issue732PinnedThresholdMS)
	}

	orch := orchestrator.New(db, nil, orchestrator.WithProbeFunc(
		func(_ context.Context, endpoint, _, _, _, _ string, _, _ any, _, _ int, _ time.Duration) (time.Duration, error) {
			if endpoint == source.Endpoint {
				return outerRTT, nil
			}
			return 20 * time.Millisecond, nil
		}))
	orch.SetTunnelStatusUpdater(svc)
	orch.SetSessionMigrator(svc)

	return &issue732SweepFixture{
		svc:       svc,
		orch:      orch,
		source:    source,
		target:    target,
		peer:      peer,
		sess:      sess,
		inner:     inner,
		innerBase: base,
	}
}

// slowFixture builds the reproduced shape: a successful outer probe above the
// pinned latency threshold.
func slowFixture(t *testing.T, startStatus string, base *issue732CanaryDevice) *issue732SweepFixture {
	t.Helper()
	return newIssue732SweepFixture(t, startStatus, time.Duration(issue732PinnedThresholdMS+400)*time.Millisecond, base, base)
}

// fastFixture builds the below-threshold control shape.
func fastFixture(t *testing.T, startStatus string, base *issue732CanaryDevice) *issue732SweepFixture {
	t.Helper()
	return newIssue732SweepFixture(t, startStatus, 20*time.Millisecond, base, base)
}

func (d *issue732CanaryDevice) probeCalls() int         { return d.canaryCalls }
func (d *issue732ObsoleteCanaryDevice) probeCalls() int { return d.canaryCalls }

// sweep runs ONE real orchestrator health sweep and reads back the durable and
// live state that a session interruption would show.
func (f *issue732SweepFixture) sweep(t *testing.T) issue732SweepObservation {
	t.Helper()
	ctx := t.Context()

	if err := f.orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("health sweep: %v", err)
	}

	post, err := f.svc.pool.GetTunnel(f.source.ServerID)
	if err != nil {
		t.Fatalf("read source tunnel after sweep: %v", err)
	}
	postTarget, err := f.svc.pool.GetTunnel(f.target.ServerID)
	if err != nil {
		t.Fatalf("read target tunnel after sweep: %v", err)
	}
	memSess, ok := f.svc.sessionMgr.GetSessionSnapshotByID(f.sess.ID)
	if !ok {
		t.Fatal("session vanished from the in-memory session manager")
	}
	dbSess, err := f.svc.db.GetVPNSessionByID(ctx, f.sess.ID)
	if err != nil || dbSess == nil {
		t.Fatalf("read durable session: %v", err)
	}

	obs := issue732SweepObservation{
		sourceID:        f.source.ID,
		targetID:        f.target.ID,
		sourceStatus:    post.Status,
		sessionTunnelID: memSess.BackendTunnelID,
		dbSessionTunnel: dbSess.BackendTunnelID,
		routeOnSource:   f.svc.forwarder.HasSessionRoute(f.peer.peerKey, f.sess.ID, f.peer.connID, f.peer.ip.String(), f.source.ID),
		routeOnTarget:   f.svc.forwarder.HasSessionRoute(f.peer.peerKey, f.sess.ID, f.peer.connID, f.peer.ip.String(), f.target.ID),
		sourceConns:     post.ActiveConnections,
		targetConns:     postTarget.ActiveConnections,
		canaryCalls:     f.inner.probeCalls(),
	}
	t.Logf("sweep source=%d target=%d => %+v", f.source.ID, f.target.ID, obs)
	return obs
}

// assertIssue732SessionPreservedOnSource is the preservation invariant: the
// in-memory and durable session assignment, the live forwarder route and the
// connection counters all stay on the source backend.
func assertIssue732SessionPreservedOnSource(t *testing.T, o issue732SweepObservation) {
	t.Helper()
	if o.routeOnTarget || !o.routeOnSource {
		t.Errorf("live forwarder route moved off the source backend: onSource=%t onTarget=%t", o.routeOnSource, o.routeOnTarget)
	}
	if o.sessionTunnelID != o.sourceID || o.dbSessionTunnel != o.sourceID {
		t.Errorf("session migrated off source backend %d: in-memory=%d durable=%d", o.sourceID, o.sessionTunnelID, o.dbSessionTunnel)
	}
	if o.sourceConns <= 0 || o.targetConns != 0 {
		t.Errorf("connection counters not preserved on source: source=%d target=%d", o.sourceConns, o.targetConns)
	}
}

// The reproduced defect: a handshake_blocked backend with an established
// session, a WORKING inner path, and one slow SUCCESSFUL outer probe above the
// latency threshold. Outer latency alone must not move the session.
func TestIssue732_BlockedBackend_SlowOuterSuccess_WorkingInner_PreservesSession(t *testing.T) {
	f := slowFixture(t, models.TunnelStatusHandshakeBlocked, &issue732CanaryDevice{})

	o := f.sweep(t)
	if o.sourceStatus != models.TunnelStatusHandshakeBlocked {
		t.Errorf("expected the blocked backend to stay handshake_blocked, got %q", o.sourceStatus)
	}
	if o.canaryCalls == 0 {
		t.Error("expected the inner canary to be consulted before any status change")
	}
	assertIssue732SessionPreservedOnSource(t, o)
}

// Repeated sweeps: the preservation must not depend on one lucky sample.
func TestIssue732_BlockedBackend_RepeatedSlowOuterSuccess_PreservesSession(t *testing.T) {
	f := slowFixture(t, models.TunnelStatusHandshakeBlocked, &issue732CanaryDevice{})

	for i := 0; i < 3; i++ {
		o := f.sweep(t)
		if o.sourceStatus != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("sweep %d: expected handshake_blocked, got %q", i+1, o.sourceStatus)
		}
		assertIssue732SessionPreservedOnSource(t, o)
	}
}

// Negative control (sustained inner failure): the same slow outer success with a
// genuinely dead inner path still reaches degraded at the failure threshold and
// migrates, so the repair cannot silently disable the existing policy.
func TestIssue732_BlockedBackend_SlowOuterSuccess_SustainedInnerFailure_Migrates(t *testing.T) {
	dev := &issue732CanaryDevice{fail: true}
	f := slowFixture(t, models.TunnelStatusHandshakeBlocked, dev)

	threshold := f.orch.ProbeFailureThreshold()
	if threshold < 1 {
		t.Fatalf("unexpected probe failure threshold %d", threshold)
	}

	var last issue732SweepObservation
	for i := 0; i < threshold; i++ {
		last = f.sweep(t)
		if i < threshold-1 && last.sourceStatus != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("sweep %d of %d: inner failure below threshold must keep handshake_blocked, got %q",
				i+1, threshold, last.sourceStatus)
		}
	}
	if last.sourceStatus != models.TunnelStatusDegraded {
		t.Fatalf("expected degraded after %d sustained inner failures, got %q", threshold, last.sourceStatus)
	}
	if last.sessionTunnelID != last.targetID || last.dbSessionTunnel != last.targetID {
		t.Errorf("expected the session to migrate to target %d: in-memory=%d durable=%d",
			last.targetID, last.sessionTunnelID, last.dbSessionTunnel)
	}
}

// Negative control (stale/obsolete inner evidence): an inner verdict belonging
// to a superseded generation is not evidence of inner loss, so it must not be
// used to justify a migration.
func TestIssue732_BlockedBackend_SlowOuterSuccess_ObsoleteInnerEvidence_NoMigration(t *testing.T) {
	dev := &issue732ObsoleteCanaryDevice{}
	f := newIssue732SweepFixture(t, models.TunnelStatusHandshakeBlocked,
		time.Duration(issue732PinnedThresholdMS+400)*time.Millisecond, dev, nil)

	o := f.sweep(t)
	if o.canaryCalls == 0 {
		t.Error("expected the inner canary to be consulted")
	}
	if o.sourceStatus != models.TunnelStatusHandshakeBlocked {
		t.Errorf("expected handshake_blocked after obsolete inner evidence, got %q", o.sourceStatus)
	}
	assertIssue732SessionPreservedOnSource(t, o)
}

// Legitimate normal recovery control: a below-threshold success with a healthy
// inner path still promotes the backend and keeps the session in place.
func TestIssue732_BlockedBackend_FastOuterSuccess_WorkingInner_RecoversWithoutMigration(t *testing.T) {
	f := fastFixture(t, models.TunnelStatusHandshakeBlocked, &issue732CanaryDevice{})

	o := f.sweep(t)
	if o.sourceStatus != models.TunnelStatusActive {
		t.Errorf("expected recovery to active, got %q", o.sourceStatus)
	}
	if o.canaryCalls == 0 {
		t.Error("expected the inner canary to be consulted on recovery")
	}
	assertIssue732SessionPreservedOnSource(t, o)
}

// Fast-success failed-inner control: below the outer threshold, one inner
// failure keeps the backend blocked and the session preserved.
func TestIssue732_BlockedBackend_FastOuterSuccess_FailedInner_StaysBlockedPreserved(t *testing.T) {
	dev := &issue732CanaryDevice{fail: true}
	f := fastFixture(t, models.TunnelStatusHandshakeBlocked, dev)

	o := f.sweep(t)
	if o.sourceStatus != models.TunnelStatusHandshakeBlocked {
		t.Errorf("expected handshake_blocked below the failure threshold, got %q", o.sourceStatus)
	}
	if o.canaryCalls == 0 {
		t.Error("expected the inner canary to be consulted")
	}
	assertIssue732SessionPreservedOnSource(t, o)
}

// Adjacent previously-active slow-latency control: an ACTIVE backend keeps its
// existing latency policy (degrade and migrate) despite a healthy inner path.
// The repair is scoped to the handshake_blocked preservation contract.
func TestIssue732_ActiveBackend_SlowOuterSuccess_KeepsExistingLatencyPolicy(t *testing.T) {
	f := slowFixture(t, models.TunnelStatusActive, &issue732CanaryDevice{})

	o := f.sweep(t)
	if o.sourceStatus != models.TunnelStatusDegraded {
		t.Errorf("expected the active backend to degrade on latency as before, got %q", o.sourceStatus)
	}
	if o.canaryCalls != 0 {
		t.Errorf("active latency-only degradation must not consult the inner canary, got %d calls", o.canaryCalls)
	}
}
