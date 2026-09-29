package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// serviceIngressAdmission adapts *Service to ingress.Admission for the
// upstream plaintext ingress path (issue #388). The router has no context on
// its packet hot path, so admission runs under context.Background() — the
// same shape as the custom listener's incoming-peer handler.
type serviceIngressAdmission struct {
	svc        *Service
	returnPath *forwarder.ReturnPath
}

// Compile-time proof that the adapter satisfies the ingress admission seam.
var _ ingress.Admission = serviceIngressAdmission{}

// EnsureSession implements ingress.Admission by delegating to
// Service.EnsureBackendSessionForIngress.
func (a serviceIngressAdmission) EnsureSession(o ingress.PeerOwnership) (ingress.SessionHandle, ingress.BackendHandle, error) {
	sess, backend, _, err := a.svc.ensureBackendSessionForIngress(context.Background(), o, a.returnPath)
	if err != nil {
		return nil, nil, err
	}
	return ingressSessionHandle{sess: sess}, ingressBackendHandle{tun: backend}, nil
}

// ingressSessionHandle adapts *models.VPNSession to ingress.SessionHandle.
type ingressSessionHandle struct{ sess *models.VPNSession }

func (h ingressSessionHandle) SessionID() string  { return h.sess.ID }
func (h ingressSessionHandle) AssignedIP() string { return h.sess.AssignedIP }

// ingressBackendHandle adapts *models.BackendTunnel to ingress.BackendHandle.
type ingressBackendHandle struct{ tun *models.BackendTunnel }

func (h ingressBackendHandle) TunnelID() int64 { return h.tun.ID }

// errIngressSubsystems reports an admission attempt on a service whose core
// subsystems are not initialized (the same precondition HandleIncomingPeer
// enforces).
var errIngressSubsystems = errors.New("ingress admission: subsystems not initialized")

// EnsureBackendSessionForIngress is the dedicated routing-session admission
// primitive for the upstream plaintext ingress path (issue #388). It admits
// the peer that durably owns o.IP and returns its backend routing session
// and the selected backend tunnel. Unlike HandleIncomingPeer — the
// handshake-era admission, deliberately left untouched for the custom
// listener and rollback compatibility until #394 — this path has NO
// handshake-era side effects:
//
//   - it never advances AWG/handshake generations (no peerGenerations,
//     no AdvanceLiveSessionGeneration, no endpoint fencing);
//   - it never allocates, repairs, or rebinds a client IP — the assigned
//     IP comes from o (the resolver's durable record) EXACTLY, and a
//     mismatch between the resolver record and the connection's durable
//     lease fails closed instead of being repaired;
//   - it never attaches the custom listener's peerVirtualDevice or any
//     other custom-listener device;
//   - it never queries or mutates AWG crypto state (the upstream engine
//     owns all of it).
//
// Semantics:
//
//   - The durable connection/user behind the ownership is revalidated with
//     the same pure-lookup eligibility checks the transport path uses
//     (AuthenticatePeer), and the ownership record must agree with what
//     authentication finds (same peer key, connection, user, IP).
//   - A healthy live session is reused when valid: status connected, same
//     user, backend enabled+active, and (when the forwarder is wired) a
//     live forwarder route matching the live identity. Liveness for the
//     ingress path is LastSeen-based — there are no generations here — so
//     a live session is reused regardless of upstream handshake age.
//   - When no live session qualifies, a backend is selected through the
//     existing sticky/LB/capacity primitives and a routing session is
//     created lazily with the persisted assigned IP. A pre-existing
//     invalid session (stranded backend, diverged IP) is replaced through
//     SessionManager's own replacement path; the new backend's active
//     count is applied EXACTLY once per admission (issue #388 rework D):
//     the replacement hook owns the transfer (Dec old, Inc new when they
//     differ) and the admission increments only when the hook did not —
//     reported by the ReplacementPoolDelta returned from the admission's
//     own CreateSessionWithDelta call.
//
// Capacity serialization contract (issue #86): s.mu is held for the ENTIRE
// reuse-check -> select -> CreateSession -> IncrementConnections -> route
// registration sequence, exactly like HandleIncomingPeer. The
// check-then-allocate capacity decision (GetActiveTunnels snapshot ->
// selectTunnelForPeer/FilterHealthy -> IncrementConnections) is only safe
// under this serialization; the rollback below depends on it too (no
// concurrent disconnect can interleave a mirror-decrement between the
// increment and the rollback decrement).
//
// Route registration and rollback (issue #388): admission-then-register —
// session/backend selection happens first, CHECKED route registration LAST.
// Any state created for a failed admission is rolled back in reverse order:
// the vpn_sessions row + in-memory session (CloseSession), the backend
// active-connection counter (DecrementConnections, exactly mirroring the
// single increment attributable to this admission), and the sticky
// assignment created solely for this admission (ClearPeerAffinity — a
// pre-existing affinity owned by an earlier successful admission is never
// cleared). On any error no state reports a connected session without a
// usable route.
//
// The returned retirement (empty except on success) must be Wait()ed by the
// caller AFTER releasing its own admission serialization, mirroring
// HandleIncomingPeer's unlock-then-wait ordering; EnsureSessionForIngress
// (the Admission seam below) does this on the caller's behalf.
//
//nolint:gocyclo // durable revalidation, live-session reuse, selection, creation, and rollback are intentionally one serialized admission (issue #86).
func (s *Service) EnsureBackendSessionForIngress(ctx context.Context, o ingress.PeerOwnership) (*models.VPNSession, *models.BackendTunnel, forwarder.Retirement, error) {
	return s.ensureBackendSessionForIngress(ctx, o, nil)
}

// ensureBackendSessionForIngress binds fresh and reused routes to the caller's
// engine lifetime under the same admission serialization as session creation.
//
//nolint:gocyclo // one serialized admission preserves capacity and rollback invariants.
func (s *Service) ensureBackendSessionForIngress(ctx context.Context, o ingress.PeerOwnership, path *forwarder.ReturnPath) (*models.VPNSession, *models.BackendTunnel, forwarder.Retirement, error) {
	var retirement forwarder.Retirement
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
	}()

	if path != nil && path.Closed() {
		return nil, nil, retirement, forwarder.ErrReturnPathClosed
	}
	if s.auth == nil || s.sessionMgr == nil || s.pool == nil {
		return nil, nil, retirement, errIngressSubsystems
	}
	if o.PeerPublicKey == "" || o.ConnectionID == "" || !o.IP.IsValid() {
		return nil, nil, retirement, errors.New("ingress admission: incomplete ownership record")
	}

	// Durable revalidation: the same pure-lookup eligibility checks the
	// transport path uses. Past this point the ownership record is
	// authoritative for the IP.
	user, conn, err := s.auth.AuthenticatePeer(ctx, o.PeerPublicKey)
	if err != nil {
		return nil, nil, retirement, fmt.Errorf("ingress admission: peer authentication failed: %w", err)
	}
	if conn == nil || conn.ID != o.ConnectionID || user == nil || user.ID != o.UserID {
		return nil, nil, retirement, fmt.Errorf("ingress admission: ownership record for peer %s does not match durable state", ingress.RedactKey(o.PeerPublicKey))
	}
	assignedIP := o.IP.String()
	if durable, ok := conn.ClientParams["assigned_ip"].(string); !ok || durable != assignedIP {
		// The resolver's record and the connection's durable lease
		// disagree: fail closed rather than admit on stale ownership
		// (a #391 sync gap). Never repair, never rebind.
		return nil, nil, retirement, fmt.Errorf("ingress admission: durable lease for peer %s is %q, resolver claims %q", ingress.RedactKey(o.PeerPublicKey), durable, assignedIP)
	}

	// Live-session reuse: LastSeen-based validity, no generations. A
	// healthy live session keeps its backend and route through upstream
	// rekeys (issue #388: a rekey must not recreate the Nexus session).
	if live, ok := s.sessionMgr.GetSessionSnapshotByPeer(o.PeerPublicKey); ok && live.UserID == user.ID && live.Status == "connected" {
		backend, backendErr := s.pool.GetTunnelByID(live.BackendTunnelID)
		// Same reuse conditions as HandleIncomingPeer minus generation
		// advancement: administrative eligibility (#90) and runtime
		// health, plus identity agreement with the durable ownership.
		if backendErr == nil &&
			backend.Enabled &&
			strings.EqualFold(backend.Status, models.TunnelStatusActive) &&
			live.AssignedIP == assignedIP &&
			live.PeerPublicKey == o.PeerPublicKey &&
			(s.forwarder == nil || s.forwarder.HasSessionRoute(o.PeerPublicKey, live.ID, conn.ID, live.AssignedIP, backend.ID)) {
			var boundPath bool
			if path != nil && s.forwarder != nil {
				retirement, err = s.forwarder.BindSessionReturnPath(live.ID, conn.ID, o.PeerPublicKey, assignedIP, backend.ID, path)
				if err != nil {
					return nil, nil, retirement, err
				}
				boundPath = true
			}
			// Provenance seam (issue #390 part 1): the returned session is
			// served by the ingress path, so its idle reap must be
			// routing-only even when it was CREATED by the legacy
			// handshake-era admission and adopted for reuse here. The stamp
			// goes through the manager (identity-guarded, under sm.mu) so a
			// reaper sweeping the live map concurrently observes it, not
			// just this returned copy. The custom listener has already torn
			// its transport state down for that session (CloseSession
			// removed it from the live map), so a routing-only reap cannot
			// strand listener state.
			// If the session was concurrently reaped or replaced
			// (MarkSessionAdmissionSource returns false), adoption has
			// failed: roll back any return-path binding done for live.ID and
			// fall through to fresh admission.
			if !s.sessionMgr.MarkSessionAdmissionSource(o.PeerPublicKey, live.ID, models.SessionAdmissionIngress) {
				if boundPath && s.forwarder != nil {
					_, _ = s.forwarder.BindSessionReturnPath(live.ID, conn.ID, o.PeerPublicKey, assignedIP, backend.ID, nil)
				}
				retirement = forwarder.Retirement{}
			} else {
				if s.stickyMgr != nil {
					s.stickyMgr.AssignPeerAffinity(o.PeerPublicKey, backend.ID)
				}
				live.AdmittedVia = models.SessionAdmissionIngress
				return &live, backend, retirement, nil
			}
		}
	}

	// New admission: select through the existing sticky/LB/capacity
	// primitives (all under s.mu — issue #86).
	activeTunnels := s.pool.GetActiveTunnels()
	if len(activeTunnels) == 0 {
		return nil, nil, retirement, loadbalancer.ErrNoActiveBackends
	}

	// Sticky provenance, captured BEFORE selection: if the peer had no
	// affinity yet, the assignment selection is about to install was
	// created solely for this admission and must be rolled back on
	// failure. All affinity mutators for this peer run under s.mu, so the
	// observation cannot race.
	hadSticky := false
	if s.stickyMgr != nil {
		_, hadSticky = s.stickyMgr.GetPeerAffinity(o.PeerPublicKey)
	}

	req := &loadbalancer.RoutingRequest{
		UserID:           user.ID,
		PeerPublicKey:    o.PeerPublicKey,
		AvailableTunnels: activeTunnels,
	}
	backend, err := s.selectTunnelForPeer(ctx, req)
	if err != nil {
		s.rollbackIngressSticky(o.PeerPublicKey, hadSticky)
		return nil, nil, retirement, fmt.Errorf("ingress admission: backend selection failed: %w", err)
	}

	sess, delta, err := s.sessionMgr.CreateSessionWithDeltaAndSource(ctx, user.ID, o.PeerPublicKey, assignedIP, backend.ID, conn.Name, models.SessionAdmissionIngress)
	if err != nil {
		s.rollbackIngressSticky(o.PeerPublicKey, hadSticky)
		return nil, nil, retirement, fmt.Errorf("ingress admission: session creation failed: %w", err)
	}

	// Backend accounting, exactly-once across replacement (issue #388 rework
	// D). CreateSessionWithDelta returns what its replacement hook already
	// moved on the pool counters as part of THIS call's result — no shared
	// state, no serialization needed beyond the s.mu issue-#86 admission
	// sequence itself, and a concurrent legacy CreateSession (which does not
	// take s.mu) can no longer influence the decision:
	//
	//   - fresh creation (no prior session): the hook fired nothing — THIS
	//     admission owns the new backend's increment;
	//   - same-backend replacement (A==B): the hook decremented A (the old
	//     count moves out) and did NOT increment (new backend == old). This
	//     admission restores the count by re-incrementing the same backend —
	//     the peer's live count stays exactly 1, mirroring HandleIncomingPeer;
	//   - different-backend replacement (A!=B): the hook did BOTH halves of
	//     the transfer (Dec(A), Inc(B)) — the admission adds NOTHING, or B
	//     would end at 2 for one session.
	//
	// The per-call delta is the ground truth even when the live snapshot at
	// the top of this function went stale before CreateSession acquired the
	// session manager lock: what matters for exactly-once is what the hook
	// moved for this call, not what the snapshot predicted.
	if !delta.HasInc {
		s.pool.IncrementConnections(backend.ID)
	}

	// Route registration LAST (admission-then-register): only a checked,
	// successful registration makes the admission visible.
	if s.forwarder != nil {
		retirement, err = s.forwarder.TryRegisterSessionWithReturnPath(sess.ID, conn.ID, o.PeerPublicKey, assignedIP, backend.ID, 0, 0, path)
		if err != nil {
			s.rollbackIngressSession(ctx, sess)
			// Mirror decrement of the count THIS admission left on the NEW
			// backend, whatever its provenance above: the admission's own
			// increment (fresh / same-backend) or the hook's transfer
			// increment (different-backend replacement). One routing session
			// held that count; both it and the route are gone now. The
			// hook's Dec of the OLD backend is the old session's own
			// teardown and is not undone — the old session was invalidated
			// by the replacement and the admission failed.
			s.pool.DecrementConnections(backend.ID)
			s.rollbackIngressSticky(o.PeerPublicKey, hadSticky)
			retirement = forwarder.Retirement{}
			return nil, nil, retirement, fmt.Errorf("ingress admission: route registration failed: %w", err)
		}
	}
	s.freshSessionRegistrations.Add(1)

	log.Printf("[vpn/ingress] admitted peer %s ip=%s backend=%d session=%s", ingress.RedactKey(o.PeerPublicKey), assignedIP, backend.ID, sess.ID)
	return sess, backend, retirement, nil
}

// rollbackIngressSession closes a session created for a failed admission —
// DB row and in-memory state — using the same teardown primitive as a clean
// disconnect. Called with s.mu held (issue #86 regime; takes sm.mu inside,
// the one permitted order).
func (s *Service) rollbackIngressSession(ctx context.Context, sess *models.VPNSession) {
	if s.sessionMgr == nil || sess == nil {
		return
	}
	if err := s.sessionMgr.CloseSession(ctx, sess.ID, "disconnected"); err != nil {
		log.Printf("[vpn/ingress] rollback: closing session %s for peer %s: %v", sess.ID, ingress.RedactKey(sess.PeerPublicKey), err)
	}
}

// rollbackIngressSticky clears a sticky assignment created solely for a
// failed admission (hadSticky=false). A pre-existing affinity is left
// untouched — it belongs to an earlier successful admission. Called with
// s.mu held.
func (s *Service) rollbackIngressSticky(peerKey string, hadSticky bool) {
	if s.stickyMgr == nil || hadSticky {
		return
	}
	s.stickyMgr.ClearPeerAffinity(peerKey)
}

// EnsureSessionForIngress adapts EnsureBackendSessionForIngress to the
// ingress.Admission seam: ownership-carried admission whose success leaves a
// live route for the peer and whose failure leaves nothing behind. By
// construction the admitted session's assigned IP equals the ownership
// record (the primitive creates sessions with o.IP verbatim and reuses only
// sessions whose IP matches), which is also the invariant the router's
// defense-in-depth fence re-checks.
func (s *Service) EnsureSessionForIngress(ctx context.Context, o ingress.PeerOwnership) (ingress.SessionHandle, ingress.BackendHandle, error) {
	sess, backend, _, err := s.EnsureBackendSessionForIngress(ctx, o)
	if err != nil {
		return nil, nil, err
	}
	return ingressSessionHandle{sess: sess}, ingressBackendHandle{tun: backend}, nil
}

// IngressAdmission returns the production Admission implementation for the
// upstream plaintext ingress path (issue #388). The ingress engine owner
// wires it into ingress.NewRouter; nothing in the production startup path
// calls this until #393 activates the engine.
func (s *Service) IngressAdmission() ingress.Admission {
	return serviceIngressAdmission{svc: s}
}
