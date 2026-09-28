package ingress

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// SessionHandle exposes the identity fields routing needs from the admitted
// session. Production wiring adapts *models.VPNSession; its ID and AssignedIP
// fields satisfy the interface through small adapter methods if necessary.
type SessionHandle interface {
	SessionID() string
	AssignedIP() string
}

// BackendHandle exposes the tunnel identity route registration needs from the
// selected backend. Production wiring adapts *models.BackendTunnel (ID field).
type BackendHandle interface {
	TunnelID() int64
}

// Admission is the lazily-evaluated admission seam. Production wiring adapts
// vpn.Service.HandleIncomingPeer, preserving its issue-#86 contract: the
// implementation holds its own serialization (the service lock) across
// backend select, session creation, and pool-counter increments, and reuses a
// healthy live session for a peer across rekeys instead of recreating it. The
// router relies on both properties; do not point it at an implementation
// without them.
type Admission interface {
	// EnsureSession admits the peer: it returns the peer's (possibly already
	// live) session and the selected backend, or an error when the peer
	// cannot be admitted. Both handles must be non-nil on success.
	EnsureSession(peerPublicKey string) (SessionHandle, BackendHandle, error)
}

// AdmissionFunc adapts an ordinary function to the Admission interface.
type AdmissionFunc func(peerPublicKey string) (SessionHandle, BackendHandle, error)

// EnsureSession implements Admission.
func (f AdmissionFunc) EnsureSession(peerPublicKey string) (SessionHandle, BackendHandle, error) {
	return f(peerPublicKey)
}

// routeRegistrar is the forwarder surface the router depends on: route
// registration plus route verification and the client-to-backend submission.
// *forwarder.Forwarder implements it. Registration happens only when the
// live route does not already match the admitted identity — never per packet
// — because registration replaces the route generation (stopping the old
// pump), which must not churn on every datagram.
type routeRegistrar interface {
	BeginRegisterSessionWithLimit(sessionID, connectionID, peerKey, assignedIP string, backendTunnelID int64, limitDownBps, limitUpBps int64) forwarder.Retirement
	RouteClientToBackend(peerKey string, packet []byte) error
	HasSessionRoute(peerKey, sessionID, connectionID, assignedIP string, backendTunnelID int64) bool
}

// Compile-time proof that the production forwarder satisfies the seam.
var _ routeRegistrar = (*forwarder.Forwarder)(nil)

// Stats is a point-in-time snapshot of the router's admission and ownership
// counters.
type Stats struct {
	// AdmittedSessions counts lazy admissions (first valid plaintext for a
	// peer without a live matching route), not per-packet events.
	AdmittedSessions        uint64 `json:"admitted_sessions"`
	MalformedPacketDrops    uint64 `json:"malformed_packet_drops"`
	UnmappedSourceIPDrops   uint64 `json:"unmapped_source_ip_drops"`
	OwnershipMismatchDrops  uint64 `json:"ownership_mismatch_drops"`
	AdmissionRejectedDrops  uint64 `json:"admission_rejected_drops"`
	RouteRegistrationErrors uint64 `json:"route_registration_errors"`
}

// admittedRoute is the memoized identity of one peer's admission: the exact
// tuple HasSessionRoute validates the live forwarder route against.
type admittedRoute struct {
	sessionID    string
	connectionID string
	assignedIP   string
	backendID    int64
}

// Router turns one plaintext packet into a routed backend submission or a
// counted drop. Admission runs lazily: once per peer for as long as the
// admitted route stays live, exactly like the custom listener admits per
// handshake rather than per packet. Construct with NewRouter; a Router is
// safe for concurrent use.
type Router struct {
	resolver  *Resolver
	admission Admission
	forwarder routeRegistrar

	admittedSessions atomic.Uint64
	malformedDrops   atomic.Uint64
	unmappedDrops    atomic.Uint64
	mismatchDrops    atomic.Uint64
	rejectedDrops    atomic.Uint64
	routeRegErrors   atomic.Uint64

	// stateMu guards sessions and serializes admission. Fast packets (memo
	// hit) hold it only for the map read; admission holds it across the
	// callback so a first-packet burst cannot stampede the admission
	// implementation even if its own serialization were ever weakened,
	// and so exactly-once admission per burst is observable regardless of
	// the callback's internals (production admission additionally
	// serializes itself under the service lock — issue #86).
	stateMu sync.Mutex
	// sessions maps peer public key -> last admitted identity.
	sessions map[string]admittedRoute
}

// NewRouter constructs a Router. All dependencies are required; a nil value
// for any of them is a programming error and panics.
func NewRouter(resolver *Resolver, admission Admission, fwd *forwarder.Forwarder) *Router {
	if resolver == nil || admission == nil || fwd == nil {
		panic("ingress: NewRouter requires resolver, admission and forwarder")
	}
	return &Router{
		resolver:  resolver,
		admission: admission,
		forwarder: fwd,
		sessions:  make(map[string]admittedRoute),
	}
}

// HandlePacket processes one plaintext IPv4 packet from the upstream client
// device: parse -> resolve the durable owner of the source IP -> admit the
// owning peer lazily (skipped while the admitted route is still live, which
// is what keeps rekeys session-stable: Nexus never sees the upstream
// handshake, and a live session keeps its backend through rekeys) -> verify
// exact ownership -> submit the packet to the backend through the forwarder
// exactly like the custom listener path does. Every drop is classified and
// counted.
func (r *Router) HandlePacket(packet []byte) error {
	src, ok := ParseIPv4Source(packet)
	if !ok {
		r.malformedDrops.Add(1)
		return dropError(ErrDropMalformed, ReasonMalformed)
	}

	owner, known := r.resolver.Lookup(src)
	if !known {
		r.unmappedDrops.Add(1)
		return dropError(ErrDropUnmapped, ReasonUnmappedSource)
	}

	// Fast path: a previously admitted identity whose forwarder route is
	// still live routes without re-running admission.
	if r.routeLive(owner) {
		return r.submit(owner, packet)
	}

	// Slow path: admit under the router's serialization lock.
	r.stateMu.Lock()
	// Double-check after acquiring the lock: a concurrent first packet for
	// the same peer may have completed admission already.
	if r.routeLiveLocked(owner) {
		r.stateMu.Unlock()
		return r.submit(owner, packet)
	}
	session, backend, err := r.admission.EnsureSession(owner.PeerPublicKey)
	if err != nil {
		r.stateMu.Unlock()
		r.rejectedDrops.Add(1)
		return fmt.Errorf("%w: peer %s: %w", ErrAdmissionRejected, RedactKey(owner.PeerPublicKey), err)
	}
	if session == nil || backend == nil {
		r.stateMu.Unlock()
		r.rejectedDrops.Add(1)
		return fmt.Errorf("%w: peer %s: nil session or backend handle", ErrAdmissionContract, RedactKey(owner.PeerPublicKey))
	}

	// Defense-in-depth ownership check at admission time: the admitted
	// session's assigned IP must equal the resolver's durable record.
	// Divergence means the resolver and the session store disagree (a
	// #391 sync gap, a manual DB edit); the packet is dropped and counted,
	// never routed. Upstream AllowedIPs enforcement should make this
	// impossible — this check is the second fence.
	assigned := session.AssignedIP()
	if assigned != owner.IP.String() {
		r.stateMu.Unlock()
		r.mismatchDrops.Add(1)
		return dropError(ErrDropMismatch, ReasonOwnershipMismatch)
	}

	route := admittedRoute{
		sessionID:    session.SessionID(),
		connectionID: owner.ConnectionID,
		assignedIP:   assigned,
		backendID:    backend.TunnelID(),
	}
	retirement, regErr := r.registerLocked(owner, route)
	if regErr != nil {
		r.stateMu.Unlock()
		return regErr
	}
	r.sessions[owner.PeerPublicKey] = route
	r.stateMu.Unlock()
	// Join any replaced route's in-flight device writes only after
	// releasing stateMu, mirroring HandleIncomingPeer's unlock-then-wait
	// ordering so a slow client write cannot stall other peers' ingress.
	retirement.Wait()
	r.admittedSessions.Add(1)

	return r.submit(owner, packet)
}

// routeLive reports whether the memoized admission for the owner still
// matches a live forwarder route. Lock-free shortcut on an empty memo.
func (r *Router) routeLive(o PeerOwnership) bool {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	return r.routeLiveLocked(o)
}

// routeLiveLocked is routeLive; stateMu must be held.
func (r *Router) routeLiveLocked(o PeerOwnership) bool {
	route, ok := r.sessions[o.PeerPublicKey]
	if !ok {
		return false
	}
	// The memo must agree with the resolver's durable record; divergence
	// (e.g. a #391 revocation after admission) forces re-admission.
	if route.assignedIP != o.IP.String() || route.connectionID != o.ConnectionID {
		return false
	}
	return r.forwarder.HasSessionRoute(o.PeerPublicKey, route.sessionID, route.connectionID, route.assignedIP, route.backendID)
}

// registerLocked installs the route when the forwarder does not already hold
// a matching one and reports the retirement of any replaced route. The
// assigned IP always comes from the resolver's durable record — never from
// the packet — so srcIP == route.assignedIP by construction and the
// forwarder's issue-#89 rebind branch cannot trigger on this path.
// stateMu must be held.
func (r *Router) registerLocked(o PeerOwnership, route admittedRoute) (forwarder.Retirement, error) {
	if r.forwarder.HasSessionRoute(o.PeerPublicKey, route.sessionID, route.connectionID, route.assignedIP, route.backendID) {
		return forwarder.Retirement{}, nil
	}
	retirement := r.forwarder.BeginRegisterSessionWithLimit(route.sessionID, route.connectionID, o.PeerPublicKey, route.assignedIP, route.backendID, 0, 0)
	if !r.forwarder.HasSessionRoute(o.PeerPublicKey, route.sessionID, route.connectionID, route.assignedIP, route.backendID) {
		r.routeRegErrors.Add(1)
		return forwarder.Retirement{}, fmt.Errorf("ingress: route registration for peer %s did not take effect", RedactKey(o.PeerPublicKey))
	}
	return retirement, nil
}

// submit hands the packet to the forwarder's client->backend path — the same
// primitive the custom listener's packet router uses, with the same fast-path
// semantics (srcIP equals the route's assigned IP, so no rebind can occur).
func (r *Router) submit(o PeerOwnership, packet []byte) error {
	if err := r.forwarder.RouteClientToBackend(o.PeerPublicKey, packet); err != nil {
		// Forwarder-level rejections (queue full, rate limit, backend
		// missing) are already counted on the forwarder's own counters;
		// surface the cause to the caller.
		return fmt.Errorf("ingress: forward packet for peer %s: %w", RedactKey(o.PeerPublicKey), err)
	}
	return nil
}

// StatsSnapshot returns the current counter values.
func (r *Router) StatsSnapshot() Stats {
	return Stats{
		AdmittedSessions:        r.admittedSessions.Load(),
		MalformedPacketDrops:    r.malformedDrops.Load(),
		UnmappedSourceIPDrops:   r.unmappedDrops.Load(),
		OwnershipMismatchDrops:  r.mismatchDrops.Load(),
		AdmissionRejectedDrops:  r.rejectedDrops.Load(),
		RouteRegistrationErrors: r.routeRegErrors.Load(),
	}
}
