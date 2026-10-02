// Package ingress routes plaintext client packets produced by the upstream
// client-facing AWG device (clientawg.ClientAWGDevice.ReceiveOutbound) into
// Nexus backend sessions (issue #388).
//
// # Data path
//
//	upstream client engine (amneziawg-go device)
//	  |  UDP datagrams: authenticated, decrypted
//	clientawg.ClientAWGDevice (portal role, owns one VirtualTUN)
//	  |  ReceiveOutbound: authenticated plaintext IPv4
//	ingress.Router.HandlePacket
//	  |-- Resolver.Lookup(src)        durable assigned-IP -> ownership
//	  |-- Admission.EnsureSession     lazy admission, once per live route;
//	  |                               wired to Service.EnsureBackendSessionForIngress,
//	  |                               with capacity serialization and
//	  |                               rekey-stable live-session reuse
//	  '-- forwarder.Forwarder         route registration + RouteClientToBackend
//
// Upstream AllowedIPs enforcement is the first ownership fence: the engine
// only delivers plaintext whose source matches the peer's leased /32. The
// router's own checks are the second fence and never mutate a route to
// self-heal a divergent packet.
//
// # Components
//
//   - Resolver: the durable assigned-IP -> peer ownership map. Loaded at
//     startup from the same durable state the portal leases client IPs from
//     (user_connections.client_params["assigned_ip"], read through
//     database.DB.GetVPNClientIPAssignments, durable rows only) and kept
//     current through an explicit replacement-semantics mutation API that
//     issue #391's event-driven sync builds on.
//
//   - Router: strict structural IPv4 parsing plus the ownership checks that
//     gate lazy admission and forwarder route registration for every
//     plaintext packet.
//
// # Error semantics
//
// HandlePacket returns nil only when the packet was submitted to the selected
// backend's queue. Every other outcome wraps exactly one sentinel, so callers
// classify outcomes with errors.Is, never string matching:
//
//   - ErrDropMalformed: the packet failed the strict structural IPv4 parse
//   - shorter than a minimum header, non-IPv4 version nibble, IHL below
//     5, header length beyond the received bytes, or a total-length field
//     inconsistent with the header or the received length. Counted as
//     MalformedPacketDrops.
//   - ErrDropUnmapped: the parsed source IP has no durable owner in the
//     resolver. Counted as UnmappedSourceIPDrops.
//   - ErrAdmissionRejected: the admission callback refused the peer (unknown
//     peer, disabled or expired user, traffic limit, no healthy backend, or
//     the load balancer's ErrNoActiveBackends). Data-plane backpressure, not
//     a programming error. Counted as AdmissionRejectedDrops.
//   - ErrAdmissionContract: the admission callback returned nil handles with
//     a nil error. Counted as AdmissionRejectedDrops.
//   - ErrDropMismatch: the admitted session's assigned IP disagrees with the
//     resolver's durable record - the resolver and the session store diverge
//     (a #391 sync gap, a manual DB edit). The packet is dropped, never
//     routed, and the route memo is left untouched. Counted as
//     OwnershipMismatchDrops.
//
// A forwarder-level rejection (queue full, rate limit, missing backend) is
// returned wrapped with the peer identity; those events are already counted
// on the forwarder's own counters.
//
// StatsSnapshot exposes the router's counters; the DropReason values double
// as the documented metric counter names.
//
// # Rekey stability
//
// The router never sees upstream handshakes: a rekey replaces only the
// upstream transport session, while plaintext keeps flowing from the same
// assigned IP. As long as the admitted route stays live in the forwarder,
// HandlePacket takes the memoized fast path, so admission runs exactly once
// per live route and the Nexus route session ID survives rekeys unchanged.
//
// # Resolver API contract (issue #391)
//
// The resolver is the single durable-ownership authority on the data path.
// It holds only durable state: LoadResolver and Reload skip session-only
// legacy leases (NeedsMigration=true) and rows without a durable
// assigned_ip, so stale runtime residue can never authorize a source IP;
// the load report's skip counters (skipped_needs_migration and friends)
// keep that filtering observable. Every mutation preserves the load-time
// invariants - one IP per peer, one peer per IP - and fails closed instead
// of repairing:
//
//   - Update registers one lease with replacement semantics: a peer whose
//     lease moves to a different IP is swapped atomically (the previous IP
//     becomes unmapped, concurrent lookups observe old-or-new, never a
//     mixture), so an event-driven sync can apply a lease move as a single
//     step. Re-asserting a peer's exact current ownership is a no-op, so
//     an idempotent re-sync cannot fail. Conflicts (a second peer claiming
//     an owned IP) and malformed input are rejected; error text names the
//     conflicting address and redacts peer keys.
//   - Remove drops one peer's lease (no-op when unknown) and reports the
//     removed address; a removed IP immediately becomes unmapped on the
//     data path and the peer can never re-admit through it.
//   - Reload atomically replaces the whole map from durable state with
//     LoadResolver's durable-only eligibility and conflict rules; on error
//     the previous contents stay untouched, on success readers observe
//     old-or-new, never a mixture.
//
// The router consults the resolver per packet and forces re-admission
// whenever a memoized route diverges from the durable record, so #391's
// event-driven sync only has to keep the resolver current; no router-side
// invalidation hook is needed.
//
// # Wiring status
//
// The upstream amneziawg-go engine is the permanent, active client-facing AWG
// runtime engine in Nexus. Service.EnsureBackendSessionForIngress is the dedicated
// admission primitive, and Service.NewIngressEngine owns the upstream chain:
// clientawg.ClientAWGDevice -> receive loop -> Router -> Admission -> strict
// forwarder path, wired to the service's real forwarder and SessionLiveness.
package ingress
