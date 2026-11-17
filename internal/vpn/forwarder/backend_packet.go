package forwarder

// BackendPacket is one admitted packet plus the immutable identity of the flow that
// admitted it (issue #861, R15/R16).
//
// The backend queue is the boundary where attribution used to be lost: the pump
// dequeued a bare byte slice and handed it to the device, so a failed or short write
// could only be counted globally. The identity now travels WITH the work, which is why
// there is no paired metadata queue and no side map: one bounded channel carries both
// the bytes and the owner, and the owner is the value captured at enqueue.
//
// Ownership is immutable. A queued packet written after a rekey, a retirement or a
// tuple reuse credits the incarnation that admitted it, never whoever owns the tuple
// now. The pointer's lifetime is bounded by the admitted work: the flow entry that
// holds it is dropped when the flow retires, and the queue is bounded, so no retired
// payload is retained beyond the traffic that was already admitted.
type BackendPacket struct {
	packet []byte
	// owner is the admitting flow's evidence block, nil for a packet enqueued by a
	// path that carries no flow identity (the legacy non-policy path).
	owner      *flowStats
	sessionID  string
	generation uint64
}

// newBackendPacket wraps one packet with the identity captured at admission.
func newBackendPacket(packet []byte, owner *flowStats, sessionID string, generation uint64) BackendPacket {
	return BackendPacket{packet: packet, owner: owner, sessionID: sessionID, generation: generation}
}

// Bytes returns the packet payload. It is the same slice that was enqueued; callers
// must treat it as read-only.
func (p BackendPacket) Bytes() []byte { return p.packet }

// NewBackendPacketForTest builds a packet with no admitting flow, for tests outside
// this package that need to place work on a backend queue directly. Production paths
// always carry an owner or explicitly nil, and never use this constructor.
func NewBackendPacketForTest(packet []byte) BackendPacket {
	return BackendPacket{packet: packet}
}

// FlowIdentity reports the session and route generation that admitted the packet, and
// whether an admitting flow was known at all.
func (p BackendPacket) FlowIdentity() (sessionID string, generation uint64, known bool) {
	return p.sessionID, p.generation, p.owner != nil
}
