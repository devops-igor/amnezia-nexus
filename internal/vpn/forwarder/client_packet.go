package forwarder

// ClientPacket is one reply traveling from a backend device to a client. It carries the
// bytes and, when the reply was matched to a recorded flow before it was queued, the
// evidence block of that flow.
//
// The identity is captured at admission and never re-resolved. The client writer runs
// asynchronously, so a flow can be retired or replaced before the write happens; a
// re-resolution at that point would credit whichever flow owns the tuple now. A nil
// evidence block means the reply was admitted without a matched flow, and the delivered
// outcome is then reported as unattributed rather than guessed.
type ClientPacket struct {
	packet   []byte
	evidence *flowStats
}

// Bytes returns the packet payload. Callers that only observe bytes use this; the
// ownership fields stay inside this package.
func (p ClientPacket) Bytes() []byte { return p.packet }

// NewClientPacketForTest builds a packet with no matched flow, for tests outside this
// package that place work directly on a client queue. Production admission always
// records the match it performed, including an explicit miss.
func NewClientPacketForTest(packet []byte) ClientPacket {
	return ClientPacket{packet: packet}
}

// evidenceOrNil reports the matched flow evidence, if any.
func (p ClientPacket) evidenceOrNil() *flowStats { return p.evidence }
