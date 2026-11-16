package forwarder

// Oversized return attribution.
//
// Two producers refuse a return reply for exceeding MaxClientQueuePacketBytes:
// the proxy/backend return path (RouteBackendToClient) and the direct WAN return
// path (DeliverDirectWANReply). The aggregate dropsPacketTooLarge counter keeps
// its existing meaning; these two tallies say WHICH producer refused the reply
// and how large the largest refused reply was, so an operator no longer has to
// infer the origin of the loss.
//
// The record is descriptive and deliberately minimal: a count and one size in
// bytes per producer. No payload, address, peer key, session identifier or
// per-flow entry is kept or logged, so the cost is fixed no matter how much
// traffic is dropped. A count of zero means that producer refused nothing; a
// non-zero maximum says only that some reply was larger than the queue bound,
// never why (aggregation, offload or a mis-sized sender remain unproven).

import "sync/atomic"

// oversizedReturnTally is one return producer's oversized-rejection record: how
// many replies it refused and the largest refused payload size it saw.
type oversizedReturnTally struct {
	count    atomic.Uint64
	maxBytes atomic.Uint64
}

// OversizedReturnAttribution splits oversized return rejections by the producer
// that refused them, with the largest refused reply size per producer in bytes.
type OversizedReturnAttribution struct {
	BackendCount    uint64
	BackendMaxBytes uint64
	DirectCount     uint64
	DirectMaxBytes  uint64
}

// recordOversizedReturn books one oversized return refusal against producer
// tally t. The aggregate counters are advanced HERE rather than at the two
// producer call sites, so the published total is always exactly the sum of the
// two producer counts and the split cannot drift from it.
func (f *Forwarder) recordOversizedReturn(t *oversizedReturnTally, size int) {
	t.count.Add(1)
	raiseAtomicMax(&t.maxBytes, uint64(size)) // #nosec G115 -- callers pass a packet length above the queue bound.
	f.dropsPacketTooLarge.Add(1)
	f.dropsTotal.Add(1)
}

// raiseAtomicMax stores n into c when it exceeds the current value.
func raiseAtomicMax(c *atomic.Uint64, n uint64) {
	for {
		current := c.Load()
		if n <= current {
			return
		}
		if c.CompareAndSwap(current, n) {
			return
		}
	}
}

// OversizedReturnStats returns the oversized return rejections in the current
// Start() epoch split by the producer that refused them, together with the
// largest refused reply size per producer.
func (f *Forwarder) OversizedReturnStats() OversizedReturnAttribution {
	if f == nil {
		return OversizedReturnAttribution{}
	}
	return OversizedReturnAttribution{
		BackendCount:    f.oversizedBackendReturns.count.Load(),
		BackendMaxBytes: f.oversizedBackendReturns.maxBytes.Load(),
		DirectCount:     f.oversizedDirectReturns.count.Load(),
		DirectMaxBytes:  f.oversizedDirectReturns.maxBytes.Load(),
	}
}
