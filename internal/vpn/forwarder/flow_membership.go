package forwarder

// Per-session flow membership (issue #861).
//
// The flow table is keyed by 5-tuple, so answering "which flows belong to this client"
// used to mean walking the whole table and stopping at a visit cap. That cap is a bound on
// the WORK, not on one client's answer: a busy table could exhaust it before reaching the
// client that was asked about, so a small client's page could come back empty for reasons
// that had nothing to do with that client.
//
// This file keeps a secondary membership map from (session, generation) to the flow keys
// that incarnation owns. It is not a second copy of the flow data: it stores only keys, so
// its memory is proportional to the existing flow count, and every mutation of m.flows goes
// through the helpers below under the SAME DirectEgressManager.mu transaction, so the
// membership can never describe a flow that does not exist or miss one that does.
//
// Invariants (asserted by membershipInvariantLocked and by the tests):
//
//  1. every entry in m.flows appears exactly once, in the bucket of its own session and
//     generation;
//  2. every key in every bucket exists in m.flows with the same session and generation;
//  3. no bucket is left empty.

// flowMemberKey identifies one incarnation's membership bucket.
type flowMemberKey struct {
	sessionID  string
	generation uint64
}

// flowMemberBucket holds the keys that one incarnation owns. The set is bounded by the flow
// table capacity, because a flow can only be in one bucket.
type flowMemberBucket struct {
	keys map[FlowKey]struct{}
}

// memberKeyOf reports the bucket a flow entry belongs to.
func memberKeyOf(entry *flowEntry) flowMemberKey {
	return flowMemberKey{sessionID: entry.sessionID, generation: entry.generation}
}

// storeFlowLocked inserts or replaces a flow and keeps the membership exact. A tuple that
// is re-recorded by another incarnation moves its membership instead of duplicating it.
func (m *DirectEgressManager) storeFlowLocked(key FlowKey, entry *flowEntry) {
	if m == nil || entry == nil {
		return
	}
	if previous, ok := m.flows[key]; ok {
		m.dropMembershipLocked(key, previous)
	}
	m.flows[key] = entry
	m.addMembershipLocked(key, entry)
}

// rebindFlowLocked updates the owning incarnation of an existing flow in place. The
// membership follows the entry, so a rekey never leaves the key in the previous
// incarnation's bucket.
func (m *DirectEgressManager) rebindFlowLocked(key FlowKey, entry *flowEntry, sessionID string, generation uint64) {
	if m == nil || entry == nil {
		return
	}
	m.dropMembershipLocked(key, entry)
	entry.sessionID = sessionID
	entry.generation = generation
	m.addMembershipLocked(key, entry)
}

// removeFlowLocked deletes a flow and its membership together.
func (m *DirectEgressManager) removeFlowLocked(key FlowKey) {
	if m == nil {
		return
	}
	entry, ok := m.flows[key]
	if !ok {
		return
	}
	m.dropMembershipLocked(key, entry)
	delete(m.flows, key)
}

func (m *DirectEgressManager) addMembershipLocked(key FlowKey, entry *flowEntry) {
	bucketKey := memberKeyOf(entry)
	bucket := m.members[bucketKey]
	if bucket == nil {
		bucket = &flowMemberBucket{keys: make(map[FlowKey]struct{})}
		m.members[bucketKey] = bucket
		incarnations := m.sessionBuckets[bucketKey.sessionID]
		if incarnations == nil {
			incarnations = make(map[uint64]*flowMemberBucket)
			m.sessionBuckets[bucketKey.sessionID] = incarnations
		}
		incarnations[bucketKey.generation] = bucket
	}
	bucket.keys[key] = struct{}{}
}

func (m *DirectEgressManager) dropMembershipLocked(key FlowKey, entry *flowEntry) {
	bucketKey := memberKeyOf(entry)
	bucket := m.members[bucketKey]
	if bucket == nil {
		return
	}
	delete(bucket.keys, key)
	if len(bucket.keys) == 0 {
		// An empty bucket would be an orphan: nothing left to read, but memory still held.
		delete(m.members, bucketKey)
		if incarnations := m.sessionBuckets[bucketKey.sessionID]; incarnations != nil {
			delete(incarnations, bucketKey.generation)
			if len(incarnations) == 0 {
				// Same for a session whose last incarnation is gone.
				delete(m.sessionBuckets, bucketKey.sessionID)
			}
		}
	}
}

// membershipKeysLocked returns the flow keys of one selection, how many buckets it had to
// visit, and the selection's exact key count.
//
// A zero generation means "every incarnation of this session", which is the documented
// meaning of the request's generation field elsewhere in the diagnosis API. Either way the
// work is session-local: the per-session bucket set is consulted, so another client's
// incarnations are never iterated, whatever the table holds.
//
// total is the selection's own size, computed while collecting, so a caller can report an
// exact total even when its visit is capped. The returned slice is the caller's and holds
// keys only.
func (m *DirectEgressManager) membershipKeysLocked(sessionID string, generation uint64) (keys []FlowKey, buckets int, total int) {
	if m == nil || sessionID == "" {
		return nil, 0, 0
	}
	incarnations := m.sessionBuckets[sessionID]
	if len(incarnations) == 0 {
		return nil, 0, 0
	}
	if generation != 0 {
		bucket := incarnations[generation]
		if bucket == nil {
			return nil, 1, 0
		}
		out := make([]FlowKey, 0, len(bucket.keys))
		for key := range bucket.keys {
			out = append(out, key)
		}
		return out, 1, len(out)
	}
	var out []FlowKey
	for _, bucket := range incarnations {
		buckets++
		for key := range bucket.keys {
			out = append(out, key)
		}
	}
	return out, buckets, len(out)
}

// membershipInvariantLocked reports the membership defects the helpers above must prevent.
// It is a check, not a repair: the tests use it after every mutation path, and a production
// caller never pays for it.
func (m *DirectEgressManager) membershipInvariantLocked() (dangling, missing, duplicates int) {
	inBucket := make(map[FlowKey]int, len(m.flows))
	for key, entry := range m.flows {
		bucket := m.members[memberKeyOf(entry)]
		if bucket == nil {
			missing++
			continue
		}
		if _, ok := bucket.keys[key]; !ok {
			missing++
		}
	}
	for _, bucket := range m.members {
		for key := range bucket.keys {
			inBucket[key]++
			if _, ok := m.flows[key]; !ok {
				dangling++
			}
		}
	}
	for _, count := range inBucket {
		if count > 1 {
			duplicates++
		}
	}
	// The per-session bucket set must reach every bucket exactly once, or a session-local
	// read would silently skip an incarnation.
	reachable := make(map[*flowMemberBucket]int, len(m.members))
	for _, incarnations := range m.sessionBuckets {
		for _, bucket := range incarnations {
			reachable[bucket]++
		}
	}
	for bucketKey, bucket := range m.members {
		if reachable[bucket] != 1 {
			missing++
			continue
		}
		if m.sessionBuckets[bucketKey.sessionID][bucketKey.generation] != bucket {
			missing++
		}
	}
	for _, count := range reachable {
		if count > 1 {
			duplicates++
		}
	}
	return dangling, missing, duplicates
}
