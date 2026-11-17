package vpn

// DNS history lifetime for the per-client diagnosis (issue #861).
//
// Both history writers run after the client's reply was delivered: the answer record
// first, the terminal event last. A client can disconnect in that window, so an
// already-admitted producer can resume after its session's history was retired. The
// lifetime recorded here is the authority that decides those late writes: it opens at
// query receipt, closes in the same critical section that erases the rows, and both
// writers require it under the lock they append with.
//
// Lock order: dnsRecordsMu sits below the forwarder lock and above the ledger's own
// mutex. The lifetime helpers never call the route authority while holding it.

// historyWriteAllowedLocked reports whether a history row may be appended for a receipt
// of this session. The caller holds dnsRecordsMu for writing, which is the same lock
// RetireSessionScope takes to close the lifetime and erase the rows, so the decision and
// the append are one critical section: retirement either already closed the lifetime
// (the row is dropped) or runs after the append (the append is erased).
//
// A carried receipt generation older than the lifetime's first generation belongs to an
// earlier lifetime of the same session id, which is what a re-admitted session is, so it
// is refused instead of being credited to the new history.
func (c *MemoryRouteCache) historyWriteAllowedLocked(sessionID string, receiptGeneration uint64, receiptKnown bool) bool {
	if c == nil || c.dnsRecords == nil || sessionID == "" {
		return false
	}
	start, open := c.historyLifetimes[sessionID]
	if !open {
		return false
	}
	if receiptKnown && start != 0 && receiptGeneration < start {
		return false
	}
	return true
}

// openHistoryLifetime records the lifetime a freshly received query belongs to, once per
// lifetime. It is admitted only while the session still owns a route, and the admission
// is re-fenced after the registration, so a retirement that interleaved with it removes
// the entry it reopened instead of leaving history writable for a session that is gone.
// Neither check runs under dnsRecordsMu: the route table takes the forwarder lock, which
// sits above this cache's locks.
func (c *MemoryRouteCache) openHistoryLifetime(sessionID string, receiptGeneration uint64, receiptKnown bool) {
	if c == nil || sessionID == "" || !receiptKnown {
		return
	}
	if c.registerHistoryLifetime(sessionID, receiptGeneration) {
		// The lifetime is already open: a later receipt cannot raise its first generation,
		// or a same-lifetime rekey would be refused as if it came from an older one.
		return
	}
	// Re-fence the registration: a retirement that interleaved with it has already closed
	// this lifetime, and reopening it must not leave history writable for a session that
	// is gone.
	if current, stillKnown := c.observedIncarnation(sessionID); stillKnown && current >= receiptGeneration {
		return
	}
	c.dnsRecordsMu.Lock()
	if start, still := c.historyLifetimes[sessionID]; still && start == receiptGeneration {
		c.closeHistoryLifetimeLocked(sessionID)
	}
	c.dnsRecordsMu.Unlock()
}

// registerHistoryLifetime records the session's history lifetime if it has none and
// reports whether one was already open. The caller holds no history lock.
func (c *MemoryRouteCache) registerHistoryLifetime(sessionID string, receiptGeneration uint64) bool {
	c.dnsRecordsMu.Lock()
	defer c.dnsRecordsMu.Unlock()
	if c.historyLifetimes == nil {
		c.historyLifetimes = make(map[string]uint64)
	}
	if _, open := c.historyLifetimes[sessionID]; open {
		return true
	}
	c.historyLifetimes[sessionID] = receiptGeneration
	return false
}

// closeHistoryLifetimeLocked closes the session's history lifetime and erases the rows it
// owned, as one step: a writer that appends under the same lock either ran before this
// and is erased here, or runs after it and finds the lifetime closed. The caller holds
// dnsRecordsMu for writing.
func (c *MemoryRouteCache) closeHistoryLifetimeLocked(sessionID string) {
	delete(c.historyLifetimes, sessionID)
	if c.dnsRecords != nil {
		c.dnsRecords.RetireSession(sessionID)
	}
}
