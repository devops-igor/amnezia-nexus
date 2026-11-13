package tunnel

// Ownership of the runtime caller mark across a SEQUENTIAL enrollment retry.
//
// One backend slot has three quarantine owners (durable row, pool generation and
// the prober's server-keyed caller mark). A deploy enrollment must end with all
// three released by the attempt that actually qualified, and only by it.
//
// The durable and pool owners are re-bound to a new attempt by the pool itself, in
// the same critical section that commits the re-enrollment. The caller mark is
// server-keyed and was established BEFORE that attempt existed (the deploy consumer
// marks the server while the slot still holds the previous row, and
// markEnrollmentLocked deliberately does not invent an attempt), so it kept the
// label of whichever attempt last wrote it. When that attempt FAILED, its withdraw
// path stamps the mark with the failed attempt; the retry's successful
// qualification then refuses to release it, promotion reports success, and the next
// ordinary healthy probe re-applies the stale quarantine.
//
// AdoptEnrollmentAttempt is the missing producer statement: the enrollment that
// just committed attempt N owns this server's caller mark, so N's own qualification
// can release it.

// AdoptEnrollmentAttempt transfers ownership of an existing caller mark to the
// enrollment attempt that has just committed for tunnelID.
//
// It only ever RAISES the recorded owner, never lowers it: an attempt id is issued
// under the pool lock and never reused, so a recorded id that is greater than the
// one being adopted belongs to a LATER enrollment and must keep the mark. This is
// what keeps a delayed call for a superseded enrollment from stealing the current
// one's gate. Nothing is created: with no mark set there is no ownership to
// transfer, and the durable and pool owners already hold the backend out of
// selection.
//
// The published attempt is authoritative here for the same reason
// MarkEnrollmentForAttempt exists: the caller validated it against the row it
// committed, rather than re-deriving it from whatever the slot holds later.
func (hp *HealthProber) AdoptEnrollmentAttempt(serverID, tunnelID int64, attempt uint64) {
	if hp == nil || attempt == 0 {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if hp.pendingEnrollment == nil || !hp.pendingEnrollment[serverID] {
		return
	}
	if recorded := hp.pendingEnrollmentAttempt[serverID]; recorded >= attempt {
		return
	}
	if hp.pendingEnrollmentGeneration == nil {
		hp.pendingEnrollmentGeneration = make(map[int64]int64)
	}
	if hp.pendingEnrollmentAttempt == nil {
		hp.pendingEnrollmentAttempt = make(map[int64]uint64)
	}
	hp.pendingEnrollmentGeneration[serverID] = tunnelID
	hp.pendingEnrollmentAttempt[serverID] = attempt
}
