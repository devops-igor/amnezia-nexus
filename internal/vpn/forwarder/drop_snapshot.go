package forwarder

import "time"

// ClientDropSnapshot returns this client's retained pre-flow refusals, newest first.
//
// It is a pure read of a bounded store: no pruning, no recency refresh, no policy
// evaluation, no other session's records. Callers cannot see a session they did not name,
// and a retired session reads as empty rather than resurrecting its evidence.
func (f *Forwarder) ClientDropSnapshot(sessionID string, limit int) DropSnapshot {
	if f == nil {
		return DropSnapshot{}
	}
	return f.clientDrops.SessionSnapshot(sessionID, limit, time.Now())
}
