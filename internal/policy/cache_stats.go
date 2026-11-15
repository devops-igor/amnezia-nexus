package policy

// This file exposes a read-only size accessor for the DNS route cache so the
// admin stats endpoint (#678) can report the current route-cache size without
// reaching into the cache's internals or holding its lock longer than a copy.
//
// SessionCount stays in route_cache.go next to the scope bookkeeping it counts;
// only the entry total is #678-specific.

// EntryCount returns the total number of route-cache entries currently held
// across all live sessions. It is a point-in-time count of cached DNS-derived
// routing decisions, not a traffic counter.
func (c *RouteCache) EntryCount() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalEntries
}
