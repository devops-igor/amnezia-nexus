package policy

// This file exposes read-only size accessors for the DNS route cache so the
// admin stats endpoint (#678) can report the current route-cache size without
// reaching into the cache's internals or holding its lock longer than a copy.

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

// SessionCount returns the number of live session route caches.
func (c *RouteCache) SessionCount() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sessions)
}
