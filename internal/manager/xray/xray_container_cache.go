package xray

import (
	"fmt"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const defaultContainerCacheTTL = 5 * time.Minute

type containerCacheEntry struct {
	running   bool
	expiresAt time.Time
}

type xrayContainerCache struct {
	mu    sync.RWMutex
	cache map[string]containerCacheEntry
}

func newXrayContainerCache() *xrayContainerCache {
	return &xrayContainerCache{
		cache: make(map[string]containerCacheEntry),
	}
}

func (c *xrayContainerCache) get(key string) (bool, bool) {
	if key == "" {
		return false, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cache == nil {
		return false, false
	}
	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return false, false
	}
	return entry.running, true
}

func (c *xrayContainerCache) set(key string, running bool) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = make(map[string]containerCacheEntry)
	}
	c.cache[key] = containerCacheEntry{
		running:   running,
		expiresAt: time.Now().Add(defaultContainerCacheTTL),
	}
}

func (c *xrayContainerCache) invalidate(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, key)
}

func (c *xrayContainerCache) keyForServer(server *models.Server) string {
	if server == nil {
		return ""
	}
	if server.ID != 0 {
		return fmt.Sprintf("id:%d", server.ID)
	}
	if server.Host != "" {
		return fmt.Sprintf("host:%s:%d", server.Host, server.SSHPort)
	}
	return ""
}
