package awg

import (
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const defaultContainerCacheTTL = 5 * time.Minute

type containerCacheEntry struct {
	name      string
	expiresAt time.Time
}

func (m *AWGManager) getCachedContainer(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	if m.containerCache == nil {
		return "", false
	}
	entry, ok := m.containerCache[key]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	if !IsValidContainerName(entry.name) {
		return "", false
	}
	return entry.name, true
}

func (m *AWGManager) setCachedContainer(key string, name string) {
	if key == "" || !IsValidContainerName(name) {
		return
	}
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if m.containerCache == nil {
		m.containerCache = make(map[string]containerCacheEntry)
	}
	m.containerCache[key] = containerCacheEntry{
		name:      name,
		expiresAt: time.Now().Add(defaultContainerCacheTTL),
	}
}

func (m *AWGManager) getCachedContainerForClient(client ssh.SSHClient) (string, bool) {
	if client == nil {
		return "", false
	}
	if id := client.GetServerID(); id != nil && *id != 0 {
		if val, ok := m.getCachedContainer(fmt.Sprintf("id:%d", *id)); ok {
			return val, true
		}
	}
	if host := client.GetHost(); host != "" {
		if val, ok := m.getCachedContainer(fmt.Sprintf("host:%s:%d", host, client.GetPort())); ok {
			return val, true
		}
		if val, ok := m.getCachedContainer(fmt.Sprintf("host:%s", host)); ok {
			return val, true
		}
	}
	return "", false
}

func (m *AWGManager) setCachedContainerForClient(client ssh.SSHClient, name string) {
	if client == nil || !IsValidContainerName(name) {
		return
	}
	if id := client.GetServerID(); id != nil && *id != 0 {
		m.setCachedContainer(fmt.Sprintf("id:%d", *id), name)
	}
	if host := client.GetHost(); host != "" {
		m.setCachedContainer(fmt.Sprintf("host:%s:%d", host, client.GetPort()), name)
		m.setCachedContainer(fmt.Sprintf("host:%s", host), name)
	}
}

func (m *AWGManager) setCachedContainerForServer(server *models.Server, name string) {
	if server == nil || !IsValidContainerName(name) {
		return
	}
	if server.ID != 0 {
		m.setCachedContainer(fmt.Sprintf("id:%d", server.ID), name)
	}
	if server.Host != "" {
		port := server.SSHPort
		if port == 0 {
			port = 22
		}
		m.setCachedContainer(fmt.Sprintf("host:%s:%d", server.Host, port), name)
		m.setCachedContainer(fmt.Sprintf("host:%s", server.Host), name)
	}
}

func (m *AWGManager) invalidateContainerCache(server *models.Server) {
	if server == nil {
		return
	}
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if m.containerCache == nil {
		return
	}
	if server.ID != 0 {
		delete(m.containerCache, fmt.Sprintf("id:%d", server.ID))
	}
	if server.Host != "" {
		port := server.SSHPort
		if port == 0 {
			port = 22
		}
		delete(m.containerCache, fmt.Sprintf("host:%s:%d", server.Host, port))
		delete(m.containerCache, fmt.Sprintf("host:%s", server.Host))
	}
}
