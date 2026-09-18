package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
)

// AWGIPAllocation represents an allocated IP record in awg_ip_allocations.
type AWGIPAllocation struct {
	ID        int64     `json:"id"`
	ServerID  int64     `json:"server_id"`
	ClientID  string    `json:"client_id"`
	IP        string    `json:"ip"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AllocateAWGClientIP atomically reserves and allocates the next available IP address
// for an AWG client on the specified server subnet.
//
// Behavior:
//  1. Checks if clientID or clientPubKey already has an active allocation on this server,
//     and reuses that IP if present (idempotent).
//  2. Fetches all currently allocated IPs from DB for this server.
//  3. Merges them with usedConfigIPs from remote configuration into a unified used IP set.
//  4. Calculates the next available IP using awg.GetNextIP.
//  5. Inserts a new allocation row into awg_ip_allocations.
//  6. If a unique constraint violation occurs (concurrent allocation collision), it retries.
func (d *DB) AllocateAWGClientIP(
	ctx context.Context,
	serverID int64,
	clientID, clientPubKey string,
	usedConfigIPs []string,
	subnetAddr string,
	subnetCIDR int,
	gatewayIP string,
) (string, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	clientID = strings.TrimSpace(clientID)
	clientPubKey = strings.TrimSpace(clientPubKey)
	storedClientID := clientPubKey
	if storedClientID == "" {
		storedClientID = clientID
	}

	const maxRetries = 50
	for attempt := 0; attempt < maxRetries; attempt++ {
		// 1. Idempotency: Check if clientID or clientPubKey already has an active allocation on this server
		existingIP, err := d.findExistingAllocation(ctx, serverID, clientID, clientPubKey)
		if err != nil {
			return "", err
		}
		if existingIP != "" {
			claimed, claimErr := d.isAllocationClaimedByOther(ctx, serverID, existingIP, clientID, clientPubKey)
			if claimErr != nil {
				return "", claimErr
			}
			if !claimed {
				return existingIP, nil
			}
		}

		// 2. Query all existing allocated IPs for this server
		allocatedIPs, err := d.fetchAllocatedIPs(ctx, serverID)
		if err != nil {
			return "", err
		}

		// 3. Merge usedConfigIPs and DB allocations into unified set
		combinedUsed := mergeUsedIPs(usedConfigIPs, allocatedIPs)

		// 4. Calculate next available IP
		nextIP, err := awg.GetNextIP(combinedUsed, subnetAddr, subnetCIDR, gatewayIP)
		if err != nil {
			return "", err
		}

		// 5. Insert record into awg_ip_allocations
		now := time.Now().UTC().Format(time.RFC3339)
		_, err = d.sqlDB.ExecContext(ctx,
			"INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at) VALUES (?, ?, ?, 'allocated', ?, ?)",
			serverID, storedClientID, nextIP, now, now,
		)
		if err != nil {
			if isUniqueConstraintError(err) {
				// Concurrent collision, retry with refreshed allocation state
				continue
			}
			return "", fmt.Errorf("failed to insert AWG IP allocation: %w", err)
		}

		return nextIP, nil
	}

	return "", fmt.Errorf("failed to allocate AWG IP after %d attempts due to collisions", maxRetries)
}

func (d *DB) findExistingAllocation(ctx context.Context, serverID int64, clientID, clientPubKey string) (string, error) {
	clientID = strings.TrimSpace(clientID)
	clientPubKey = strings.TrimSpace(clientPubKey)
	if clientID == "" && clientPubKey == "" {
		return "", nil
	}

	var existingIP string
	var err error
	if clientID != "" && clientPubKey != "" && clientID != clientPubKey {
		err = d.sqlDB.QueryRowContext(ctx,
			"SELECT ip FROM awg_ip_allocations WHERE server_id = ? AND status = 'allocated' AND (client_id = ? OR client_id = ?) LIMIT 1",
			serverID, clientID, clientPubKey,
		).Scan(&existingIP)
	} else {
		lookupID := clientPubKey
		if lookupID == "" {
			lookupID = clientID
		}
		err = d.sqlDB.QueryRowContext(ctx,
			"SELECT ip FROM awg_ip_allocations WHERE server_id = ? AND status = 'allocated' AND client_id = ? LIMIT 1",
			serverID, lookupID,
		).Scan(&existingIP)
	}

	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to check existing AWG IP allocation: %w", err)
	}
	return existingIP, nil
}

func (d *DB) isAllocationClaimedByOther(ctx context.Context, serverID int64, ip, clientID, clientPubKey string) (bool, error) {
	clientID = strings.TrimSpace(clientID)
	clientPubKey = strings.TrimSpace(clientPubKey)
	var ownerID string
	err := d.sqlDB.QueryRowContext(ctx,
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated' LIMIT 1",
		serverID, ip,
	).Scan(&ownerID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to verify AWG IP ownership: %w", err)
	}
	ownerID = strings.TrimSpace(ownerID)
	if (clientID != "" && ownerID == clientID) || (clientPubKey != "" && ownerID == clientPubKey) {
		return false, nil
	}
	return true, nil
}

func (d *DB) fetchAllocatedIPs(ctx context.Context, serverID int64) ([]string, error) {
	rows, err := d.sqlDB.QueryContext(ctx,
		"SELECT ip FROM awg_ip_allocations WHERE server_id = ? AND status = 'allocated'",
		serverID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query allocated AWG IPs: %w", err)
	}
	defer rows.Close()

	var allocatedIPs []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("failed to scan allocated AWG IP: %w", err)
		}
		allocatedIPs = append(allocatedIPs, ip)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed reading allocated AWG IPs: %w", err)
	}
	return allocatedIPs, nil
}

func mergeUsedIPs(usedConfigIPs, allocatedIPs []string) []string {
	usedMap := make(map[string]bool, len(usedConfigIPs)+len(allocatedIPs))
	var combinedUsed []string
	for _, ip := range usedConfigIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" && !usedMap[ip] {
			usedMap[ip] = true
			combinedUsed = append(combinedUsed, ip)
		}
	}
	for _, ip := range allocatedIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" && !usedMap[ip] {
			usedMap[ip] = true
			combinedUsed = append(combinedUsed, ip)
		}
	}
	return combinedUsed
}

// ReleaseAWGClientIP removes or frees the allocated IP record for a client on the specified server.
func (d *DB) ReleaseAWGClientIP(ctx context.Context, serverID int64, clientID, ip string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	clientID = strings.TrimSpace(clientID)
	ip = strings.TrimSpace(ip)
	if clientID == "" && ip == "" {
		return nil
	}

	var err error
	if clientID != "" && ip != "" {
		_, err = d.sqlDB.ExecContext(ctx,
			"DELETE FROM awg_ip_allocations WHERE server_id = ? AND client_id = ? AND ip = ?",
			serverID, clientID, ip,
		)
	} else if ip != "" {
		_, err = d.sqlDB.ExecContext(ctx,
			"DELETE FROM awg_ip_allocations WHERE server_id = ? AND ip = ?",
			serverID, ip,
		)
	} else {
		_, err = d.sqlDB.ExecContext(ctx,
			"DELETE FROM awg_ip_allocations WHERE server_id = ? AND client_id = ?",
			serverID, clientID,
		)
	}

	if err != nil {
		return fmt.Errorf("failed to release AWG client IP: %w", err)
	}
	return nil
}

// TransferAWGClientIPLease transfers the allocation record to a new client ID or public key
// when an existing client is re-keyed or re-registered.
func (d *DB) TransferAWGClientIPLease(ctx context.Context, serverID int64, newClientID, oldClientID, ip string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	newClientID = strings.TrimSpace(newClientID)
	oldClientID = strings.TrimSpace(oldClientID)
	ip = strings.TrimSpace(ip)
	if newClientID == "" || oldClientID == "" || ip == "" {
		return fmt.Errorf("lease transfer rejected: missing required parameters (newClientID=%q, oldClientID=%q, ip=%q)", newClientID, oldClientID, ip)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.sqlDB.ExecContext(ctx,
		"UPDATE awg_ip_allocations SET client_id = ?, updated_at = ? WHERE server_id = ? AND client_id = ? AND ip = ?",
		newClientID, now, serverID, oldClientID, ip,
	)
	if err != nil {
		return fmt.Errorf("failed to transfer AWG IP lease: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected for AWG IP lease transfer: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("lease transfer rejected: IP %s on server %d is not owned by %s", ip, serverID, oldClientID)
	}
	return nil
}

// AdoptAWGClientIPLease adopts an existing IP for a client into awg_ip_allocations if it is not
// already claimed by another client. Used for migrating/upgrading legacy clients without DB lease rows.
func (d *DB) AdoptAWGClientIPLease(ctx context.Context, serverID int64, clientID, clientPubKey, ip string) (bool, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	clientID = strings.TrimSpace(clientID)
	clientPubKey = strings.TrimSpace(clientPubKey)
	ip = strings.TrimSpace(ip)
	if ip == "" || net.ParseIP(ip) == nil {
		return false, nil
	}
	storedClientID := clientPubKey
	if storedClientID == "" {
		storedClientID = clientID
	}
	if storedClientID == "" {
		return false, nil
	}

	// Check if this IP is already allocated on this server
	var ownerID string
	err := d.sqlDB.QueryRowContext(ctx,
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated' LIMIT 1",
		serverID, ip,
	).Scan(&ownerID)
	if err == nil {
		ownerID = strings.TrimSpace(ownerID)
		if (storedClientID != "" && ownerID == storedClientID) || (clientID != "" && ownerID == clientID) || (clientPubKey != "" && ownerID == clientPubKey) {
			return true, nil
		}
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("failed to check existing IP allocation for adoption: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Check if this client already has an active allocation on this server
	var existingClientIP string
	err = d.sqlDB.QueryRowContext(ctx,
		"SELECT ip FROM awg_ip_allocations WHERE server_id = ? AND status = 'allocated' AND (client_id = ? OR client_id = ?) LIMIT 1",
		serverID, storedClientID, clientID,
	).Scan(&existingClientIP)
	if err == nil {
		if existingClientIP == ip {
			return true, nil
		}
		// If the client currently has a different active allocation on this server that was marked 'allocated',
		// but ip is unallocated to any other client: update the old allocation to status = 'superseded' and activate ip.
		_, err = d.sqlDB.ExecContext(ctx,
			"UPDATE awg_ip_allocations SET status = 'superseded', updated_at = ? WHERE server_id = ? AND status = 'allocated' AND (client_id = ? OR client_id = ?)",
			now, serverID, storedClientID, clientID,
		)
		if err != nil {
			return false, fmt.Errorf("failed to supersede existing allocation for client: %w", err)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("failed to check client allocation for adoption: %w", err)
	}

	_, err = d.sqlDB.ExecContext(ctx,
		`INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at)
		VALUES (?, ?, ?, 'allocated', ?, ?)
		ON CONFLICT(server_id, ip) DO UPDATE SET
			client_id = excluded.client_id,
			status = 'allocated',
			updated_at = excluded.updated_at`,
		serverID, storedClientID, ip, now, now,
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to adopt AWG IP lease: %w", err)
	}
	return true, nil
}

// GetAllocatedAWGIPs returns a slice of all allocated IPs for the server.
func (d *DB) GetAllocatedAWGIPs(ctx context.Context, serverID int64) ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.sqlDB.QueryContext(ctx,
		"SELECT ip FROM awg_ip_allocations WHERE server_id = ? AND status = 'allocated' ORDER BY id ASC",
		serverID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query allocated AWG IPs: %w", err)
	}
	defer rows.Close()

	ips := make([]string, 0)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("failed to scan allocated AWG IP: %w", err)
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed reading allocated AWG IPs: %w", err)
	}
	return ips, nil
}

// GetAWGIPAllocationOwner returns the client_id for the specified allocated IP on a server.
func (d *DB) GetAWGIPAllocationOwner(ctx context.Context, serverID int64, ip string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var clientID string
	err := d.sqlDB.QueryRowContext(ctx,
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated' LIMIT 1",
		serverID, strings.TrimSpace(ip),
	).Scan(&clientID)
	if err != nil {
		return "", err
	}
	return clientID, nil
}
