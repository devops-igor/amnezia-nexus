package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
		existingIP, err := d.findExistingAllocation(ctx, serverID, storedClientID, clientPubKey)
		if err != nil {
			return "", err
		}
		if existingIP != "" {
			return existingIP, nil
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

func (d *DB) findExistingAllocation(ctx context.Context, serverID int64, storedClientID, clientPubKey string) (string, error) {
	if storedClientID == "" && clientPubKey == "" {
		return "", nil
	}

	var existingIP string
	var err error
	if storedClientID != "" && clientPubKey != "" && storedClientID != clientPubKey {
		err = d.sqlDB.QueryRowContext(ctx,
			"SELECT ip FROM awg_ip_allocations WHERE server_id = ? AND status = 'allocated' AND (client_id = ? OR client_id = ?) LIMIT 1",
			serverID, storedClientID, clientPubKey,
		).Scan(&existingIP)
	} else {
		lookupID := storedClientID
		if lookupID == "" {
			lookupID = clientPubKey
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
			"DELETE FROM awg_ip_allocations WHERE server_id = ? AND (client_id = ? OR ip = ?)",
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
