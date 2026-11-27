package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
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
	// Enforce the same identity rule the client-add path applies: an explicit
	// identifier naming a different client than the public key is refused before
	// any row is read or written, so the pair can never be stored under one
	// identity while the other is silently dropped.
	if err := awg.ValidateAllocationIdentity(clientID, clientPubKey); err != nil {
		return "", err
	}
	// The row is stored under the single identity rule that release also uses
	// (public key when supplied, otherwise the explicit client identifier).
	storedClientID := awg.AllocationKey(clientID, clientPubKey)

	const maxRetries = 50
	for attempt := 0; attempt < maxRetries; attempt++ {
		// 1. Idempotency: reuse the active allocation already stored for the
		// canonical identity on this server.
		existingIP, reuse, err := d.reusableAllocation(ctx, serverID, storedClientID)
		if err != nil {
			return "", err
		}
		if reuse {
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

// reusableAllocation returns the active IP already allocated to the canonical
// identity on this server when the caller may keep it. reuse is false when there
// is no row for this identity, or when the row found is claimed by another
// identity, so the caller allocates a fresh address instead.
func (d *DB) reusableAllocation(ctx context.Context, serverID int64, storedClientID string) (string, bool, error) {
	existingIP, err := d.findExistingAllocation(ctx, serverID, storedClientID)
	if err != nil {
		return "", false, err
	}
	if existingIP == "" {
		return "", false, nil
	}
	claimed, err := d.isAllocationClaimedByOther(ctx, serverID, existingIP, storedClientID)
	if err != nil {
		return "", false, err
	}
	return existingIP, !claimed, nil
}

// findExistingAllocation returns the active IP already allocated to the canonical
// identity on this server. It searches by that single identity only: the caller
// has already refused an explicit identifier that disagrees with the public key,
// so there is exactly one identity a row could be stored under.
func (d *DB) findExistingAllocation(ctx context.Context, serverID int64, storedClientID string) (string, error) {
	if storedClientID == "" {
		return "", nil
	}

	var existingIP string
	err := d.sqlDB.QueryRowContext(ctx,
		"SELECT ip FROM awg_ip_allocations WHERE server_id = ? AND status = 'allocated' AND client_id = ? LIMIT 1",
		serverID, storedClientID,
	).Scan(&existingIP)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to check existing AWG IP allocation: %w", err)
	}
	return existingIP, nil
}

// ipLeaseOwner reports whether ip is currently allocated on this server and, if
// so, which identity holds it. It is the shared read behind both the adoption
// check and the allocation ownership check.
func (d *DB) ipLeaseOwner(ctx context.Context, serverID int64, ip string) (bool, string, error) {
	var ownerID string
	err := d.sqlDB.QueryRowContext(ctx,
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated' LIMIT 1",
		serverID, ip,
	).Scan(&ownerID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, ownerID, nil
}

// isAllocationClaimedByOther reports whether ip is held on this server by an
// identity other than the canonical one.
func (d *DB) isAllocationClaimedByOther(ctx context.Context, serverID int64, ip, storedClientID string) (bool, error) {
	found, ownerID, err := d.ipLeaseOwner(ctx, serverID, ip)
	if err != nil {
		return false, fmt.Errorf("failed to verify AWG IP ownership: %w", err)
	}
	if !found {
		return false, nil
	}
	return strings.TrimSpace(ownerID) != storedClientID, nil
}

func (d *DB) fetchAllocatedIPs(ctx context.Context, serverID int64) ([]string, error) {
	rows, err := d.sqlDB.QueryContext(ctx,
		"SELECT ip FROM awg_ip_allocations WHERE server_id = ? AND status != 'released'",
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
//
// clientID is the allocation identity produced by awg.AllocationKey (the public
// key when one exists), i.e. exactly the identity AllocateAWGClientIP stored. A
// release that matches no row leaves the address reserved, so it is reported
// rather than swallowed: a row still held under another identity is logged at
// ERROR (visible even when LOG_LEVEL=ERROR filters warnings) and an absent row --
// indistinguishable from an intentional repeat release -- at INFO. It is not an
// error because a caller releasing an already-released or mismatched pair must
// not fail the surrounding removal.
func (d *DB) ReleaseAWGClientIP(ctx context.Context, serverID int64, clientID, ip string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	clientID = strings.TrimSpace(clientID)
	ip = strings.TrimSpace(ip)
	if clientID == "" && ip == "" {
		return nil
	}

	var res sql.Result
	var err error
	if clientID != "" && ip != "" {
		res, err = d.sqlDB.ExecContext(ctx,
			"DELETE FROM awg_ip_allocations WHERE server_id = ? AND client_id = ? AND ip = ?",
			serverID, clientID, ip,
		)
	} else if ip != "" {
		res, err = d.sqlDB.ExecContext(ctx,
			"DELETE FROM awg_ip_allocations WHERE server_id = ? AND ip = ?",
			serverID, ip,
		)
	} else {
		res, err = d.sqlDB.ExecContext(ctx,
			"DELETE FROM awg_ip_allocations WHERE server_id = ? AND client_id = ?",
			serverID, clientID,
		)
	}

	if err != nil {
		return fmt.Errorf("failed to release AWG client IP: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected for AWG client IP release: %w", err)
	}
	if rows == 0 {
		d.reportReleaseMiss(ctx, serverID, clientID, ip)
	}
	return nil
}

// reportReleaseMiss reports a release whose DELETE matched no row.
//
// Two different situations produce a zero-row release and they must not be
// described as the same thing:
//   - A row for the address still exists under a different identity. That is a
//     genuine miss: the address is still reserved and the release did nothing.
//     It is reported at ERROR so it survives the documented LOG_LEVEL=ERROR
//     configuration, which is exactly the silent-reserved-address failure this
//     diagnostic exists to surface.
//   - No row exists at all. That is indistinguishable from an intentional
//     repeat release (already freed), so it is reported at INFO and never claims
//     the address is still reserved; the caller still gets the idempotent nil.
//
// The return value stays nil in both cases so a retry is never turned into a
// failure; observability, not control flow, is what changes with the level.
func (d *DB) reportReleaseMiss(ctx context.Context, serverID int64, clientID, ip string) {
	if ip == "" {
		// Released by identity only and nothing matched: no allocation row exists
		// for this client. Nothing was found, so nothing is claimed to be held.
		slog.Info("AWG IP release matched no allocation row: no allocation exists for this client identity",
			"server_id", serverID,
			"client_id", clientID,
		)
		return
	}

	var ownerID string
	err := d.sqlDB.QueryRowContext(ctx,
		"SELECT client_id FROM awg_ip_allocations WHERE server_id = ? AND ip = ? AND status = 'allocated' LIMIT 1",
		serverID, ip,
	).Scan(&ownerID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		slog.Info("AWG IP release matched no allocation row: no allocation exists for this address",
			"server_id", serverID,
			"client_id", clientID,
			"ip", ip,
		)
	case err != nil:
		slog.Warn("AWG IP release matched no allocation row and the surviving holder could not be checked",
			"server_id", serverID,
			"client_id", clientID,
			"ip", ip,
			"error", err,
		)
	default:
		slog.Error("AWG IP release matched no allocation row: the address is still held by another identity",
			"server_id", serverID,
			"client_id", clientID,
			"ip", ip,
			"owner_id", strings.TrimSpace(ownerID),
		)
	}
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
	// Same identity rule as the client-add path and AllocateAWGClientIP: refuse
	// before reading, adopting or updating anything when the pair disagrees.
	if err := awg.ValidateAllocationIdentity(clientID, clientPubKey); err != nil {
		return false, err
	}
	if ip == "" || net.ParseIP(ip) == nil {
		return false, nil
	}
	storedClientID := awg.AllocationKey(clientID, clientPubKey)
	if storedClientID == "" {
		return false, nil
	}

	found, ownerID, err := d.ipLeaseOwner(ctx, serverID, ip)
	if err != nil {
		return false, fmt.Errorf("failed to check existing IP allocation for adoption: %w", err)
	}
	if found {
		return strings.TrimSpace(ownerID) == storedClientID, nil
	}

	now := time.Now().UTC().Format(time.RFC3339)
	return d.adoptClientLease(ctx, serverID, storedClientID, ip, now)
}

// adoptClientLease upserts ip as an allocated lease for the identity and
// supersedes any other active allocation that identity holds on the server. The
// caller has already established that ip is not allocated to anyone, so any
// active row for this identity belongs to a different address.
func (d *DB) adoptClientLease(ctx context.Context, serverID int64, storedClientID, ip, now string) (bool, error) {
	if _, err := d.sqlDB.ExecContext(ctx,
		"UPDATE awg_ip_allocations SET status = 'superseded', updated_at = ? WHERE server_id = ? AND status = 'allocated' AND client_id = ?",
		now, serverID, storedClientID,
	); err != nil {
		return false, fmt.Errorf("failed to supersede existing allocation for client: %w", err)
	}

	_, err := d.sqlDB.ExecContext(ctx,
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
