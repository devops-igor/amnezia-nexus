package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type legacyActiveAllocRow struct {
	id int64
	ip string
}

func (d *DB) reconcileLegacyDuplicateActiveAllocationsLocked(ctx context.Context) error {
	var tableExists int
	err := d.sqlDB.QueryRowContext(ctx, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='awg_ip_allocations'").Scan(&tableExists)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to check if awg_ip_allocations table exists: %w", err)
	}

	// a) Safely delete identical duplicate active rows (same server_id, client_id, and ip)
	_, err = d.sqlDB.ExecContext(ctx, `
		DELETE FROM awg_ip_allocations
		WHERE status = 'allocated'
		  AND id NOT IN (
		      SELECT MIN(id)
		      FROM awg_ip_allocations
		      WHERE status = 'allocated'
		      GROUP BY server_id, client_id, ip
		  )
	`)
	if err != nil {
		return fmt.Errorf("failed to delete identical duplicate active allocations: %w", err)
	}

	// b) For divergent active allocations (same server_id, client_id, but different IPs)
	type dupGroup struct {
		serverID int64
		clientID string
	}

	groupRows, err := d.sqlDB.QueryContext(ctx, `
		SELECT server_id, client_id
		FROM awg_ip_allocations
		WHERE status = 'allocated'
		GROUP BY server_id, client_id
		HAVING COUNT(*) > 1
	`)
	if err != nil {
		return fmt.Errorf("failed to query divergent active allocation groups: %w", err)
	}

	var groups []dupGroup
	for groupRows.Next() {
		var g dupGroup
		if err := groupRows.Scan(&g.serverID, &g.clientID); err != nil {
			_ = groupRows.Close()
			return fmt.Errorf("failed to scan divergent allocation group: %w", err)
		}
		groups = append(groups, g)
	}
	if err := groupRows.Err(); err != nil {
		_ = groupRows.Close()
		return fmt.Errorf("failed reading divergent allocation groups: %w", err)
	}
	_ = groupRows.Close()

	if len(groups) > 0 {
		var ucExists int
		err = d.sqlDB.QueryRowContext(ctx, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_connections'").Scan(&ucExists)
		hasUserConnections := (err == nil)

		now := time.Now().UTC().Format(time.RFC3339)
		for _, g := range groups {
			allocs, err := d.fetchActiveAllocationsForGroupLocked(ctx, g.serverID, g.clientID)
			if err != nil {
				return err
			}
			if len(allocs) <= 1 {
				continue
			}

			var retainID int64 = -1
			if hasUserConnections {
				retainID = d.findMatchingAllocIDFromUserConnectionsLocked(ctx, g.serverID, g.clientID, allocs)
			}
			if retainID == -1 {
				retainID = allocs[0].id
			}

			for _, a := range allocs {
				if a.id == retainID {
					continue
				}
				_, err = d.sqlDB.ExecContext(ctx,
					"UPDATE awg_ip_allocations SET status = 'superseded', updated_at = ? WHERE id = ?",
					now, a.id,
				)
				if err != nil {
					return fmt.Errorf("failed to mark divergent allocation %d as superseded: %w", a.id, err)
				}
			}
		}
	}

	// c) Then create the unique partial index
	_, err = d.sqlDB.ExecContext(ctx,
		"CREATE UNIQUE INDEX IF NOT EXISTS uq_awg_ip_allocations_server_client_active ON awg_ip_allocations(server_id, client_id) WHERE status = 'allocated'",
	)
	if err != nil {
		return fmt.Errorf("failed to create uq_awg_ip_allocations_server_client_active index: %w", err)
	}

	return nil
}

func (d *DB) fetchActiveAllocationsForGroupLocked(ctx context.Context, serverID int64, clientID string) ([]legacyActiveAllocRow, error) {
	rows, err := d.sqlDB.QueryContext(ctx,
		"SELECT id, ip FROM awg_ip_allocations WHERE server_id = ? AND client_id = ? AND status = 'allocated' ORDER BY id ASC",
		serverID, clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch active allocations for group (%d, %s): %w", serverID, clientID, err)
	}
	defer rows.Close()

	var allocs []legacyActiveAllocRow
	for rows.Next() {
		var a legacyActiveAllocRow
		if err := rows.Scan(&a.id, &a.ip); err != nil {
			return nil, fmt.Errorf("failed to scan active allocation: %w", err)
		}
		allocs = append(allocs, a)
	}
	return allocs, rows.Err()
}

func (d *DB) findMatchingAllocIDFromUserConnectionsLocked(ctx context.Context, serverID int64, clientID string, allocs []legacyActiveAllocRow) int64 {
	rows, err := d.sqlDB.QueryContext(ctx,
		"SELECT client_params FROM user_connections WHERE server_id = ? AND (client_id = ? OR id = ?)",
		serverID, clientID, clientID,
	)
	if err != nil {
		return -1
	}
	defer rows.Close()

	var candidateIPs []string
	for rows.Next() {
		var raw sql.NullString
		if err := rows.Scan(&raw); err != nil || !raw.Valid || strings.TrimSpace(raw.String) == "" {
			continue
		}
		var params map[string]any
		if err := json.Unmarshal([]byte(raw.String), &params); err != nil {
			continue
		}
		if ip := extractIPFromClientParams(params["assigned_ip"]); ip != "" {
			candidateIPs = append(candidateIPs, ip)
		}
		if ip := extractIPFromClientParams(params["Address"]); ip != "" {
			candidateIPs = append(candidateIPs, ip)
		}
	}

	for _, cand := range candidateIPs {
		for _, a := range allocs {
			if matchAllocationIP(a.ip, cand) {
				return a.id
			}
		}
	}

	return -1
}

func extractIPFromClientParams(val any) string {
	if val == nil {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip.String()
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

func matchAllocationIP(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA != nil && ipB != nil && ipA.Equal(ipB) {
		return true
	}
	return false
}
