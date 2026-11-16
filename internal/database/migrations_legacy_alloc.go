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

// legacyDupGroup is one (server_id, client_id) pair with more than one active
// allocation.
type legacyDupGroup struct {
	serverID int64
	clientID string
}

type legacyActiveAllocRow struct {
	id int64
	ip string
}

// Statements executed by the legacy duplicate-allocation reconciliation. They
// are named constants so a lock-wait failure can report the exact statement that
// was blocked instead of only the surrounding step.
const (
	awgAllocTableProbeSQL = "SELECT 1 FROM sqlite_master WHERE type='table' AND name='awg_ip_allocations'"

	awgAllocDeleteDuplicatesSQL = `
		DELETE FROM awg_ip_allocations
		WHERE status = 'allocated'
		  AND id NOT IN (
		      SELECT MIN(id)
		      FROM awg_ip_allocations
		      WHERE status = 'allocated'
		      GROUP BY server_id, client_id, ip
		  )
	`

	awgAllocDivergentGroupsSQL = `
		SELECT server_id, client_id
		FROM awg_ip_allocations
		WHERE status = 'allocated'
		GROUP BY server_id, client_id
		HAVING COUNT(*) > 1
	`

	awgAllocActiveGroupSQL = "SELECT id, ip FROM awg_ip_allocations WHERE server_id = ? AND client_id = ? AND status = 'allocated' ORDER BY id ASC"

	awgUserConnectionsProbeSQL = "SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_connections'"

	awgUserConnectionsParamsSQL = "SELECT client_params FROM user_connections WHERE server_id = ? AND (client_id = ? OR id = ?)"

	awgAllocSupersedeSQL = "UPDATE awg_ip_allocations SET status = 'superseded', updated_at = ? WHERE id = ?"

	awgAllocUniqueIndexSQL = "CREATE UNIQUE INDEX IF NOT EXISTS uq_awg_ip_allocations_server_client_active ON awg_ip_allocations(server_id, client_id) WHERE status = 'allocated'"
)

func (d *DB) reconcileLegacyDuplicateActiveAllocationsLocked(ctx context.Context) error {
	var tableExists int
	err := d.sqlDB.QueryRowContext(ctx, awgAllocTableProbeSQL).Scan(&tableExists)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return schemaInitStep{"failed to check if awg_ip_allocations table exists", awgAllocTableProbeSQL}.wrap(err)
	}

	// a) Safely delete identical duplicate active rows (same server_id, client_id, and ip)
	_, err = d.sqlDB.ExecContext(ctx, awgAllocDeleteDuplicatesSQL)
	if err != nil {
		return schemaInitStep{"failed to delete identical duplicate active allocations", awgAllocDeleteDuplicatesSQL}.wrap(err)
	}

	// b) For divergent active allocations (same server_id, client_id, but different IPs)
	groupRows, err := d.sqlDB.QueryContext(ctx, awgAllocDivergentGroupsSQL)
	if err != nil {
		return schemaInitStep{"failed to query divergent active allocation groups", awgAllocDivergentGroupsSQL}.wrap(err)
	}

	var groups []legacyDupGroup
	for groupRows.Next() {
		var g legacyDupGroup
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
		hasUserConnections, err := d.userConnectionsTableExistsLocked(ctx)
		if err != nil {
			return err
		}

		now := time.Now().UTC().Format(time.RFC3339)
		for _, g := range groups {
			if err := d.supersedeDivergentAllocationsLocked(ctx, g, hasUserConnections, now); err != nil {
				return err
			}
		}
	}

	// c) Then create the unique partial index
	_, err = d.sqlDB.ExecContext(ctx, awgAllocUniqueIndexSQL)
	if err != nil {
		return schemaInitStep{"failed to create uq_awg_ip_allocations_server_client_active index", awgAllocUniqueIndexSQL}.wrap(err)
	}

	return nil
}

// supersedeDivergentAllocationsLocked retains one active allocation of the group
// and marks the others superseded. Documented fallback: with no connection
// record naming one of the allocations (no table, or no matching row), the
// earliest allocation is retained. A failed read is not that answer and is
// returned before anything is superseded.
func (d *DB) supersedeDivergentAllocationsLocked(ctx context.Context, g legacyDupGroup, hasUserConnections bool, now string) error {
	allocs, err := d.fetchActiveAllocationsForGroupLocked(ctx, g.serverID, g.clientID)
	if err != nil {
		return err
	}
	if len(allocs) <= 1 {
		return nil
	}

	retainID := allocs[0].id
	if hasUserConnections {
		matchID, found, err := d.findMatchingAllocIDFromUserConnectionsLocked(ctx, g.serverID, g.clientID, allocs)
		if err != nil {
			return err
		}
		if found {
			retainID = matchID
		}
	}

	for _, a := range allocs {
		if a.id == retainID {
			continue
		}
		if _, err := d.sqlDB.ExecContext(ctx, awgAllocSupersedeSQL, now, a.id); err != nil {
			return schemaInitStep{
				fmt.Sprintf("failed to mark divergent allocation %d as superseded", a.id),
				awgAllocSupersedeSQL,
			}.wrap(err)
		}
	}
	return nil
}

func (d *DB) fetchActiveAllocationsForGroupLocked(ctx context.Context, serverID int64, clientID string) ([]legacyActiveAllocRow, error) {
	rows, err := d.sqlDB.QueryContext(ctx, awgAllocActiveGroupSQL, serverID, clientID)
	if err != nil {
		return nil, schemaInitStep{
			fmt.Sprintf("failed to fetch active allocations for group (%d, %s)", serverID, clientID),
			awgAllocActiveGroupSQL,
		}.wrap(err)
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

// userConnectionsTableExistsLocked reports whether user_connections exists.
// Only an affirmative "no such table" answer (no row from sqlite_master) is
// absence; a failed probe is an error and is returned, because treating it as
// absence would skip the connection records and select the fallback allocation.
func (d *DB) userConnectionsTableExistsLocked(ctx context.Context) (bool, error) {
	var one int
	err := d.sqlDB.QueryRowContext(ctx, awgUserConnectionsProbeSQL).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, schemaInitStep{"failed to check if user_connections table exists", awgUserConnectionsProbeSQL}.wrap(err)
	}
	return true, nil
}

// findMatchingAllocIDFromUserConnectionsLocked looks for the active allocation
// that a connection record of this (server, client) pair names. The three
// outcomes are distinct: a read failure returns a non-nil error; a completed
// read that names no allocation returns found == false; a match returns its id
// with found == true. Callers apply the documented fallback only for found ==
// false, so a failed read can never select an allocation by accident.
//
// A row whose client_params is NULL, empty or not a JSON object was read
// successfully and carries no usable evidence, so it is skipped.
func (d *DB) findMatchingAllocIDFromUserConnectionsLocked(ctx context.Context, serverID int64, clientID string, allocs []legacyActiveAllocRow) (id int64, found bool, err error) {
	step := schemaInitStep{
		fmt.Sprintf("failed to read connection records for group (%d, %s)", serverID, clientID),
		awgUserConnectionsParamsSQL,
	}
	rows, err := d.sqlDB.QueryContext(ctx, awgUserConnectionsParamsSQL, serverID, clientID, clientID)
	if err != nil {
		return 0, false, step.wrap(err)
	}
	defer rows.Close()

	var candidateIPs []string
	for rows.Next() {
		var raw sql.NullString
		if err := rows.Scan(&raw); err != nil {
			return 0, false, step.wrap(err)
		}
		candidateIPs = append(candidateIPs, candidateIPsFromClientParams(raw)...)
	}
	// rows.Err distinguishes a result set that ended from one that was cut
	// short; only the former may be treated as the complete evidence.
	if err := rows.Err(); err != nil {
		return 0, false, step.wrap(err)
	}

	for _, cand := range candidateIPs {
		for _, a := range allocs {
			if matchAllocationIP(a.ip, cand) {
				return a.id, true, nil
			}
		}
	}
	return 0, false, nil
}

// candidateIPsFromClientParams extracts the addresses a connection record
// claims. Unusable content yields none; it is not a read failure.
func candidateIPsFromClientParams(raw sql.NullString) []string {
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil
	}
	var params map[string]any
	if err := json.Unmarshal([]byte(raw.String), &params); err != nil {
		return nil
	}
	var ips []string
	for _, key := range []string{"assigned_ip", "Address"} {
		if ip := extractIPFromClientParams(params[key]); ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
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
