package vpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// SessionsEnriched returns active sessions with identity joins and persisted
// traffic resolved from the database, plus the forwarder accountant's
// un-flushed buffered deltas on top: rx/tx are the last-flushed DB totals
// (production-live via the periodic Flush into UpdateVPNSessionTraffic)
// plus whatever RecordRx/RecordTx has buffered but not yet flushed.
// last_seen comes from the DB row only: it is the last accounted traffic
// activity visible via the accountant flush — not transport-level peer
// liveness (review-2 P2). Read-path only (issue #189).
//
// Row-set source is the DB. For the admin table that must agree with the
// active-sessions card by construction, use SessionsLive instead.
func (s *Service) SessionsEnriched(ctx context.Context) ([]models.EnrichedVPNSession, error) {
	if s.db == nil {
		return nil, errors.New("database not available")
	}

	sessions, err := s.db.GetEnrichedActiveVPNSessions(ctx)
	if err != nil {
		return nil, err
	}

	return s.applyBufferedAccountantDeltas(sessions), nil
}

// applyBufferedAccountantDeltas adds the forwarder accountant's un-flushed
// buffered rx/tx deltas onto each session's persisted counters. Exact, no
// double counting: Flush swaps each buffer to 0 when it persists the drained
// amount into the DB row. Shared by SessionsEnriched (DB truth) and
// SessionsLive (memory truth).
func (s *Service) applyBufferedAccountantDeltas(sessions []models.EnrichedVPNSession) []models.EnrichedVPNSession {
	s.mu.RLock()
	accountant := s.accountant
	s.mu.RUnlock()
	if accountant == nil {
		return sessions
	}
	for i := range sessions {
		if rx, tx := accountant.GetSessionTraffic(sessions[i].ID); rx != 0 || tx != 0 {
			sessions[i].RxBytes += rx
			sessions[i].TxBytes += tx
		}
	}
	return sessions
}

// SessionsLive is the memory-authoritative variant of SessionsEnriched
// (issue #189 improvement round): the SNAPSHOT (row membership) comes from
// the SessionManager's in-memory connected set, the same source the
// active-sessions card counts, so the card and the admin table can never
// disagree. Ghost DB rows (peers that vanished without a teardown) cannot
// appear, and a live session can never be missing from the table.
//
// Identity is resolved by PEER PUBLIC KEY (issue #213), not by vpn_sessions
// row survival: the peer key is the stable connection-config identity
// (user_connections.client_id, the same key DBAuthenticator authenticates),
// so a live session keeps its username and server identity even when its
// vpn_sessions row is displaced (e.g. the UNIQUE assigned_ip collision when
// another user's config legitimately reclaims the IP). The username comes
// from user_connections -> users, the server identity from the snapshot's
// backend tunnel -> servers. Identity fallbacks match the DB-enriched path:
// a peer key with no user_connections row (or a user row gone) renders
// 'unknown'; a tunnel missing from backend_tunnels renders
// 'Server #<tunnelID>' with server ID 0.
//
// Traffic counters and displayed last_seen are NOT memory-authoritative:
// while in-memory session liveness is kept fresh by TouchSession() in
// handleTransportData to prevent premature idle reaping (issue #294),
// displayed last_seen and rx/tx counters in SessionsLive reflect accounting
// activity telemetry persisted by TrafficAccountant.Flush rather than real-time
// per-packet transport timestamps. rx/tx/last_seen are seeded from the
// persisted vpn_sessions row by session ID (cumulative-since-connect totals,
// written incrementally by TrafficAccountant.Flush), and the accountant's
// un-flushed buffered deltas are added on top. The displayed value is
// therefore DB cumulative + buffered, continuous across flushes. A session
// with no DB row (brand-new session, displaced row, enrichment miss) keeps
// the snapshot's zeros and in-memory last_seen; the buffered deltas still
// apply to it either way.
//
// ConnectionName is the value captured at handshake from the authenticating
// user_connection; the manager always knows it, so no fallback is needed.
// Like the DB path, displayed last_seen is accounting activity telemetry
// (the last flush that moved counters), not transport-level liveness proof.
func (s *Service) SessionsLive(ctx context.Context) ([]models.EnrichedVPNSession, error) {
	if s.db == nil {
		return nil, errors.New("database not available")
	}
	if s.sessionMgr == nil {
		return nil, errors.New("session manager not initialized")
	}

	snapshot := s.sessionMgr.ListActiveSessionsSnapshot()

	out := make([]models.EnrichedVPNSession, 0, len(snapshot))
	for i := range snapshot {
		sess := snapshot[i]
		out = append(out, models.EnrichedVPNSession{
			ID:              sess.ID,
			UserID:          sess.UserID,
			Username:        "unknown",
			BackendTunnelID: sess.BackendTunnelID,
			ServerID:        0,
			ServerName:      fmt.Sprintf("Server #%d", sess.BackendTunnelID),
			PeerPublicKey:   sess.PeerPublicKey,
			AssignedIP:      sess.AssignedIP,
			ConnectedAt:     sess.ConnectedAt,
			LastSeen:        sess.LastSeen,
			RxBytes:         sess.RxBytes,
			TxBytes:         sess.TxBytes,
			Status:          sess.Status,
			ConnectionName:  sess.ConnectionName,
		})
	}
	if len(out) == 0 {
		return out, nil
	}

	// Traffic/last_seen seeding (issue #213: unchanged contract) — single
	// pass over vpn_sessions by session ID. QMARK placeholders
	// (modernc.org/sqlite).
	ids := make([]string, 0, len(out))
	seen := make(map[string]struct{}, len(out))
	for i := range out {
		if _, dup := seen[out[i].ID]; dup {
			continue
		}
		seen[out[i].ID] = struct{}{}
		ids = append(ids, out[i].ID)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	trafficQuery := `SELECT s.id,
		COALESCE(s.rx_bytes, 0) AS rx_bytes, COALESCE(s.tx_bytes, 0) AS tx_bytes,
		COALESCE(s.last_seen, '') AS last_seen
		FROM vpn_sessions s
		WHERE s.id IN (` + placeholders + `)`

	rows, err := s.db.QueryContext(ctx, trafficQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to enrich live vpn session traffic: %w", err)
	}

	type liveTraffic struct {
		rxBytes  int64
		txBytes  int64
		lastSeen time.Time
	}
	byID := make(map[string]liveTraffic, len(ids))
	for rows.Next() {
		var id string
		var traffic liveTraffic
		var lastSeenStr string
		if err := rows.Scan(&id, &traffic.rxBytes, &traffic.txBytes, &lastSeenStr); err != nil {
			_ = rows.Close() // early close; error already superseding
			return nil, fmt.Errorf("failed to scan live vpn session traffic: %w", err)
		}
		if lastSeenStr != "" {
			if ts, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
				traffic.lastSeen = ts
			}
		}
		byID[id] = traffic
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() // early close; error already superseding
		return nil, fmt.Errorf("failed to iterate live vpn session traffic: %w", err)
	}
	_ = rows.Close() // fully iterated; release before the identity queries

	// Identity resolution keyed by PEER PUBLIC KEY (issue #213): the peer
	// key is the stable connection-config identity, so the username
	// survives vpn_sessions row displacement. user_connections.client_id is
	// cryptographically unique by construction (Curve25519 public key;
	// enforced in practice by the auth path treating it as the identity
	// key, not by a schema constraint — same precedent as
	// DBAuthenticator.AuthenticatePeer). Duplicates, if data ever
	// degenerated, would map to an arbitrary-but-stable iteration winner
	// and must not fabricate traffic.
	peerIdentities, err := s.resolvePeerIdentitiesByPeerKey(ctx, out)
	if err != nil {
		return nil, err
	}

	// Server identity from the snapshot's backend tunnel (independent of
	// vpn_sessions): one small pass over backend_tunnels + servers, scoped
	// to the DISTINCT tunnels the live snapshot references (backend_tunnels
	// grows unboundedly; only snapshot tunnels are needed). A tunnel gone
	// from the table falls back to 'Server #<tunnelID>'.
	tunnelIDs := make([]int64, 0, len(out))
	tunnelSeen := make(map[int64]struct{}, len(out))
	for i := range out {
		if _, dup := tunnelSeen[out[i].BackendTunnelID]; dup {
			continue
		}
		tunnelSeen[out[i].BackendTunnelID] = struct{}{}
		tunnelIDs = append(tunnelIDs, out[i].BackendTunnelID)
	}
	byTunnel, err := s.resolveServerNamesByTunnel(ctx, tunnelIDs)
	if err != nil {
		return nil, err
	}

	// Merge. Identity (peer-key pass, authoritative) and server identity
	// (snapshot tunnel) are applied unconditionally; traffic/last_seen are
	// applied only when the vpn_sessions row exists. Misses keep the
	// fallbacks set above — same COALESCE semantics as the DB-enriched
	// read path. When the DB row exists it is authoritative for traffic
	// and last_seen: the persisted counters are cumulative (Flush adds
	// deltas via UpdateVPNSessionTraffic), and the snapshot's per-session
	// counters never move in production, so seeding from the DB is what
	// keeps the displayed total continuous across flushes. Rows without a
	// DB row keep the snapshot's zero counters and in-memory last_seen;
	// the buffered deltas are added below either way.
	for i := range out {
		if id, ok := peerIdentities[out[i].PeerPublicKey]; ok {
			out[i].Username = id.username
			out[i].ConnectionID = id.connectionID
		}
		if srv, ok := byTunnel[out[i].BackendTunnelID]; ok {
			out[i].ServerID = srv.serverID
			out[i].ServerName = srv.serverName
		}
		if traffic, ok := byID[out[i].ID]; ok {
			out[i].RxBytes = traffic.rxBytes
			out[i].TxBytes = traffic.txBytes
			if !traffic.lastSeen.IsZero() {
				out[i].LastSeen = traffic.lastSeen
			}
		}
	}

	return s.applyBufferedAccountantDeltas(out), nil
}

type livePeerIdentity struct {
	username     string
	connectionID string
}

// resolvePeerIdentitiesByPeerKey resolves session identity and connection ID by PEER PUBLIC KEY
// (issue #213, issue #447): user_connections.client_id is the stable connection-config
// identity, so the username and connection ID survive vpn_sessions row displacement.
func (s *Service) resolvePeerIdentitiesByPeerKey(ctx context.Context, sessions []models.EnrichedVPNSession) (map[string]livePeerIdentity, error) {
	peerKeys := make([]string, 0, len(sessions))
	peerSeen := make(map[string]struct{}, len(sessions))
	for i := range sessions {
		pk := sessions[i].PeerPublicKey
		if pk == "" {
			continue
		}
		if _, dup := peerSeen[pk]; dup {
			continue
		}
		peerSeen[pk] = struct{}{}
		peerKeys = append(peerKeys, pk)
	}
	identities := make(map[string]livePeerIdentity, len(peerKeys))
	if len(peerKeys) == 0 {
		return identities, nil
	}

	pkPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(peerKeys)), ",")
	pkArgs := make([]any, len(peerKeys))
	for i, pk := range peerKeys {
		pkArgs[i] = pk
	}
	identityQuery := `SELECT uc.client_id AS pk, COALESCE(u.username, 'unknown') AS username,
		COALESCE(uc.id, '') AS connection_id
		FROM user_connections uc
		LEFT JOIN users u ON u.id = uc.user_id
		WHERE uc.client_id IN (` + pkPlaceholders + `)`

	idRows, err := s.db.QueryContext(ctx, identityQuery, pkArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve live session identity by peer key: %w", err)
	}
	defer idRows.Close()
	for idRows.Next() {
		var pk, username, connID string
		if err := idRows.Scan(&pk, &username, &connID); err != nil {
			return nil, fmt.Errorf("failed to scan live session identity: %w", err)
		}
		identities[pk] = livePeerIdentity{
			username:     username,
			connectionID: connID,
		}
	}
	if err := idRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate live session identities: %w", err)
	}
	return identities, nil
}

// liveServerIdentity is one backend tunnel's resolved server identity.
type liveServerIdentity struct {
	serverID   int64
	serverName string
}

// resolveServerNamesByTunnel maps backend tunnel IDs to server identity
// (independent of vpn_sessions): backend_tunnels -> servers by tunnel ID,
// scoped to the caller-supplied DISTINCT tunnel IDs (the ones the live
// snapshot references). tunnelIDs empty -> empty map, no query. A tunnel
// missing from backend_tunnels simply has no entry; callers keep their
// fallback.
func (s *Service) resolveServerNamesByTunnel(ctx context.Context, tunnelIDs []int64) (map[int64]liveServerIdentity, error) {
	byTunnel := make(map[int64]liveServerIdentity)
	if len(tunnelIDs) == 0 {
		return byTunnel, nil
	}

	tPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(tunnelIDs)), ",")
	tArgs := make([]any, len(tunnelIDs))
	for i, id := range tunnelIDs {
		tArgs[i] = id
	}
	serverQuery := `SELECT t.id AS tunnel_id, COALESCE(t.server_id, 0) AS server_id,
		COALESCE(srv.name, 'Server #' || t.id) AS server_name
		FROM backend_tunnels t
		LEFT JOIN servers srv ON srv.id = t.server_id
		WHERE t.id IN (` + tPlaceholders + `)`

	srvRows, err := s.db.QueryContext(ctx, serverQuery, tArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve live session server identity: %w", err)
	}
	defer srvRows.Close()
	for srvRows.Next() {
		var tunnelID int64
		var srv liveServerIdentity
		if err := srvRows.Scan(&tunnelID, &srv.serverID, &srv.serverName); err != nil {
			return nil, fmt.Errorf("failed to scan live session server identity: %w", err)
		}
		byTunnel[tunnelID] = srv
	}
	if err := srvRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate live session server identities: %w", err)
	}
	return byTunnel, nil
}
