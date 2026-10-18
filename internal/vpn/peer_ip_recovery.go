package vpn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ipam"
)

func quarantinePersistedAssignment(ctx context.Context, db *database.DB, claimant database.VPNClientIPAssignment, conflictingIP string, retireKeypair bool) error {
	if claimant.ClientParams == nil {
		claimant.ClientParams = make(map[string]any)
	}
	delete(claimant.ClientParams, "assigned_ip")
	if retireKeypair {
		delete(claimant.ClientParams, "client_private_key")
	}
	claimant.ClientParams["quarantined_ip_collision"] = conflictingIP
	claimant.ClientParams["config_regeneration_required"] = true
	if db != nil && claimant.ConnectionID != "" {
		updates := map[string]any{
			"client_params": claimant.ClientParams,
		}
		if retireKeypair {
			updates["client_id"] = ""
		}
		updated, err := db.UpdateConnection(ctx, claimant.ConnectionID, updates)
		if err != nil {
			return fmt.Errorf("update connection %s: %w", claimant.ConnectionID, err)
		}
		if !updated {
			return fmt.Errorf("connection %s not found for quarantine update", claimant.ConnectionID)
		}
	}
	if claimant.NeedsMigration && claimant.PeerKey != "" && db != nil {
		sess, err := db.GetVPNSessionByPeerKey(ctx, claimant.PeerKey)
		if err == nil && sess != nil {
			if err := db.DeleteVPNSession(ctx, sess.ID); err != nil {
				return fmt.Errorf("delete colliding session %s: %w", sess.ID, err)
			}
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("get vpn session for peer %s: %w", claimant.PeerKey, err)
		}
	}
	return nil
}

func sortAssignments(assignments []database.VPNClientIPAssignment) {
	// Sort assignments deterministically:
	// 1) Durable lease (!NeedsMigration) beats legacy fallback (NeedsMigration).
	// 2) Oldest connection (CreatedAt earlier).
	// 3) Stable tie-breaker (ConnectionID).
	sort.SliceStable(assignments, func(i, j int) bool {
		if assignments[i].NeedsMigration != assignments[j].NeedsMigration {
			return !assignments[i].NeedsMigration
		}
		if !assignments[i].CreatedAt.Equal(assignments[j].CreatedAt) {
			return assignments[i].CreatedAt.Before(assignments[j].CreatedAt)
		}
		return assignments[i].ConnectionID < assignments[j].ConnectionID
	})
}

func resolvePeerClaims(ctx context.Context, db *database.DB, claims []database.VPNClientIPAssignment) ([]database.VPNClientIPAssignment, error) {
	if len(claims) <= 1 {
		return claims, nil
	}
	allSameIP := true
	firstIP := claims[0].AssignedIP
	for _, c := range claims[1:] {
		if c.AssignedIP != firstIP {
			allSameIP = false
			break
		}
	}
	if allSameIP {
		return claims, nil
	}

	sortAssignments(claims)
	winnerIP := claims[0].AssignedIP
	var active []database.VPNClientIPAssignment
	for _, c := range claims {
		if c.AssignedIP == winnerIP {
			active = append(active, c)
		} else {
			if err := quarantinePersistedAssignment(ctx, db, c, c.AssignedIP, true); err != nil {
				return nil, err
			}
			log.Printf("[vpn] warning: connection %s (user %s, peer %s) has conflicting persisted address %s (resolved to %s); quarantined conflicting lease and retired keypair (requires config regeneration)", c.ConnectionID, c.UserID, c.PeerKey, c.AssignedIP, winnerIP)
		}
	}
	return active, nil
}

func reserveSinglePeerForIP(ctx context.Context, db *database.DB, ipamMgr *ipam.IPAM, peerKey string, claims []database.VPNClientIPAssignment, ip net.IP, ipStr string) error {
	// If several durable rows share this peer identity and the peer as a whole
	// must be quarantined, retire the duplicated keypair on every row. Keeping
	// the shared client_id would make post-regeneration authentication depend on
	// whichever duplicate row GetConnectionByClientID happens to return.
	retireKeypair := len(claims) > 1
	if current, ok := ipamMgr.GetAssignedIP(peerKey); ok && !current.Equal(ip) {
		for _, c := range claims {
			if err := quarantinePersistedAssignment(ctx, db, c, ipStr, retireKeypair); err != nil {
				return err
			}
			log.Printf("[vpn] warning: connection %s (user %s, peer %s) has conflicting persisted address %s (already assigned %s); quarantined conflicting lease (requires config regeneration)", c.ConnectionID, c.UserID, c.PeerKey, ipStr, current)
		}
		return nil
	}
	if err := ipamMgr.Reserve(ip, peerKey); err != nil {
		if errors.Is(err, ipam.ErrIPNotInSubnet) || errors.Is(err, ipam.ErrIPReserved) {
			return nil
		}
		if errors.Is(err, ipam.ErrIPAlreadyAllocated) {
			for _, c := range claims {
				if err := quarantinePersistedAssignment(ctx, db, c, ipStr, retireKeypair); err != nil {
					return err
				}
				log.Printf("[vpn] warning: startup IP collision on %s: connection %s (user %s, peer %s) address already allocated to another peer; quarantined conflicting lease (requires config regeneration)", ipStr, c.ConnectionID, c.UserID, c.PeerKey)
			}
			return nil
		}
		return fmt.Errorf("connection %s peer %s address %s: %w", claims[0].ConnectionID, peerKey, ipStr, err)
	}
	return nil
}

type candidatePeer struct {
	peerKey   string
	bestClaim database.VPNClientIPAssignment
	allClaims []database.VPNClientIPAssignment
}

func reconcileCollidingPeersForIP(ctx context.Context, db *database.DB, ipamMgr *ipam.IPAM, peersForIP map[string][]database.VPNClientIPAssignment, ip net.IP, ipStr string) error {
	peerKeys := make([]string, 0, len(peersForIP))
	for pKey := range peersForIP {
		peerKeys = append(peerKeys, pKey)
	}
	sort.Strings(peerKeys)

	candidates := make([]candidatePeer, 0, len(peerKeys))
	for _, pKey := range peerKeys {
		claims := peersForIP[pKey]
		sortAssignments(claims)
		candidates = append(candidates, candidatePeer{
			peerKey:   pKey,
			bestClaim: claims[0],
			allClaims: claims,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		ci := candidates[i].bestClaim
		cj := candidates[j].bestClaim
		if ci.NeedsMigration != cj.NeedsMigration {
			return !ci.NeedsMigration
		}
		if !ci.CreatedAt.Equal(cj.CreatedAt) {
			return ci.CreatedAt.Before(cj.CreatedAt)
		}
		return ci.ConnectionID < cj.ConnectionID
	})

	winner := candidates[0]
	losers := candidates[1:]

	// If reconciliation has to quarantine an entire peer identity represented
	// by multiple rows, retire that duplicated keypair on every row. A single
	// claimant may keep its keypair so explicit config regeneration can preserve
	// its peer identity while assigning a new IP.
	retireWinnerKeypair := len(winner.allClaims) > 1

	// Reserve winner in IPAM
	if current, ok := ipamMgr.GetAssignedIP(winner.peerKey); ok && !current.Equal(ip) {
		for _, c := range winner.allClaims {
			if err := quarantinePersistedAssignment(ctx, db, c, ipStr, retireWinnerKeypair); err != nil {
				return err
			}
			log.Printf("[vpn] warning: connection %s (user %s, peer %s) has conflicting persisted address %s (already assigned %s); quarantined conflicting lease (requires config regeneration)", c.ConnectionID, c.UserID, c.PeerKey, ipStr, current)
		}
	} else {
		if err := ipamMgr.Reserve(ip, winner.peerKey); err != nil {
			if !errors.Is(err, ipam.ErrIPNotInSubnet) && !errors.Is(err, ipam.ErrIPReserved) {
				if errors.Is(err, ipam.ErrIPAlreadyAllocated) {
					for _, c := range winner.allClaims {
						if err := quarantinePersistedAssignment(ctx, db, c, ipStr, retireWinnerKeypair); err != nil {
							return err
						}
						log.Printf("[vpn] warning: startup IP collision on %s: connection %s (user %s, peer %s) address already allocated to another peer; quarantined conflicting lease (requires config regeneration)", ipStr, c.ConnectionID, c.UserID, c.PeerKey)
					}
				} else {
					return fmt.Errorf("connection %s peer %s address %s: %w", winner.bestClaim.ConnectionID, winner.peerKey, ipStr, err)
				}
			}
		}
	}

	// For every loser peer: quarantine ALL claims for that peer on this IP.
	// Multiple rows sharing the losing peer must also retire their shared
	// keypair, otherwise regenerating only one row would leave another row with
	// the same client_id and make peer authentication ambiguous again.
	for _, loser := range losers {
		retireLoserKeypair := len(loser.allClaims) > 1
		for _, c := range loser.allClaims {
			if err := quarantinePersistedAssignment(ctx, db, c, ipStr, retireLoserKeypair); err != nil {
				return err
			}
			log.Printf("[vpn] warning: startup IP collision on %s: connection %s (user %s, peer %s) conflicts with owner connection %s; quarantined/cleared conflicting lease (requires config regeneration)", ipStr, c.ConnectionID, c.UserID, c.PeerKey, winner.bestClaim.ConnectionID)
		}
	}
	return nil
}

func reservePersistedClientIPs(ctx context.Context, db *database.DB, ipamMgr *ipam.IPAM) error {
	if ipamMgr == nil || db == nil {
		return nil
	}
	assignments, err := db.GetVPNClientIPAssignments(ctx)
	if err != nil {
		return err
	}

	// Group assignments by PeerKey first
	byPeer := make(map[string][]database.VPNClientIPAssignment)
	for _, a := range assignments {
		if a.PeerKey != "" && a.AssignedIP != "" {
			byPeer[a.PeerKey] = append(byPeer[a.PeerKey], a)
		}
	}

	peerKeys := make([]string, 0, len(byPeer))
	for pKey := range byPeer {
		peerKeys = append(peerKeys, pKey)
	}
	sort.Strings(peerKeys)

	// Resolve peer-level inconsistencies and collect surviving active claims
	var activeClaims []database.VPNClientIPAssignment
	for _, pKey := range peerKeys {
		resolved, err := resolvePeerClaims(ctx, db, byPeer[pKey])
		if err != nil {
			return err
		}
		activeClaims = append(activeClaims, resolved...)
	}

	// Group surviving active claims by IP -> PeerKey -> []assignments
	byIP := make(map[string]map[string][]database.VPNClientIPAssignment)
	for _, c := range activeClaims {
		if byIP[c.AssignedIP] == nil {
			byIP[c.AssignedIP] = make(map[string][]database.VPNClientIPAssignment)
		}
		byIP[c.AssignedIP][c.PeerKey] = append(byIP[c.AssignedIP][c.PeerKey], c)
	}

	ips := make([]string, 0, len(byIP))
	for ipStr := range byIP {
		ips = append(ips, ipStr)
	}
	sort.Strings(ips)

	for _, ipStr := range ips {
		peersForIP := byIP[ipStr]
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue
		}

		if len(peersForIP) == 1 {
			var singlePeerKey string
			var singleClaims []database.VPNClientIPAssignment
			for pk, cl := range peersForIP {
				singlePeerKey = pk
				singleClaims = cl
			}
			if err := reserveSinglePeerForIP(ctx, db, ipamMgr, singlePeerKey, singleClaims, ip, ipStr); err != nil {
				return err
			}
			continue
		}

		if err := reconcileCollidingPeersForIP(ctx, db, ipamMgr, peersForIP, ip, ipStr); err != nil {
			return err
		}
	}
	return nil
}
