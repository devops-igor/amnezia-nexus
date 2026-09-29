package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

// PeerSyncStatus is operational state, never a peer/key registry. Counts and
// errors remain available after a failed post-commit synchronization.
type PeerSyncStatus struct {
	DesiredPeers                int       `json:"desired_peers"`
	ActualPeers                 int       `json:"actual_peers"`
	InvalidRows                 int       `json:"invalid_rows"`
	SyncFailures                uint64    `json:"sync_failures"`
	AddFailures                 uint64    `json:"add_failures"`
	RemoveFailures              uint64    `json:"remove_failures"`
	UpdateFailures              uint64    `json:"update_failures"`
	LastSuccessfulReconcile     time.Time `json:"last_successful_reconcile"`
	LastError                   string    `json:"last_error,omitempty"`
	PortalConfigRestartRequired bool      `json:"portal_config_restart_required"`
}

type portalPeerDevice interface {
	Status() (clientawg.Status, error)
	AddPeer(clientawg.Peer) error
	RemovePeer(string) error
}

type peerSynchronizer struct {
	mu       sync.Mutex
	db       *database.DB
	portal   portalPeerDevice
	resolver *ingress.Resolver
	config   clientawg.Config
	subnet   string
	settings models.VPNConfig
	status   PeerSyncStatus
}

func newPeerSynchronizer(db *database.DB, portal portalPeerDevice, resolver *ingress.Resolver, cfg clientawg.Config, settings *models.VPNConfig) *peerSynchronizer {
	return &peerSynchronizer{db: db, portal: portal, resolver: resolver, config: cfg, subnet: settings.SubnetCIDR, settings: *settings}
}

func (s *peerSynchronizer) Status() PeerSyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// ValidatePortalConfig requires a controlled stop/restart for changes to
// upstream listener parameters. Ordinary LB and queue setting changes remain
// live. The guard runs before SaveVPNConfig commits, so callers cannot receive
// an apparent successful config update while the active device still uses old
// AWG parameters.
func (s *peerSynchronizer) ValidatePortalConfig(cfg *models.VPNConfig) error {
	if cfg == nil {
		return errors.New("nil VPN configuration")
	}
	p := s.settings
	if cfg.ServerPublicKey != p.ServerPublicKey || cfg.ListenPort != p.ListenPort ||
		cfg.SubnetCIDR != p.SubnetCIDR || cfg.H1.String() != p.H1.String() || cfg.H2.String() != p.H2.String() ||
		cfg.H3.String() != p.H3.String() || cfg.H4.String() != p.H4.String() || cfg.S1 != p.S1 || cfg.S2 != p.S2 ||
		cfg.S3 != p.S3 || cfg.S4 != p.S4 || cfg.HeaderProtectionKey != p.HeaderProtectionKey ||
		cfg.ContentPaddingAddition != p.ContentPaddingAddition {
		return errors.New("portal AWG parameters require stopping the upstream listener before update and restarting it afterward")
	}
	return nil
}

type desiredPeer struct {
	peer  clientawg.Peer
	owner ingress.PeerOwnership
}

func (s *peerSynchronizer) desired(ctx context.Context) (map[string]desiredPeer, int, error) {
	users, err := s.db.GetAllUsers(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read users: %w", err)
	}
	connections, err := s.db.GetAllConnections(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read connections: %w", err)
	}
	block, err := netip.ParsePrefix(s.subnet)
	if err != nil || !block.Addr().Is4() {
		return nil, 0, errors.New("invalid persisted portal subnet")
	}
	block = block.Masked()
	userByID := make(map[string]models.User, len(users))
	for _, user := range users {
		userByID[user.ID] = user
	}
	result := make(map[string]desiredPeer)
	keyCount := make(map[string]int)
	ipCount := make(map[netip.Addr]int)
	invalid := 0
	now := time.Now()
	for _, c := range connections {
		if c.ServerID != 0 || models.NormalizeProtocol(c.Protocol) != "awg" {
			continue
		}
		u, exists := userByID[c.UserID]
		if !exists || !eligiblePeer(u, c, now) {
			continue
		}
		candidate, present, valid := s.peerFromConnection(c, block)
		// An entirely blank row is normal during config issuance. A
		// half-populated row is excluded and reported for repair.
		if !present {
			continue
		}
		if !valid {
			invalid++
			continue
		}
		keyCount[c.ClientID]++
		ipCount[candidate.owner.IP]++
		result[c.ID] = candidate
	}
	byKey := make(map[string]desiredPeer, len(result))
	for _, candidate := range result {
		if keyCount[candidate.peer.PublicKey] != 1 || ipCount[candidate.owner.IP] != 1 {
			invalid++
			continue
		}
		byKey[candidate.peer.PublicKey] = candidate
	}
	return byKey, invalid, nil
}

func eligiblePeer(u models.User, c models.UserConnection, now time.Time) bool {
	return u.Enabled &&
		(u.ExpiresAt == nil || u.ExpiresAt.IsZero() || !now.After(*u.ExpiresAt)) &&
		(u.ExpirationDate == nil || u.ExpirationDate.IsZero() || !now.After(*u.ExpirationDate)) &&
		(u.TrafficLimit <= 0 || u.TrafficUsed < u.TrafficLimit) &&
		c.ClientParams["disabled"] != true && c.ClientParams["config_regeneration_required"] != true &&
		c.ClientParams["quarantined_ip_collision"] == nil
}

func (s *peerSynchronizer) peerFromConnection(c models.UserConnection, block netip.Prefix) (desiredPeer, bool, bool) {
	ipText, _ := c.ClientParams["assigned_ip"].(string)
	if c.ClientID == "" && ipText == "" {
		return desiredPeer{}, false, false
	}
	if c.ClientID == "" || ipText == "" {
		return desiredPeer{}, true, false
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil || !ip.Is4() || !block.Contains(ip) || ip == block.Addr() ||
		ip == block.Addr().Next() || isIPv4Broadcast(block, ip) {
		return desiredPeer{}, true, false
	}
	peer := clientawg.Peer{PublicKey: c.ClientID, AllowedIP: netip.PrefixFrom(ip, 32)}
	if clientawg.ValidatePeer(peer, s.config.PublicKey) != nil {
		return desiredPeer{}, true, false
	}
	return desiredPeer{peer: peer, owner: ingress.PeerOwnership{
		PeerPublicKey: c.ClientID, ConnectionID: c.ID, UserID: c.UserID, IP: ip,
	}}, true, true
}

func isIPv4Broadcast(block netip.Prefix, ip netip.Addr) bool {
	bits := block.Bits()
	if bits >= 31 {
		return true
	}
	a := block.Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	mask := uint32(1)<<(32-bits) - 1
	b := ip.As4()
	w := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return w == v|mask
}

// ReconcilePeers derives desired state afresh, removes obsolete access first,
// then installs peers. The resolver is replaced before device calls so a
// failed revocation cannot keep a plaintext route. The upstream device's
// Status is the only source used for actual peer state.
func (s *peerSynchronizer) ReconcilePeers(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	configDrift := s.portalConfigDrift(ctx)
	s.status.PortalConfigRestartRequired = configDrift != nil
	desired, invalid, err := s.desired(ctx)
	if err != nil {
		// A failed durable read cannot justify keeping stale plaintext
		// ownership, especially just after a committed revocation.
		_ = s.resolver.Replace(nil)
		return s.fail(err)
	}
	if invalid > 0 && invalid != s.status.InvalidRows {
		log.Printf("[vpn/peer-sync] excluded %d invalid or conflicting durable portal peer rows", invalid)
	}
	s.status.DesiredPeers, s.status.InvalidRows = len(desired), invalid
	owners := make([]ingress.PeerOwnership, 0, len(desired))
	for _, entry := range desired {
		owners = append(owners, entry.owner)
	}
	if err := s.resolver.Replace(owners); err != nil {
		return s.fail(err)
	}
	current, err := s.portal.Status()
	if err != nil {
		return s.fail(err)
	}
	actual := make(map[string]clientawg.PeerStatus, len(current.Peers))
	for _, peer := range current.Peers {
		actual[peer.PublicKey] = peer
	}
	s.status.ActualPeers = len(actual)
	failures := s.removeDriftedPeers(actual, desired)
	failures = append(failures, s.addMissingPeers(actual, desired)...)
	failures = append(failures, s.verifyPeers(desired)...)
	if configDrift != nil {
		failures = append(failures, configDrift)
	}
	if len(failures) != 0 {
		return s.fail(errors.Join(failures...))
	}
	s.status.LastSuccessfulReconcile = time.Now().UTC()
	s.status.LastError = ""
	return nil
}

func (s *peerSynchronizer) portalConfigDrift(ctx context.Context) error {
	current, configErr := clientawg.LoadConfig(ctx, s.db, s.config.TUN, nil)
	stored, subnetErr := s.db.GetVPNConfig(ctx)
	if configErr != nil || subnetErr != nil || stored == nil ||
		current.PrivateKey != s.config.PrivateKey || current.PublicKey != s.config.PublicKey ||
		current.ListenPort != s.config.ListenPort || current.Parameters != s.config.Parameters ||
		(stored != nil && stored.SubnetCIDR != s.subnet) {
		return errors.New("persisted portal AWG parameters differ from the running device; controlled restart required")
	}
	return nil
}

func (s *peerSynchronizer) removeDriftedPeers(actual map[string]clientawg.PeerStatus, desired map[string]desiredPeer) []error {
	var failures []error
	// Remove all stale and changed assignments before adding. This also
	// handles two peers swapping IPs without stealing either AllowedIP.
	keys := make([]string, 0, len(actual))
	for key := range actual {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		want, exists := desired[key]
		if exists && want.peer.AllowedIP == actual[key].AllowedIP {
			continue
		}
		if err := s.portal.RemovePeer(key); err != nil {
			if exists {
				s.status.UpdateFailures++
			} else {
				s.status.RemoveFailures++
			}
			failures = append(failures, fmt.Errorf("remove peer %s: %w", ingress.RedactKey(key), err))
		}
	}
	return failures
}

func (s *peerSynchronizer) addMissingPeers(actual map[string]clientawg.PeerStatus, desired map[string]desiredPeer) []error {
	var failures []error
	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		want := desired[key]
		if have, exists := actual[key]; exists && have.AllowedIP == want.peer.AllowedIP {
			continue
		}
		if err := s.portal.AddPeer(want.peer); err != nil {
			if _, exists := actual[key]; exists {
				s.status.UpdateFailures++
			} else {
				s.status.AddFailures++
			}
			failures = append(failures, fmt.Errorf("add peer %s: %w", ingress.RedactKey(key), err))
		}
	}
	return failures
}

func (s *peerSynchronizer) verifyPeers(desired map[string]desiredPeer) []error {
	after, err := s.portal.Status()
	if err != nil {
		return []error{err}
	}
	s.status.ActualPeers = len(after.Peers)
	if len(after.Peers) != len(desired) {
		return []error{errors.New("upstream peer count differs from durable state")}
	}
	for _, peer := range after.Peers {
		want, ok := desired[peer.PublicKey]
		if !ok || want.peer.AllowedIP != peer.AllowedIP {
			return []error{errors.New("upstream peer assignment differs from durable state")}
		}
	}
	return nil
}

func (s *peerSynchronizer) fail(err error) error {
	s.status.SyncFailures++
	s.status.LastError = err.Error()
	log.Printf("[vpn/peer-sync] reconciliation failed: %v", err)
	return err
}
