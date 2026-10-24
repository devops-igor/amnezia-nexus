package awg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/cps"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

var (
	AWGContainerNames  = []string{"amnezia-awg2", "amnezia-awg", "amnezia-awg-legacy"}
	containerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
)

// IsValidContainerName validates a container name against strict regex:
// must start with an alphanumeric character, followed by alphanumeric, dot, underscore, or hyphen.
func IsValidContainerName(name string) bool {
	return containerNameRegex.MatchString(name)
}

// SSHProvider abstracts obtaining an SSHClient for a server.
type SSHProvider interface {
	Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error)
}

// IPAllocator defines an interface for managing atomic IP address allocations.
//
// Contract:
//   - AllocateAWGClientIP:
//   - clientID: logical identifier for the client (e.g. user ID or explicit client identifier).
//   - clientPubKey: WireGuard / AmneziaWG public key for the peer.
//   - The allocation is idempotent: if an allocation already exists for either clientID or
//     clientPubKey on serverID, the previously allocated IP is retained and returned.
//   - Concurrent allocations on the same server are synchronized and serialized to guarantee
//     zero IP collisions within the subnet.
//   - ReleaseAWGClientIP:
//   - Releases the allocation matching serverID and clientID (and/or ip).
//   - TransferAWGClientIPLease:
//   - Transfers allocation lease ownership when an existing client re-keys.
//   - AdoptAWGClientIPLease:
//   - Adopts an existing metadata IP for an upgraded client into SQLite if available.
type IPAllocator interface {
	AllocateAWGClientIP(ctx context.Context, serverID int64, clientID, clientPubKey string, usedConfigIPs []string, subnetAddr string, subnetCIDR int, gatewayIP string) (string, error)
	ReleaseAWGClientIP(ctx context.Context, serverID int64, clientID, ip string) error
	TransferAWGClientIPLease(ctx context.Context, serverID int64, newClientID, oldClientID, ip string) error
	AdoptAWGClientIPLease(ctx context.Context, serverID int64, clientID, clientPubKey, ip string) (bool, error)
}

// AWGManager implements manager.ProtocolManager for AmneziaWG.
//
//nolint:revive
type AWGManager struct {
	sshPool                 SSHProvider
	mu                      sync.Mutex
	cacheMu                 sync.RWMutex
	containerCache          map[string]containerCacheEntry
	ipAllocator             IPAllocator
	serverLocks             *ServerLockRegistry
	lockHeartbeatIntervalNs atomic.Int64
	lockHeartbeatTimeoutNs  atomic.Int64
	// tcCleaned guards the one-shot legacy tc-state sweep: server IDs that
	// have already been swept by this manager instance. Guarded by mu.
	tcCleaned   map[int64]bool
	installHook func(*AWGParams)
}

// NewAWGManager creates a new AWGManager instance.
func NewAWGManager(pool SSHProvider) *AWGManager {
	return &AWGManager{
		sshPool:        pool,
		containerCache: make(map[string]containerCacheEntry),
		tcCleaned:      make(map[int64]bool),
		serverLocks:    globalServerLocks,
	}
}

// SetIPAllocator sets the IP allocator for the AWGManager.
func (m *AWGManager) SetIPAllocator(allocator IPAllocator) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAllocator = allocator
}

func (m *AWGManager) Protocol() string {
	return "awg"
}

func (m *AWGManager) getSSHClient(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}
	if m.sshPool == nil {
		return nil, errors.New("ssh pool is not configured")
	}
	return m.sshPool.Get(ctx, server)
}

func (m *AWGManager) containerName() string {
	return "amnezia-awg2"
}

func (m *AWGManager) configPath() string {
	return "/opt/amnezia/awg/awg0.conf"
}

func (m *AWGManager) clientsTablePath() string {
	return "/opt/amnezia/awg/clientsTable"
}

func (m *AWGManager) interfaceName() string {
	return "awg0"
}

func (m *AWGManager) wgBinary() string {
	return "awg"
}

func (m *AWGManager) getServerConfigWithContainer(ctx context.Context, client ssh.SSHClient, containerNames ...string) (string, string, error) {
	names := containerNames
	if len(names) == 0 || (len(names) == 1 && names[0] == "") {
		names = m.candidateContainerNames(ctx, client)
	}
	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null || docker exec -i %s cat '/etc/amnezia/amneziawg/awg0.conf' 2>/dev/null", ssh.EscapeShellArg(name), ssh.EscapeShellArg(m.configPath()), ssh.EscapeShellArg(name))
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return out, name, nil
		}
	}
	return "", "", fmt.Errorf("failed to get server config from containers: %v", names)
}

func (m *AWGManager) getServerConfig(ctx context.Context, client ssh.SSHClient, containerNames ...string) (string, error) {
	cfg, _, err := m.getServerConfigWithContainer(ctx, client, containerNames...)
	return cfg, err
}

func (m *AWGManager) resolveContainerConfigPath(ctx context.Context, client ssh.SSHClient, containerName string) string {
	candidates := []string{m.configPath(), "/etc/amnezia/amneziawg/awg0.conf"}
	for _, p := range candidates {
		cmd := fmt.Sprintf("docker exec -i %s test -f %s", ssh.EscapeShellArg(containerName), ssh.EscapeShellArg(p))
		_, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 {
			return p
		}
	}
	cmd := fmt.Sprintf("docker exec -i %s test -d '/etc/amnezia/amneziawg'", ssh.EscapeShellArg(containerName))
	if _, _, code, err := client.RunSudoCommand(ctx, cmd); err == nil && code == 0 {
		return "/etc/amnezia/amneziawg/awg0.conf"
	}
	return m.configPath()
}

func (m *AWGManager) syncInterfaceConfig(ctx context.Context, client ssh.SSHClient, cName, cfgPath string) error {
	// Strip first, separately checked. A failing strip returns here, so syncconf
	// is never invoked and the caller restores the previous configuration.
	stripPath, err := m.stripInterfaceConfig(ctx, client, cName, cfgPath)
	if err != nil {
		return err
	}
	defer m.removeContainerFile(ctx, client, cName, stripPath)

	// syncconf takes TWO operands: the interface AND the name of a configuration
	// file. The stripped configuration therefore has to arrive as a FILENAME
	// argument, not on stdin. A shell redirect (`< path`) feeds the file on the
	// standard input stream and supplies NO second operand, so syncconf aborts
	// with "Usage: awg syncconf <interface> <configuration filename>". The strip
	// file already lives inside the container, so passing its path directly
	// needs no second copy.
	syncCmd := fmt.Sprintf("docker exec -i %s bash -c %s",
		ssh.EscapeShellArg(cName), ssh.EscapeShellArg(fmt.Sprintf("%s syncconf %s %s", m.wgBinary(), m.interfaceName(), ssh.EscapeShellArg(stripPath))))
	out, errOut, code, err := client.RunSudoCommand(ctx, syncCmd)
	if err != nil || code != 0 {
		if restErr := m.restoreInterfaceIfDown(ctx, client, cName, cfgPath); restErr != nil {
			return restErr
		}
		out, errOut, code, err = client.RunSudoCommand(ctx, syncCmd)
	}
	if err != nil || code != 0 {
		errMsg := strings.TrimSpace(errOut)
		if errMsg == "" {
			errMsg = strings.TrimSpace(out)
		}
		if err != nil {
			return fmt.Errorf("failed to sync AmneziaWG config in container %s (exit code %d): %s: %w", cName, code, errMsg, err)
		}
		return fmt.Errorf("failed to sync AmneziaWG config in container %s (exit code %d): %s", cName, code, errMsg)
	}
	return nil
}

func (m *AWGManager) restoreInterfaceIfDown(ctx context.Context, client ssh.SSHClient, cName, cfgPath string) error {
	ipCmd := fmt.Sprintf("docker exec -i %s ip link show %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(m.interfaceName()))
	ipOut, _, ipCode, ipErr := client.RunSudoCommand(ctx, ipCmd)
	isUp := ipErr == nil && ipCode == 0 && (strings.Contains(ipOut, "<UP") || strings.Contains(ipOut, ",UP") || strings.Contains(ipOut, "state UP"))
	if isUp {
		return nil
	}

	upCmd := fmt.Sprintf("docker exec -i %s awg-quick up %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(cfgPath))
	upOut, upErrOut, upCode, upErr := client.RunSudoCommand(ctx, upCmd)
	if upErr != nil || upCode != 0 {
		upErrMsg := strings.TrimSpace(upErrOut)
		if upErrMsg == "" {
			upErrMsg = strings.TrimSpace(upOut)
		} else if strings.TrimSpace(upOut) != "" {
			upErrMsg = upErrMsg + ": " + strings.TrimSpace(upOut)
		}
		if upErr != nil {
			return fmt.Errorf("failed to bring up AmneziaWG interface %s with awg-quick up in container %s (exit code %d): %s: %w",
				m.interfaceName(), cName, upCode, upErrMsg, upErr)
		}
		return fmt.Errorf("failed to bring up AmneziaWG interface %s with awg-quick up in container %s (exit code %d): %s",
			m.interfaceName(), cName, upCode, upErrMsg)
	}
	return nil
}

func (m *AWGManager) getClientsTable(ctx context.Context, client ssh.SSHClient) ([]AWGClient, error) {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return []AWGClient{}, errors.New("invalid container name")
	}
	out, errOut, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s cat %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(m.clientsTablePath())))
	if err != nil {
		return []AWGClient{}, fmt.Errorf("failed to read clientsTable: %w", err)
	}
	if code != 0 {
		if strings.Contains(errOut, "No such file") || strings.Contains(out, "No such file") {
			return []AWGClient{}, nil
		}
		return []AWGClient{}, fmt.Errorf("failed to read clientsTable (exit code %d): %s", code, strings.TrimSpace(errOut))
	}
	if strings.TrimSpace(out) == "" {
		return []AWGClient{}, nil
	}
	return ParseClientsTable(out)
}

func (m *AWGManager) saveClientsTable(ctx context.Context, client ssh.SSHClient, clients []AWGClient) error {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return errors.New("invalid container name")
	}
	jsonData, err := SerializeClientsTable(clients)
	if err != nil {
		return err
	}

	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	tmpPath := fmt.Sprintf("/tmp/_amnz_clients_%d_%x.json", time.Now().UnixNano(), randBytes)
	if err := client.UploadSudoFile(ctx, tmpPath, []byte(jsonData), 0600); err != nil {
		return err
	}
	defer func() {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("rm -f %s", ssh.EscapeShellArg(tmpPath)))
	}()

	cpCmd := fmt.Sprintf("docker cp %s %s:%s", ssh.EscapeShellArg(tmpPath), ssh.EscapeShellArg(cName), ssh.EscapeShellArg(m.clientsTablePath()))
	if _, errOut, code, err := client.RunSudoCommand(ctx, cpCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to copy clientsTable into container (code %d): %s, %w", code, errOut, err)
	}
	return nil
}

// GetClients returns all registered clients from clientsTable enriched with live transfer data.
func (m *AWGManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return nil, err
	}

	// Live transfer stats via awg show all
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	showOut, _, _, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s %s show all 2>/dev/null", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(m.wgBinary())))
	showStats := parseWGShow(showOut)

	var result []map[string]any
	knownIDs := make(map[string]bool)

	for _, c := range clients {
		knownIDs[c.ClientID] = true
		ud := c.UserData

		if stat, ok := showStats[c.ClientID]; ok {
			ud.LatestHandshake = stat.LatestHandshake
			ud.DataReceived = stat.DataReceived
			ud.DataSent = stat.DataSent
			ud.DataReceivedBytes = stat.DataReceivedBytes
			ud.DataSentBytes = stat.DataSentBytes
			if stat.AllowedIPs != "" {
				ud.AllowedIPs = stat.AllowedIPs
			}
		}

		udMap := map[string]any{
			"clientName":        ud.ClientName,
			"creationDate":      ud.CreationDate,
			"clientPrivateKey":  ud.ClientPrivateKey,
			"clientIp":          ud.ClientIP,
			"psk":               ud.PSK,
			"enabled":           ud.Enabled,
			"awg_mimicry":       ud.AWGMimicry,
			"latestHandshake":   ud.LatestHandshake,
			"dataReceived":      ud.DataReceived,
			"dataSent":          ud.DataSent,
			"dataReceivedBytes": ud.DataReceivedBytes,
			"dataSentBytes":     ud.DataSentBytes,
			"allowedIps":        ud.AllowedIPs,
			"externalClient":    ud.ExternalClient,
			"rotated_at":        ud.RotatedAt,
		}

		result = append(result, map[string]any{
			"clientId": c.ClientID,
			"userData": udMap,
		})
	}

	// Pick up external peers in awg0.conf not in clientsTable
	if confText, err := m.getServerConfig(ctx, client); err == nil {
		_, peers, _ := ParseServerConfig(confText)
		for _, p := range peers {
			if !knownIDs[p.PublicKey] {
				stat := showStats[p.PublicKey]
				result = append(result, map[string]any{
					"clientId": p.PublicKey,
					"userData": map[string]any{
						"clientName":        fmt.Sprintf("External (%s)", p.AllowedIPs),
						"clientPrivateKey":  "",
						"externalClient":    true,
						"allowedIps":        p.AllowedIPs,
						"latestHandshake":   stat.LatestHandshake,
						"dataReceived":      stat.DataReceived,
						"dataSent":          stat.DataSent,
						"dataReceivedBytes": stat.DataReceivedBytes,
						"dataSentBytes":     stat.DataSentBytes,
					},
				})
			}
		}
	}

	return result, nil
}

func resolveClientName(clientParams map[string]any) string {
	if n, ok := clientParams["name"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	if n, ok := clientParams["clientName"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	if n, ok := clientParams["client_name"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	return "client"
}

// probePeerPubKey extracts a valid caller-supplied WireGuard public key from
// clientParams (checked keys: "public_key", then "client_public_key").
// A valid key is base64 that decodes to exactly 32 bytes. Returns "" when
// absent or invalid, in which case AddClient generates a keypair as usual.
func probePeerPubKey(clientParams map[string]any) string {
	for _, k := range []string{"public_key", "client_public_key"} {
		v, ok := clientParams[k]
		if !ok || v == nil {
			continue
		}
		s, isStr := v.(string)
		if !isStr || s == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(decoded) != 32 {
			continue
		}
		return s
	}
	return ""
}

// findExistingClient locates an existing clientsTable entry matching the peer
// identity: by client ID (public key) first, then by client name. Returns the
// entry index and its current client ID.
func findExistingClient(clients []AWGClient, clientPubKey, clientName string) (int, string) {
	for i := range clients {
		if clients[i].ClientID == clientPubKey || clients[i].UserData.ClientName == clientName {
			return i, clients[i].ClientID
		}
	}
	return -1, ""
}

// upsertClientEntry updates the clientsTable entry at existingIdx in place
// (keeping IP and identity fields), or appends a new entry when idx < 0.
func upsertClientEntry(clients []AWGClient, existingIdx int, clientPubKey, clientName, clientPrivKey, psk, clientIP, mimicry string, contentPadding bool) []AWGClient {
	if existingIdx >= 0 {
		clients[existingIdx].ClientID = clientPubKey
		clients[existingIdx].UserData.ClientName = clientName
		clients[existingIdx].UserData.ClientPrivateKey = clientPrivKey
		clients[existingIdx].UserData.PSK = psk
		clients[existingIdx].UserData.Enabled = true
		clients[existingIdx].UserData.ClientIP = clientIP

		ud := &clients[existingIdx].UserData
		if ud.RekeyAfterTime == nil {
			ud.RekeyAfterTime = GenerateRekeyAfterTime()
		}
		if ud.RekeyTimeout == nil {
			ud.RekeyTimeout = GenerateRekeyTimeout()
		}
		if ud.RejectAfterTime == nil {
			ud.RejectAfterTime = GenerateRejectAfterTime()
		}
		if ud.KeepaliveTimeout == nil {
			ud.KeepaliveTimeout = GenerateKeepaliveTimeout()
		}
		if ud.MaxHandshakeAttempts == nil {
			ud.MaxHandshakeAttempts = GenerateMaxHandshakeAttempts()
		}
		if ud.PersistentKeepalive == nil {
			ud.PersistentKeepalive = GeneratePersistentKeepalive()
		}
		EnforceTimingOrdering(ud.RekeyTimeout, ud.RekeyAfterTime, ud.RejectAfterTime)

		if contentPadding && clients[existingIdx].UserData.ContentPaddingAddition == nil {
			val := "16-64"
			clients[existingIdx].UserData.ContentPaddingAddition = &val
		}

		return clients
	}

	rat, rt, rej, kt, mha, pk := GenerateClientTimingParams()
	var cpAdd *string
	if contentPadding {
		val := "16-64"
		cpAdd = &val
	}

	return append(clients, AWGClient{
		ClientID: clientPubKey,
		UserData: AWGClientUserData{
			ClientName:             clientName,
			ClientPrivateKey:       clientPrivKey,
			ClientIP:               clientIP,
			PSK:                    psk,
			Enabled:                true,
			AWGMimicry:             mimicry,
			RekeyAfterTime:         rat,
			RekeyTimeout:           rt,
			RejectAfterTime:        rej,
			KeepaliveTimeout:       kt,
			MaxHandshakeAttempts:   mha,
			PersistentKeepalive:    pk,
			ContentPaddingAddition: cpAdd,
		},
	})
}

// AddClient provisions a new client/peer in the AWG configuration.
//
// If clientParams carries a valid caller-supplied public key ("public_key" or
// "client_public_key"), that key is registered as the peer identity and no
// keypair is generated (probe peers: the prober signs with the key the portal
// already holds, so no client private key is stored or returned). Probe peers
// are registered WITHOUT a PresharedKey because the prober derives Noise keys
// with an empty PSK; a registered PSK would break the IKpsk2 key derivation.
// Registration is idempotent: an existing clientsTable entry for the same
// identity (by client ID or client name) is updated in place, keeping its IP,
// instead of appending a duplicate [Peer], which amneziawg rejects.
func (m *AWGManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (res map[string]any, err error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return nil, lockErr
	}
	defer unlockRemote()

	clientName := resolveClientName(clientParams)

	// Name-based probe detection (R2): a legacy "Health Probe" entry may exist
	// with a server PSK from the old name-only registration path. Treat the
	// name as probe identity so the upsert drops the PresharedKey line and
	// forces psk="" — keeping the peer on the PSK-less identity both probers use.
	clientNameIsProbe := strings.EqualFold(strings.TrimSpace(clientName), "Health Probe")

	clientPubKey := probePeerPubKey(clientParams)
	isProbePeer := clientPubKey != "" || clientNameIsProbe
	clientPrivKey, clientPubKey, err := resolveClientKeys(clientParams)
	if err != nil {
		return nil, err
	}

	// Read server config
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return nil, err
	}

	usedIPs := GetUsedIPsFromConfig(confText)
	serverParams, remotePeers, _ := ParseServerConfig(confText)
	serverPubKey, err := m.getServerPublicKeyRequired(ctx, server)
	if err != nil {
		return nil, err
	}

	initialConfText := confText

	// Idempotency: reuse the existing entry (and its IP) when this identity is
	// already registered instead of appending a duplicate peer.
	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return nil, err
	}
	initialClients := append([]AWGClient(nil), clients...)
	existingIdx, existingPubKey := findExistingClient(clients, clientPubKey, clientName)
	isUpsert := existingIdx >= 0
	var previousClient *AWGClient
	var previousPeerSection string
	if isUpsert {
		cCopy := clients[existingIdx]
		previousClient = &cCopy
		targetKey := existingPubKey
		if targetKey == "" {
			targetKey = clients[existingIdx].ClientID
		}
		targetIP := clients[existingIdx].UserData.ClientIP
		previousPeerSection = extractPeerSection(confText, targetKey, targetIP)
	}

	effectiveClientID := resolveEffectiveClientID(clientParams, clientPubKey)

	clientIP, newlyAllocated, rekeyed, previousOwner, rekeyedIP, err := m.obtainClientIP(
		ctx, serverID, clientParams, clients, existingIdx, clientPubKey, usedIPs, serverParams, remotePeers,
	)
	if err != nil {
		return nil, err
	}

	diskWritten := false
	remoteCommitted := false
	var classification configMutationClassification
	defer func() {
		if err != nil {
			m.rollbackAddClient(ctx, client, serverID, effectiveClientID, clientPubKey, clientIP, previousOwner, rekeyedIP, initialConfText, initialClients, rekeyed, newlyAllocated, diskWritten, remoteCommitted)
		}
	}()

	// Normal clients get the server's PresharedKey (read fresh each call, as
	// before). Probe peers force psk="": the prober derives IKpsk2 keys with an
	// empty PSK, so the peer must be registered without one (R2).
	var psk string
	if !isProbePeer {
		psk, _ = m.GetServerPSK(ctx, server)
	}

	allowedIPs := resolveAllowedIPs(clientParams)
	peerSection := peerSectionFor(isProbePeer, clientPubKey, psk, clientIP, allowedIPs)

	if classification, err = m.commitPeerConfigWithCAS(ctx, client, confText, peerSection, clientPubKey, clientName, existingPubKey); err != nil {
		// The historical multi-assign populated diskWritten even when the
		// commit returned an error (disk-written failure classes), and the
		// deferred rollback below depends on that bookkeeping. Mirror it on
		// the error path too.
		diskWritten = classification.asLegacyWriteSucceeded()
		return nil, err
	}
	// AddClient's rollback bookkeeping keeps its historical meaning (rollback
	// only when the disk write is KNOWN to have persisted); the ambiguous-class
	// routing decision is R3-2's scope.
	diskWritten = classification.asLegacyWriteSucceeded()
	remoteCommitted = true

	mimicry := resolveMimicry(clientParams)
	cpOn, _ := parseBoolParam(clientParams["awg_content_padding"])

	// Fresh read-and-upsert for clientsTable to avoid lost updates
	clients, err = m.getClientsTable(ctx, client)
	if err != nil {
		return nil, err
	}
	existingIdx, _ = findExistingClient(clients, clientPubKey, clientName)
	clients = upsertClientEntry(clients, existingIdx, clientPubKey, clientName, clientPrivKey, psk, clientIP, mimicry, cpOn)
	if err = m.saveClientsTable(ctx, client, clients); err != nil {
		return nil, fmt.Errorf("failed to save clients table: %w", err)
	}

	if isProbePeer {
		// Probe peers need no client config, connection kit, or TC limits:
		// nothing consumes a private key that does not exist. Probe peers only
		// terminate keepalive probes on awg0 and never route or masquerade
		// client traffic, so ensureBackendNATRule is skipped.
		return map[string]any{
			"client_id":             clientPubKey,
			"client_name":           clientName,
			"client_ip":             clientIP,
			"client_pub_key":        clientPubKey,
			"existing_pub_key":      existingPubKey,
			"is_upsert":             isUpsert,
			"previous_client":       previousClient,
			"previous_peer_section": previousPeerSection,
			"initial_conf":          initialConfText,
			"initial_clients":       initialClients,
			"rekeyed":               rekeyed,
			"previous_owner":        previousOwner,
			"rekeyed_ip":            rekeyedIP,
			"newly_allocated":       newlyAllocated,
			"effective_client_id":   effectiveClientID,
		}, nil
	}

	// Live remediation (issues #27, #36): ensure the return route, NAT masquerade,
	// and FORWARD rules exist so portal data-plane traffic (non-local source
	// subnets like 10.100.0.0/16) is forwarded and masqueraded. This covers
	// backends provisioned with the old subnet-scoped start.sh without
	// restarting or re-creating the container. Fail loudly: without the rules,
	// all load-balanced client traffic is dropped upstream.
	if err = m.ensureBackendNATRule(ctx, client); err != nil {
		err = fmt.Errorf("failed to ensure backend NAT rules: %w", err)
		return nil, err
	}

	// Render client config
	clientConfig := m.buildClientConfig(ctx, client, server, serverParams, clientPrivKey, clientIP, serverPubKey, psk, mimicry, clientPubKey, clients)

	return map[string]any{
		"client_id":             clientPubKey,
		"client_name":           clientName,
		"client_ip":             clientIP,
		"client_pub_key":        clientPubKey,
		"existing_pub_key":      existingPubKey,
		"config":                clientConfig,
		"awg_mimicry":           mimicry,
		"is_upsert":             isUpsert,
		"previous_client":       previousClient,
		"previous_peer_section": previousPeerSection,
		"initial_conf":          initialConfText,
		"initial_clients":       initialClients,
		"rekeyed":               rekeyed,
		"previous_owner":        previousOwner,
		"rekeyed_ip":            rekeyedIP,
		"newly_allocated":       newlyAllocated,
		"effective_client_id":   effectiveClientID,
	}, nil
}

func (m *AWGManager) commitPeerConfigWithCAS(
	ctx context.Context,
	client ssh.SSHClient,
	initialConf, peerSection, clientPubKey, clientName, existingPubKey string,
) (configMutationClassification, error) {
	confText := initialConf
	currExistingPubKey := existingPubKey

	for attempt := 0; attempt < 5; attempt++ {
		freshConf, err := m.getServerConfig(ctx, client)
		if err != nil {
			return configMutationNotAttempted, fmt.Errorf("failed to fetch remote config for CAS check: %w", err)
		}
		if freshConf != confText {
			confText = freshConf
			clients, err := m.getClientsTable(ctx, client)
			if err != nil {
				return configMutationNotAttempted, fmt.Errorf("failed to fetch clientsTable for CAS retry: %w", err)
			}
			_, currExistingPubKey = findExistingClient(clients, clientPubKey, clientName)
			continue
		}

		removePubKeys := peerRemovalKeys(currExistingPubKey, clientPubKey)
		newConfig, err := upsertPeerInConfig(confText, peerSection, removePubKeys...)
		if err != nil {
			return configMutationNotAttempted, fmt.Errorf("failed to upsert peer in config: %w", err)
		}
		return m.saveServerConfigTracked(ctx, client, newConfig, false)
	}

	return configMutationNotAttempted, errors.New("failed to commit remote config: CAS retry limit exceeded due to concurrent modifications")
}

func (m *AWGManager) removePeerFromRemote(ctx context.Context, client ssh.SSHClient, pubKey, ip string) error {
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to get server config for peer removal: %w", err)
	}

	newConfig := removePeerFromConfig(confText, pubKey, ip)
	if err := m.saveServerConfigPreservingParams(ctx, client, newConfig); err != nil {
		return fmt.Errorf("failed to save config during peer removal: %w", err)
	}

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to get clients table during peer removal: %w", err)
	}
	if len(clients) > 0 {
		var updated []AWGClient
		for _, c := range clients {
			if (pubKey != "" && c.ClientID == pubKey) || (ip != "" && c.UserData.ClientIP == ip) {
				continue
			}
			updated = append(updated, c)
		}
		if err := m.saveClientsTable(ctx, client, updated); err != nil {
			return fmt.Errorf("failed to save clients table during peer removal: %w", err)
		}
	}

	return nil
}

func (m *AWGManager) restorePreviousPeer(ctx context.Context, client ssh.SSHClient, initialConfText string, initialClients []AWGClient) (bool, error) {
	if err := m.saveServerConfigPreservingParams(ctx, client, initialConfText); err != nil {
		return false, fmt.Errorf("failed to restore initial server config: %w", err)
	}
	if err := m.saveClientsTable(ctx, client, initialClients); err != nil {
		return true, fmt.Errorf("failed to restore initial clients table: %w", err)
	}
	return true, nil
}

func (m *AWGManager) rollbackAddClient(
	ctx context.Context,
	client ssh.SSHClient,
	serverID int64,
	effectiveClientID, clientPubKey, clientIP, previousOwner, rekeyedIP, initialConfText string,
	initialClients []AWGClient,
	rekeyed, newlyAllocated, diskWritten, remoteCommitted bool,
) {
	if rekeyed && m.ipAllocator != nil {
		if !diskWritten {
			if transErr := m.ipAllocator.TransferAWGClientIPLease(ctx, serverID, previousOwner, effectiveClientID, rekeyedIP); transErr != nil {
				slog.Error("failed to revert AWG client IP lease to previous owner during re-key rollback without disk write",
					"server_id", serverID,
					"previous_owner", previousOwner,
					"new_client_id", effectiveClientID,
					"ip", rekeyedIP,
					"error", transErr,
				)
			}
		} else {
			configRestored, restoreErr := m.restorePreviousPeer(ctx, client, initialConfText, initialClients)
			if !configRestored {
				slog.Error("failed to restore previous peer config on remote server during re-key rollback; retaining new key lease in DB to prevent zombie IP collision",
					"server_id", serverID,
					"previous_owner", previousOwner,
					"new_client_id", effectiveClientID,
					"ip", rekeyedIP,
					"error", restoreErr,
				)
			} else {
				if restoreErr != nil {
					slog.Warn("remote peer config restored to previous owner but clients table restore failed during re-key rollback",
						"server_id", serverID,
						"previous_owner", previousOwner,
						"new_client_id", effectiveClientID,
						"ip", rekeyedIP,
						"error", restoreErr,
					)
				}
				if relErr := m.ipAllocator.TransferAWGClientIPLease(ctx, serverID, previousOwner, effectiveClientID, rekeyedIP); relErr != nil {
					slog.Error("failed to revert AWG client IP lease to previous owner after remote restore",
						"server_id", serverID,
						"previous_owner", previousOwner,
						"new_client_id", effectiveClientID,
						"ip", rekeyedIP,
						"error", relErr,
					)
				}
			}
		}
	}
	if newlyAllocated && !rekeyed {
		m.rollbackAllocatedPeer(ctx, client, serverID, effectiveClientID, clientPubKey, clientIP, diskWritten, remoteCommitted)
	}
}

func (m *AWGManager) rollbackAllocatedPeer(
	ctx context.Context,
	client ssh.SSHClient,
	serverID int64,
	effectiveClientID, clientPubKey, clientIP string,
	diskWritten, remoteCommitted bool,
) {
	if m.ipAllocator == nil {
		return
	}
	if !diskWritten && !remoteCommitted {
		if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, effectiveClientID, clientIP); relErr != nil {
			slog.Warn("failed to release AWG client IP", "server_id", serverID, "client_id", effectiveClientID, "ip", clientIP, "error", relErr)
		}
		return
	}

	// Either diskWritten or remoteCommitted is true:
	// A peer entry was written to remote disk (and possibly applied to the interface).
	// Rollback MUST attempt remote disk cleanup by removing the peer from the remote config on disk.
	if err := m.removePeerFromRemote(ctx, client, clientPubKey, clientIP); err != nil {
		slog.Error("failed to remove peer from remote server during rollback; retaining IP allocation to prevent zombie IP collision",
			"server_id", serverID,
			"client_id", effectiveClientID,
			"ip", clientIP,
			"error", err,
		)
		return
	}

	if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, effectiveClientID, clientIP); relErr != nil {
		slog.Warn("failed to release AWG client IP after remote removal", "server_id", serverID, "client_id", effectiveClientID, "ip", clientIP, "error", relErr)
	}
}

func parseServerSubnetParams(serverParams map[string]string) (string, int, string) {
	subnetAddr := AWGDefaults["subnet_address"]
	subnetCIDR, _ := strconv.Atoi(AWGDefaults["subnet_cidr"])
	gatewayIP := AWGDefaults["subnet_ip"]

	if serverParams == nil {
		return subnetAddr, subnetCIDR, gatewayIP
	}

	addrVal := ""
	if v, ok := serverParams["Address"]; ok && strings.TrimSpace(v) != "" {
		addrVal = strings.TrimSpace(v)
	} else if v, ok := serverParams["address"]; ok && strings.TrimSpace(v) != "" {
		addrVal = strings.TrimSpace(v)
	}

	if addrVal != "" {
		ip, ipNet, err := net.ParseCIDR(addrVal)
		if err == nil && ip != nil && ipNet != nil {
			if ip4 := ip.To4(); ip4 != nil {
				gatewayIP = ip4.String()
				subnetAddr = ipNet.IP.To4().String()
				ones, _ := ipNet.Mask.Size()
				subnetCIDR = ones
			}
		}
	}

	return subnetAddr, subnetCIDR, gatewayIP
}

func conflictingRemotePeer(remotePeers []AWGPeer, targetIPStr, allowedKey string) *AWGPeer {
	targetIP := net.ParseIP(strings.TrimSpace(targetIPStr))
	if targetIP == nil {
		return nil
	}
	for _, peer := range remotePeers {
		if peer.PublicKey != allowedKey && peerHasIP(peer, targetIP) {
			p := peer
			return &p
		}
	}
	return nil
}

func peerHasIP(peer AWGPeer, targetIP net.IP) bool {
	if targetIP == nil {
		return false
	}
	for _, part := range strings.Split(peer.AllowedIPs, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parsedIP, _, err := net.ParseCIDR(part)
		if err != nil {
			parsedIP = net.ParseIP(part)
		}
		if parsedIP != nil && parsedIP.Equal(targetIP) {
			return true
		}
	}
	return false
}

const maxConflictRetries = 10

func (m *AWGManager) allocateNonConflictingIP(
	ctx context.Context,
	serverID int64,
	effectiveClientID, clientPubKey string,
	usedIPs []string,
	subnetAddr string,
	subnetCIDR int,
	gatewayIP string,
	remotePeers []AWGPeer,
) (string, error) {
	for attempt := 0; attempt < maxConflictRetries; attempt++ {
		allocatedIP, err := m.ipAllocator.AllocateAWGClientIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP)
		if err != nil {
			return "", err
		}
		if conflictingRemotePeer(remotePeers, allocatedIP, clientPubKey) == nil {
			return allocatedIP, nil
		}
		slog.Warn("allocated IP conflicts with active remote peer; releasing stale lease and re-allocating",
			"server_id", serverID,
			"client_id", effectiveClientID,
			"ip", allocatedIP,
			"attempt", attempt+1,
		)
		if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, effectiveClientID, allocatedIP); relErr != nil {
			slog.Warn("failed to release conflicting allocated IP lease",
				"server_id", serverID,
				"client_id", effectiveClientID,
				"ip", allocatedIP,
				"error", relErr,
			)
			return "", fmt.Errorf("failed to release conflicting allocated IP lease for client %s (IP %s): %w", effectiveClientID, allocatedIP, relErr)
		}
		usedIPs = append(usedIPs, allocatedIP)
	}
	return "", fmt.Errorf("failed to allocate non-conflicting IP on server %d after %d attempts: all candidates conflict with remote peers", serverID, maxConflictRetries)
}

func (m *AWGManager) revertRekeyedLease(ctx context.Context, serverID int64, previousOwner, newClientID, ip, reason string) {
	if compErr := m.ipAllocator.TransferAWGClientIPLease(ctx, serverID, previousOwner, newClientID, ip); compErr != nil {
		slog.Error("failed to revert AWG client IP lease to previous owner during "+reason,
			"server_id", serverID,
			"previous_owner", previousOwner,
			"new_client_id", newClientID,
			"ip", ip,
			"error", compErr,
		)
	}
}

func (m *AWGManager) obtainExistingClientIPWithAllocator(
	ctx context.Context,
	serverID int64,
	effectiveClientID, clientPubKey string,
	existingClient AWGClient,
	usedIPs []string,
	subnetAddr string,
	subnetCIDR int,
	gatewayIP string,
	remotePeers []AWGPeer,
) (string, bool, bool, string, string, error) {
	existingIP := existingClient.UserData.ClientIP
	existingPubKey := existingClient.ClientID

	rekeyed := false
	previousOwner := ""
	rekeyedIP := ""
	transferSucceeded := false

	// Re-keying ownership transfer: if existing peer is replacing K1 with K2
	if existingPubKey != "" && clientPubKey != "" && existingPubKey != clientPubKey {
		rekeyed = true
		previousOwner = existingPubKey
		rekeyedIP = existingIP
		if transErr := m.ipAllocator.TransferAWGClientIPLease(ctx, serverID, effectiveClientID, existingPubKey, existingIP); transErr == nil {
			transferSucceeded = true
		} else {
			// Existing client had no lease row in DB, attempt to adopt existingIP for new key
			if conflictingRemotePeer(remotePeers, existingIP, existingPubKey) != nil {
				allocatedIP, allocErr := m.allocateNonConflictingIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers)
				if allocErr != nil {
					return "", false, false, "", "", allocErr
				}
				return allocatedIP, true, false, "", "", nil
			}
			if _, adoptErr := m.ipAllocator.AdoptAWGClientIPLease(ctx, serverID, effectiveClientID, clientPubKey, existingIP); adoptErr != nil {
				return "", false, false, "", "", fmt.Errorf("failed to adopt AWG client IP lease during re-keying: %w", adoptErr)
			}
		}
	} else {
		// Existing client without lease row in DB: adopt existingIP if not claimed
		if conflictingRemotePeer(remotePeers, existingIP, clientPubKey) != nil {
			allocatedIP, allocErr := m.allocateNonConflictingIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers)
			if allocErr != nil {
				return "", false, false, "", "", allocErr
			}
			return allocatedIP, true, false, "", "", nil
		}
		if _, adoptErr := m.ipAllocator.AdoptAWGClientIPLease(ctx, serverID, effectiveClientID, clientPubKey, existingIP); adoptErr != nil {
			return "", false, false, "", "", fmt.Errorf("failed to adopt AWG client IP lease: %w", adoptErr)
		}
	}

	allocatedIP, allocErr := m.ipAllocator.AllocateAWGClientIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP)
	if allocErr != nil {
		if transferSucceeded {
			m.revertRekeyedLease(ctx, serverID, previousOwner, effectiveClientID, rekeyedIP, "allocation failure compensation")
		}
		return "", false, false, "", "", allocErr
	}

	allowedKey := clientPubKey
	if rekeyed && previousOwner != "" {
		allowedKey = previousOwner
	}
	if conflictingRemotePeer(remotePeers, allocatedIP, allowedKey) != nil {
		slog.Warn("allocated IP conflicts with active remote peer; releasing stale lease and re-allocating",
			"server_id", serverID,
			"client_id", effectiveClientID,
			"ip", allocatedIP,
		)
		if transferSucceeded {
			m.revertRekeyedLease(ctx, serverID, previousOwner, effectiveClientID, rekeyedIP, "conflicting allocation compensation")
		}
		if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, effectiveClientID, allocatedIP); relErr != nil {
			slog.Warn("failed to release conflicting allocated IP lease",
				"server_id", serverID,
				"client_id", effectiveClientID,
				"ip", allocatedIP,
				"error", relErr,
			)
			return "", false, false, "", "", fmt.Errorf("failed to release conflicting allocated IP lease for client %s (IP %s): %w", effectiveClientID, allocatedIP, relErr)
		}
		usedIPs = append(usedIPs, allocatedIP)
		allocatedIP, allocErr = m.allocateNonConflictingIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers)
		if allocErr != nil {
			return "", false, false, "", "", allocErr
		}
	}
	return allocatedIP, allocatedIP != existingIP, rekeyed, previousOwner, rekeyedIP, nil
}

func (m *AWGManager) obtainClientIP(
	ctx context.Context,
	serverID int64,
	clientParams map[string]any,
	clients []AWGClient,
	existingIdx int,
	clientPubKey string,
	usedIPs []string,
	serverParams map[string]string,
	remotePeers []AWGPeer,
) (string, bool, bool, string, string, error) {
	subnetAddr, subnetCIDR, gatewayIP := parseServerSubnetParams(serverParams)
	effectiveClientID := resolveEffectiveClientID(clientParams, clientPubKey)

	if m.ipAllocator != nil {
		if existingIdx >= 0 && clients[existingIdx].UserData.ClientIP != "" {
			return m.obtainExistingClientIPWithAllocator(
				ctx, serverID, effectiveClientID, clientPubKey, clients[existingIdx],
				usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers,
			)
		}

		allocatedIP, allocErr := m.allocateNonConflictingIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers)
		if allocErr != nil {
			return "", false, false, "", "", allocErr
		}
		return allocatedIP, true, false, "", "", nil
	}

	if existingIdx >= 0 && clients[existingIdx].UserData.ClientIP != "" {
		return clients[existingIdx].UserData.ClientIP, false, false, "", "", nil
	}
	resolvedIP, resErr := resolveClientIP(clients, existingIdx, usedIPs, subnetAddr, subnetCIDR, gatewayIP)
	if resErr != nil {
		return "", false, false, "", "", resErr
	}
	return resolvedIP, false, false, "", "", nil
}

func resolveEffectiveClientID(clientParams map[string]any, clientPubKey string) string {
	if cid, ok := clientParams["client_id"].(string); ok && strings.TrimSpace(cid) != "" {
		return strings.TrimSpace(cid)
	}
	return clientPubKey
}

func (m *AWGManager) getServerPublicKeyRequired(ctx context.Context, server *models.Server) (string, error) {
	serverPubKey, err := m.GetServerPublicKey(ctx, server)
	if err != nil {
		return "", fmt.Errorf("failed to get AmneziaWG server public key: %w", err)
	}
	if serverPubKey == "" {
		return "", errors.New("AmneziaWG server public key is empty")
	}
	return serverPubKey, nil
}

func resolveAllowedIPs(clientParams map[string]any) string {
	if aip, ok := clientParams["allowed_ips"]; ok && aip != nil {
		return fmt.Sprint(aip)
	}
	return ""
}

func resolveMimicry(clientParams map[string]any) string {
	if v, ok := clientParams["awg_mimicry"]; ok && fmt.Sprint(v) != "" {
		return fmt.Sprint(v)
	}
	return "auto"
}

func peerRemovalKeys(existingPubKey, clientPubKey string) []string {
	if existingPubKey != "" && existingPubKey != clientPubKey {
		return []string{existingPubKey}
	}
	return nil
}

func resolveClientKeys(clientParams map[string]any) (string, string, error) {
	clientPubKey := probePeerPubKey(clientParams)
	if clientPubKey != "" {
		return "", clientPubKey, nil
	}
	clientPrivKey, clientPubKey, err := GenerateWGKeypair()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate client keypair: %w", err)
	}
	return clientPrivKey, clientPubKey, nil
}

func resolveClientIP(clients []AWGClient, existingIdx int, usedIPs []string, subnetAddr string, subnetCIDR int, gatewayIP string) (string, error) {
	if existingIdx >= 0 && clients[existingIdx].UserData.ClientIP != "" {
		return clients[existingIdx].UserData.ClientIP, nil
	}
	return GetNextIP(usedIPs, subnetAddr, subnetCIDR, gatewayIP)
}

func (m *AWGManager) buildClientConfig(ctx context.Context, client ssh.SSHClient, server *models.Server, serverParams map[string]string, clientPrivKey, clientIP, serverPubKey, psk, mimicry, clientPubKey string, clients []AWGClient) string {
	parsedParams := AWGParamsFromMap(convertStringMapToAny(serverParams))
	if mimicry != "" {
		if mp, err := cps.GenerateMimicryPackets(ctx, mimicry, "", client); err == nil {
			parsedParams.I1 = mp["i1"]
			parsedParams.I2 = mp["i2"]
			parsedParams.I3 = mp["i3"]
			parsedParams.I4 = mp["i4"]
			parsedParams.I5 = mp["i5"]
		}
	}

	port := serverParams["port"]
	if port == "" {
		port = AWGDefaults["port"]
	}
	endpoint := fmt.Sprintf("%s:%s", server.Host, port)
	var ud *AWGClientUserData
	for i := range clients {
		if clients[i].ClientID == clientPubKey {
			ud = &clients[i].UserData
			break
		}
	}
	clientConfig := RenderClientConfig(clientPrivKey, clientIP, serverPubKey, psk, endpoint, AWGDefaults["dns1"], AWGDefaults["dns2"], parsedParams.MTU, parsedParams, ud)
	return clientConfig
}

func convertStringMapToAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// RollbackAddClient rolls back an AddClient operation. If the operation was an upsert
// (modifying an existing peer), the prior peer configuration and clientsTable entry are restored
// on the fresh server state without overwriting concurrent modifications.
// Otherwise, the newly added peer is removed from the fresh server state.
func (m *AWGManager) RollbackAddClient(ctx context.Context, server *models.Server, addClientResult map[string]any) error {
	if addClientResult == nil {
		return errors.New("addClientResult is nil")
	}

	isUpsert, _ := addClientResult["is_upsert"].(bool)
	clientID, _ := addClientResult["client_id"].(string)
	if clientID == "" {
		clientID, _ = addClientResult["clientId"].(string)
	}
	clientPubKey, _ := addClientResult["client_pub_key"].(string)
	if clientPubKey == "" {
		clientPubKey = clientID
	}
	clientName, _ := addClientResult["client_name"].(string)
	clientIP, _ := addClientResult["client_ip"].(string)

	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return lockErr
	}
	defer unlockRemote()

	var rollbackErrs []error
	superseded, err := m.rollbackClientsTableSurgically(ctx, client, isUpsert, clientID, clientPubKey, clientName, clientIP, addClientResult)
	if err != nil {
		rollbackErrs = append(rollbackErrs, err)
	}
	if err := m.rollbackServerConfigSurgically(ctx, client, isUpsert, superseded, clientPubKey, clientIP, addClientResult); err != nil {
		rollbackErrs = append(rollbackErrs, err)
	}
	m.rollbackIPLease(ctx, serverID, clientID, clientIP, addClientResult, superseded)

	return errors.Join(rollbackErrs...)
}

func (m *AWGManager) rollbackClientsTableSurgically(ctx context.Context, client ssh.SSHClient, isUpsert bool, clientID, clientPubKey, clientName, clientIP string, addClientResult map[string]any) (bool, error) {
	freshClients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return false, fmt.Errorf("failed to fetch fresh clientsTable during rollback: %w", err)
	}

	superseded := isClientSuperseded(freshClients, clientName, clientPubKey, clientID)

	var updatedClients []AWGClient
	if isUpsert && !superseded {
		previousClient := extractPreviousClient(addClientResult)
		updatedClients = buildRestoredUpsertClients(freshClients, previousClient, clientPubKey, clientID)
	} else {
		filterIP := !isUpsert && !superseded
		updatedClients = buildFilteredNonUpsertClients(freshClients, clientPubKey, clientID, clientIP, filterIP)
	}

	if err := m.saveClientsTable(ctx, client, updatedClients); err != nil {
		return superseded, fmt.Errorf("failed to save clientsTable during rollback: %w", err)
	}
	return superseded, nil
}

func isClientSuperseded(freshClients []AWGClient, clientName, clientPubKey, clientID string) bool {
	if clientName == "" {
		return false
	}
	for _, c := range freshClients {
		if c.UserData.ClientName == clientName {
			if (clientPubKey != "" && c.ClientID != clientPubKey) && (clientID != "" && c.ClientID != clientID) {
				slog.Info("AWG rollback detected superseding peer; abstaining from restoring previous client",
					"client_name", clientName,
					"rollback_client_id", clientPubKey,
					"current_client_id", c.ClientID,
				)
				return true
			}
		}
	}
	return false
}

func extractPreviousClient(addClientResult map[string]any) *AWGClient {
	if prev, ok := addClientResult["previous_client"].(*AWGClient); ok && prev != nil {
		return prev
	}
	if pcVal, ok := addClientResult["previous_client"].(AWGClient); ok {
		return &pcVal
	}
	return nil
}

func buildRestoredUpsertClients(freshClients []AWGClient, previousClient *AWGClient, clientPubKey, clientID string) []AWGClient {
	if previousClient == nil {
		return freshClients
	}
	var updatedClients []AWGClient
	replaced := false
	for _, c := range freshClients {
		if (clientPubKey != "" && c.ClientID == clientPubKey) || (clientID != "" && c.ClientID == clientID) {
			updatedClients = append(updatedClients, *previousClient)
			replaced = true
		} else {
			updatedClients = append(updatedClients, c)
		}
	}
	if !replaced {
		return freshClients
	}
	return updatedClients
}

func buildFilteredNonUpsertClients(freshClients []AWGClient, clientPubKey, clientID, clientIP string, filterIP bool) []AWGClient {
	var updatedClients []AWGClient
	for _, c := range freshClients {
		if (clientPubKey != "" && c.ClientID == clientPubKey) || (clientID != "" && c.ClientID == clientID) {
			continue
		}
		if filterIP && clientIP != "" && c.UserData.ClientIP == clientIP {
			continue
		}
		updatedClients = append(updatedClients, c)
	}
	return updatedClients
}

func (m *AWGManager) rollbackServerConfigSurgically(ctx context.Context, client ssh.SSHClient, isUpsert, superseded bool, clientPubKey, clientIP string, addClientResult map[string]any) error {
	freshConf, err := m.getServerConfig(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to fetch fresh server config during rollback: %w", err)
	}

	var newConf string
	if isUpsert && !superseded {
		previousPeerSection, _ := addClientResult["previous_peer_section"].(string)
		existingPubKey, _ := addClientResult["existing_pub_key"].(string)
		if previousPeerSection != "" {
			var removePubKeys []string
			if clientPubKey != "" && clientPubKey != existingPubKey {
				removePubKeys = append(removePubKeys, clientPubKey)
			}
			var upsertErr error
			newConf, upsertErr = upsertPeerInConfig(freshConf, previousPeerSection, removePubKeys...)
			if upsertErr != nil {
				return fmt.Errorf("failed to restore peer section in config during rollback: %w", upsertErr)
			}
		} else {
			newConf = freshConf
		}
	} else {
		if clientPubKey != "" && strings.Contains(freshConf, clientPubKey) {
			newConf = removePeerFromConfig(freshConf, clientPubKey, "")
		} else {
			newConf = freshConf
		}
	}

	if newConf != "" && newConf != freshConf {
		if _, saveErr := m.saveServerConfigTracked(ctx, client, newConf, false); saveErr != nil {
			return fmt.Errorf("failed to save server config during rollback: %w", saveErr)
		}
	}
	return nil
}

func (m *AWGManager) rollbackIPLease(ctx context.Context, serverID int64, clientID, clientIP string, addClientResult map[string]any, superseded bool) {
	if superseded {
		return
	}
	rekeyed, _ := addClientResult["rekeyed"].(bool)
	previousOwner, _ := addClientResult["previous_owner"].(string)
	effectiveClientID, _ := addClientResult["effective_client_id"].(string)
	if effectiveClientID == "" {
		effectiveClientID = clientID
	}
	rekeyedIP, _ := addClientResult["rekeyed_ip"].(string)
	newlyAllocated, _ := addClientResult["newly_allocated"].(bool)

	if rekeyed && m.ipAllocator != nil && previousOwner != "" && rekeyedIP != "" {
		if relErr := m.ipAllocator.TransferAWGClientIPLease(ctx, serverID, previousOwner, effectiveClientID, rekeyedIP); relErr != nil {
			slog.Error("failed to revert AWG client IP lease to previous owner during upsert rollback",
				"server_id", serverID,
				"previous_owner", previousOwner,
				"client_id", effectiveClientID,
				"ip", rekeyedIP,
				"error", relErr,
			)
		}
	} else if newlyAllocated && m.ipAllocator != nil && clientIP != "" {
		if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, effectiveClientID, clientIP); relErr != nil {
			slog.Warn("failed to release newly allocated AWG client IP during upsert rollback",
				"server_id", serverID,
				"client_id", effectiveClientID,
				"ip", clientIP,
				"error", relErr,
			)
		}
	}
}

// RemoveClient removes a client from the server WireGuard configuration and clientsTable.
func (m *AWGManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return lockErr
	}
	defer unlockRemote()

	// 1. Find peer IP for the client being removed
	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return err
	}
	var peerIP string
	for _, c := range clients {
		if c.ClientID == clientID && c.UserData.ClientIP != "" {
			peerIP = c.UserData.ClientIP
			break
		}
	}

	// 2. Remove [Peer] section from config
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}

	sections := strings.Split(confText, "[")
	var newSections []string
	for _, sec := range sections {
		if strings.TrimSpace(sec) == "" {
			continue
		}
		if strings.Contains(sec, clientID) {
			if peerIP == "" {
				ipRegex := regexp.MustCompile(`AllowedIPs\s*=\s*(\d+\.\d+\.\d+\.\d+)`)
				if matches := ipRegex.FindStringSubmatch(sec); len(matches) > 1 {
					peerIP = matches[1]
				}
			}
			continue
		}
		newSections = append(newSections, sec)
	}

	newConfig := "[" + strings.Join(newSections, "[")
	if err := m.saveServerConfigPreservingParams(ctx, client, newConfig); err != nil {
		return err
	}

	// 3. Update clientsTable
	var updatedClients []AWGClient
	for _, c := range clients {
		if c.ClientID != clientID {
			updatedClients = append(updatedClients, c)
		}
	}
	if err := m.saveClientsTable(ctx, client, updatedClients); err != nil {
		return err
	}

	// 4. Release allocated IP
	if m.ipAllocator != nil {
		if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, clientID, peerIP); relErr != nil {
			slog.Warn("failed to release AWG client IP on client removal", "server_id", serverID, "client_id", clientID, "ip", peerIP, "error", relErr)
		}
	}

	return nil
}

// GetClientConfig reconstructs the client config file for an existing client ID.
func (m *AWGManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return "", err
	}

	var targetClient *AWGClient
	for _, c := range clients {
		if c.ClientID == clientID {
			targetClient = &c
			break
		}
	}
	if targetClient == nil {
		return "", fmt.Errorf("client %s not found in clients table", clientID)
	}

	ud := targetClient.UserData
	if ud.ClientPrivateKey == "" {
		return "", errors.New("client private key not stored; config cannot be reconstructed")
	}

	confText, containerName, err := m.getServerConfigWithContainer(ctx, client)
	if err != nil {
		return "", err
	}

	serverParams, _, _ := ParseServerConfig(confText)
	serverPubKey, err := m.getServerPublicKeyInContainer(ctx, client, server, containerName, confText)
	if err != nil || serverPubKey == "" {
		if err != nil {
			return "", fmt.Errorf("failed to get AmneziaWG server public key: %w", err)
		}
		return "", errors.New("AmneziaWG server public key is empty")
	}

	psk := ud.PSK
	if psk == "" {
		psk, _ = m.GetServerPSK(ctx, server)
	}

	parsedParams := AWGParamsFromMap(convertStringMapToAny(serverParams))
	if ud.AWGMimicry != "" {
		if mp, err := cps.GenerateMimicryPackets(ctx, ud.AWGMimicry, "", client); err == nil {
			parsedParams.I1 = mp["i1"]
			parsedParams.I2 = mp["i2"]
			parsedParams.I3 = mp["i3"]
			parsedParams.I4 = mp["i4"]
			parsedParams.I5 = mp["i5"]
		}
	}

	port := serverParams["port"]
	if port == "" {
		port = AWGDefaults["port"]
	}
	endpoint := fmt.Sprintf("%s:%s", server.Host, port)

	return RenderClientConfig(ud.ClientPrivateKey, ud.ClientIP, serverPubKey, psk, endpoint, AWGDefaults["dns1"], AWGDefaults["dns2"], parsedParams.MTU, parsedParams, &ud), nil
}

// ToggleClient enables or disables a client by adding or removing the [Peer] from the server config.
func (m *AWGManager) ToggleClient(ctx context.Context, server *models.Server, clientID string, enable bool) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return lockErr
	}
	defer unlockRemote()

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return err
	}

	var target *AWGClient
	for i := range clients {
		if clients[i].ClientID == clientID {
			target = &clients[i]
			clients[i].UserData.Enabled = enable
			break
		}
	}
	if target == nil {
		return fmt.Errorf("client %s not found", clientID)
	}

	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}

	var newConfig string
	if enable {
		psk := target.UserData.PSK
		peerSec := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientID, psk, target.UserData.ClientIP)
		newConfig = strings.TrimRight(confText, "\n") + "\n" + peerSec
	} else {
		sections := strings.Split(confText, "[")
		var newSections []string
		for _, sec := range sections {
			if strings.TrimSpace(sec) == "" || strings.Contains(sec, clientID) {
				continue
			}
			newSections = append(newSections, sec)
		}
		newConfig = "[" + strings.Join(newSections, "[")
	}

	if err := m.saveServerConfigPreservingParams(ctx, client, newConfig); err != nil {
		return err
	}
	return m.saveClientsTable(ctx, client, clients)
}

// findExistingContainer checks known container names for existence.
func (m *AWGManager) findExistingContainer(ctx context.Context, client ssh.SSHClient) (string, bool, error) {
	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		outAll, errOutAll, codeAll, errAll := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps -a --filter name=^%s$ --format '{{.Names}}'", ssh.EscapeShellArg(name)))
		if errAll != nil || codeAll != 0 {
			return "", false, fmt.Errorf("docker ps -a failed checking %s (code %d): %s, %w", name, codeAll, errOutAll, errAll)
		}
		for _, line := range strings.Split(strings.TrimSpace(outAll), "\n") {
			if strings.TrimSpace(line) == name {
				return name, true, nil
			}
		}
	}
	return "", false, nil
}

// enrichRunningServerStatus populates configuration and credential details for a running container.
func (m *AWGManager) enrichRunningServerStatus(ctx context.Context, server *models.Server, client ssh.SSHClient, cName string, status map[string]any) {
	if conf, err := m.getServerConfig(ctx, client, cName); err == nil {
		params, peers, _ := ParseServerConfig(conf)
		status["port"] = params["port"]
		status["awg_params"] = params
		status["clients_count"] = len(peers)
		// Protocol generation is derived from the parsed backend config:
		// a non-empty HeaderProtectionKey means the backend speaks AWG 3.1.
		if params["header_protection_key"] != "" {
			status["protocol_generation"] = "3.1"
		} else {
			status["protocol_generation"] = "2.0"
		}
	}
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	// Best-effort AWG version lookup; empty string on any failure.
	if out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s 'awg' --version", ssh.EscapeShellArg(cName))); err == nil && code == 0 {
		if line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]); line != "" {
			status["awg_version"] = line
		}
	}
	// If port is missing or 0, fallback extraction from docker port or docker inspect
	if p, ok := status["port"]; !ok || p == nil || fmt.Sprint(p) == "" || fmt.Sprint(p) == "0" {
		if port := m.extractContainerPort(ctx, client, cName); port > 0 {
			status["port"] = port
		}
	}
	if pubKey, err := m.GetServerPublicKey(ctx, server); err == nil && pubKey != "" {
		status["public_key"] = pubKey
	}
	if psk, err := m.GetServerPSK(ctx, server); err == nil && psk != "" {
		status["psk"] = psk
	}
}

// GetServerStatus returns whether the container is running and configuration details across all valid container names.
func (m *AWGManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	foundName, exists, err := m.findExistingContainer(ctx, client)
	if err != nil {
		return nil, err
	}

	var running bool
	if exists && foundName != "" && IsValidContainerName(foundName) {
		m.setCachedContainerForServer(server, foundName)
		m.setCachedContainerForClient(client, foundName)

		outRun, errOutRun, codeRun, errRun := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Status}}'", ssh.EscapeShellArg(foundName)))
		if errRun != nil || codeRun != 0 {
			return nil, fmt.Errorf("docker ps failed checking %s (code %d): %s, %w", foundName, codeRun, errOutRun, errRun)
		}
		running = strings.Contains(outRun, "Up")
	}

	// Legacy tc cleanup (PR #231 re-review Fix 2): containers installed
	// before the speed-limit removal (74b34d9) may still carry HTB
	// qdiscs/filters/ifb0 rules that outlive the deleted control plane.
	// Only attempt cleanup if the container exists and is running.
	// tcCleaned is set ONLY after a successful sweep: a failed attempt stays
	// unmarked so the next status poll retries.
	if server != nil && exists && running && IsValidContainerName(foundName) {
		m.mu.Lock()
		alreadyCleaned := m.tcCleaned[server.ID]
		m.mu.Unlock()
		if !alreadyCleaned {
			if err := m.CleanupLegacyTcRules(ctx, client, foundName); err != nil {
				slog.Warn("legacy tc cleanup failed; will retry on next status poll",
					"server_id", server.ID, "error", err)
			} else {
				m.mu.Lock()
				m.tcCleaned[server.ID] = true
				m.mu.Unlock()
			}
		}
	}

	status := map[string]any{
		"protocol":          "awg",
		"container_exists":  exists,
		"container_running": running,
	}

	if running {
		cName := foundName
		if cName == "" {
			cName = m.resolveContainerName(ctx, client)
		}
		if !IsValidContainerName(cName) {
			cName = m.containerName()
		}
		m.enrichRunningServerStatus(ctx, server, client, cName, status)
	}

	return status, nil
}

// extractContainerPort attempts to discover the host UDP listening port of the container
// via docker port and docker inspect.
func (m *AWGManager) extractContainerPort(ctx context.Context, client ssh.SSHClient, containerName string) int {
	if containerName == "" {
		containerName = m.resolveContainerName(ctx, client)
	}
	if !IsValidContainerName(containerName) {
		containerName = m.containerName()
	}
	if !IsValidContainerName(containerName) {
		return 0
	}
	out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker port %s 2>/dev/null", ssh.EscapeShellArg(containerName)))
	if err == nil && code == 0 && strings.TrimSpace(out) != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if idx := strings.LastIndex(line, ":"); idx != -1 {
				portStr := strings.TrimSpace(line[idx+1:])
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					return p
				}
			}
		}
	}

	inspectCmd := fmt.Sprintf("docker inspect --format '{{range $p, $conf := .HostConfig.PortBindings}}{{(index $conf 0).HostPort}} {{end}}' %s 2>/dev/null", ssh.EscapeShellArg(containerName))
	outInspect, _, codeInspect, errInspect := client.RunSudoCommand(ctx, inspectCmd)
	if errInspect == nil && codeInspect == 0 && strings.TrimSpace(outInspect) != "" {
		for _, part := range strings.Fields(outInspect) {
			if p, err := strconv.Atoi(part); err == nil && p > 0 {
				return p
			}
		}
	}
	return 0
}

// GetServerPSK returns the preshared key for AmneziaWG server.
func (m *AWGManager) GetServerPSK(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	names := m.candidateContainerNames(ctx, client)

	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null || docker exec -i %s cat '/etc/amnezia/amneziawg/wireguard_psk.key' 2>/dev/null", ssh.EscapeShellArg(name), ssh.EscapeShellArg(serverPSKArtifactPath), ssh.EscapeShellArg(name))
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out), nil
		}
	}
	return "", nil
}

func parseParamString(params map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := params[k]; ok && v != nil && fmt.Sprint(v) != "" {
			return fmt.Sprint(v), true
		}
	}
	return "", false
}

func parseBoolParam(val any) (bool, bool) {
	if val == nil {
		return false, false
	}
	switch v := val.(type) {
	case bool:
		return v, true
	case string:
		return strings.ToLower(v) == "true" || v == "1", true
	case int:
		return v != 0, true
	case int64:
		return v != 0, true
	case float64:
		return v != 0, true
	default:
		return false, false
	}
}

// EditClient modifies client metadata and enabling/disabling state.
func (m *AWGManager) EditClient(ctx context.Context, server *models.Server, clientID string, params map[string]any) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return lockErr
	}
	defer unlockRemote()

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return err
	}

	var target *AWGClient
	for i := range clients {
		if clients[i].ClientID == clientID {
			target = &clients[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("client %s not found in clients table", clientID)
	}

	if name, ok := parseParamString(params, "name", "clientName", "client_name"); ok {
		target.UserData.ClientName = name
	}
	if mimicry, ok := parseParamString(params, "awg_mimicry", "mimicry"); ok {
		target.UserData.AWGMimicry = mimicry
	}

	if newEnabled, ok := parseBoolParam(params["enabled"]); ok && newEnabled != target.UserData.Enabled {
		if err := m.updateServerConfigPeer(ctx, client, clientID, target.UserData.ClientIP, target.UserData.PSK, newEnabled); err != nil {
			return fmt.Errorf("failed to update server peer config: %w", err)
		}
		target.UserData.Enabled = newEnabled
	}

	return m.saveClientsTable(ctx, client, clients)
}

func (m *AWGManager) updateServerConfigPeer(ctx context.Context, client ssh.SSHClient, clientID, clientIP, psk string, enable bool) error {
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}
	var newConfig string
	if enable {
		peerSec := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientID, psk, clientIP)
		newConfig = strings.TrimRight(confText, "\n") + "\n" + peerSec
	} else {
		sections := strings.Split(confText, "[")
		var newSections []string
		for _, sec := range sections {
			if strings.TrimSpace(sec) == "" || strings.Contains(sec, clientID) {
				continue
			}
			newSections = append(newSections, sec)
		}
		newConfig = "[" + strings.Join(newSections, "[")
	}
	return m.saveServerConfigPreservingParams(ctx, client, newConfig)
}

// RotateMimicry rotates a client's mimicry profile strictly between verified DPI-passing UDP protocols (SIP <-> DNS),
// regenerates I1-I5 packet headers, and updates clientsTable.
func (m *AWGManager) RotateMimicry(ctx context.Context, server *models.Server, clientID string) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return "", lockErr
	}
	defer unlockRemote()

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return "", err
	}

	var target *AWGClient
	for i := range clients {
		if clients[i].ClientID == clientID {
			target = &clients[i]
			break
		}
	}
	if target == nil {
		return "", fmt.Errorf("client %s not found in clients table", clientID)
	}

	curr := strings.ToLower(strings.TrimSpace(target.UserData.AWGMimicry))
	if curr == "" {
		curr = "auto"
	}

	var nextProfile string
	switch curr {
	case "auto":
		nextProfile = "dns"
	case "sip":
		nextProfile = "dns"
	case "dns":
		nextProfile = "sip"
	case "quic", "tls":
		nextProfile = "sip"
	default:
		nextProfile = "dns"
	}

	// Regenerate I1-I5 signature packets
	if mp, err := cps.GenerateMimicryPackets(ctx, nextProfile, "", client); err == nil {
		target.UserData.I1 = mp["i1"]
		target.UserData.I2 = mp["i2"]
		target.UserData.I3 = mp["i3"]
		target.UserData.I4 = mp["i4"]
		target.UserData.I5 = mp["i5"]
	}

	target.UserData.AWGMimicry = nextProfile
	target.UserData.RotatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := m.saveClientsTable(ctx, client, clients); err != nil {
		return "", fmt.Errorf("failed to save clients table after mimicry rotation: %w", err)
	}

	return nextProfile, nil
}
