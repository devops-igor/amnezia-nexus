package awg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/cps"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/tc"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/ssh"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"golang.org/x/crypto/curve25519"
)

var (
	AWGContainerNames  = []string{"amnezia-awg", "amnezia-awg2", "amnezia-awg-legacy"}
	containerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
)

const defaultContainerCacheTTL = 5 * time.Minute

// IsValidContainerName validates a container name against strict regex:
// must start with an alphanumeric character, followed by alphanumeric, dot, underscore, or hyphen.
func IsValidContainerName(name string) bool {
	return containerNameRegex.MatchString(name)
}

type containerCacheEntry struct {
	name      string
	expiresAt time.Time
}

// SSHProvider abstracts obtaining an SSHClient for a server.
type SSHProvider interface {
	Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error)
}

// AWGManager implements manager.ProtocolManager for AmneziaWG.
//
//nolint:revive
type AWGManager struct {
	sshPool        SSHProvider
	mu             sync.Mutex
	cacheMu        sync.RWMutex
	containerCache map[string]containerCacheEntry
}

// NewAWGManager creates a new AWGManager instance.
func NewAWGManager(pool SSHProvider) *AWGManager {
	return &AWGManager{
		sshPool:        pool,
		containerCache: make(map[string]containerCacheEntry),
	}
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
	return "amnezia-awg"
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

func ensureDockerInstalled(ctx context.Context, client ssh.SSHClient) error {
	out, _, code, _ := client.RunCommand(ctx, "docker --version")
	if code == 0 && strings.Contains(strings.ToLower(out), "docker") {
		return nil
	}
	dockerScript := `
if which apt-get > /dev/null 2>&1; then pm=$(which apt-get); silent_inst="-yq install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif which dnf > /dev/null 2>&1; then pm=$(which dnf); silent_inst="-yq install"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif which yum > /dev/null 2>&1; then pm=$(which yum); silent_inst="-y -q install"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
else echo "Packet manager not found"; exit 1; fi;
if [ "$dist" = "debian" ]; then export DEBIAN_FRONTEND=noninteractive; fi;
if ! command -v docker > /dev/null 2>&1; then $pm $check_pkgs && $pm $silent_inst $docker_pkg && systemctl enable --now docker; fi;
systemctl start docker; docker --version
`
	if _, errOut, dCode, err := client.RunSudoScript(ctx, dockerScript); err != nil || dCode != 0 {
		return fmt.Errorf("failed to install Docker (code %d): %s, %w", dCode, errOut, err)
	}
	return nil
}

func prepareHostAndContainers(ctx context.Context, client ssh.SSHClient) error {
	prepScript := `
mkdir -p /opt/amnezia/amnezia-awg /opt/amnezia/awg
if ! docker network ls | grep -q amnezia-dns-net; then
  docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net || true
fi
`
	if _, _, _, err := client.RunSudoScript(ctx, prepScript); err != nil {
		return fmt.Errorf("failed to prepare host: %w", err)
	}

	for _, name := range AWGContainerNames {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s 2>/dev/null || true", name))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", name))
	}
	return nil
}

func buildAndRunAWGContainer(ctx context.Context, client ssh.SSHClient, port string) error {
	dockerfile := `FROM amneziavpn/amneziawg-go:latest
LABEL maintainer="AmneziaVPN"
RUN apk add --no-cache bash curl dumb-init iptables && apk --update upgrade --no-cache
RUN mkdir -p /opt/amnezia
RUN echo "#!/bin/bash" > /opt/amnezia/start.sh && echo "tail -f /dev/null" >> /opt/amnezia/start.sh && chmod a+x /opt/amnezia/start.sh
ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
`
	if err := client.UploadSudoFile(ctx, "/opt/amnezia/amnezia-awg/Dockerfile", []byte(dockerfile), 0644); err != nil {
		return fmt.Errorf("failed to upload Dockerfile: %w", err)
	}

	if _, errOut, bCode, err := client.RunSudoCommand(ctx, "docker build --no-cache -t amnezia-awg /opt/amnezia/amnezia-awg"); err != nil || bCode != 0 {
		return fmt.Errorf("failed to build amnezia-awg image (code %d): %s, %w", bCode, errOut, err)
	}

	runCmd := fmt.Sprintf(`docker run -d \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p %s:%s/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
--name amnezia-awg \
amnezia-awg`, port, port)

	if _, errOut, rCode, err := client.RunSudoCommand(ctx, runCmd); err != nil || rCode != 0 {
		return fmt.Errorf("failed to run container (code %d): %s, %w", rCode, errOut, err)
	}

	_, _, _, _ = client.RunSudoCommand(ctx, "docker network connect amnezia-dns-net amnezia-awg 2>/dev/null || true")
	return nil
}

func initializeServerKeysAndConfig(ctx context.Context, client ssh.SSHClient, port string, awgParams *AWGParams) error {
	serverPrivKey, serverPubKey, err := GenerateWGKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate server keypair: %w", err)
	}
	serverPSK, err := GeneratePSK()
	if err != nil {
		return fmt.Errorf("failed to generate server psk: %w", err)
	}

	keygenScript := fmt.Sprintf(`
mkdir -p /opt/amnezia/awg
echo "%s" > /opt/amnezia/awg/wireguard_server_private_key.key
echo "%s" > /opt/amnezia/awg/wireguard_server_public_key.key
echo "%s" > /opt/amnezia/awg/wireguard_psk.key
`, serverPrivKey, serverPubKey, serverPSK)
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i amnezia-awg bash -c '%s'", keygenScript))

	serverConfig := RenderServerConfig(serverPrivKey, AWGDefaults["subnet_ip"], AWGDefaults["subnet_cidr"], port, awgParams.MTU, awgParams, nil)
	if err := client.UploadSudoFile(ctx, "/tmp/_amnz_awg0.conf", []byte(serverConfig), 0600); err != nil {
		return err
	}
	_, _, _, _ = client.RunSudoCommand(ctx, "docker cp /tmp/_amnz_awg0.conf amnezia-awg:/opt/amnezia/awg/awg0.conf")
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -f /tmp/_amnz_awg0.conf")

	startScript := fmt.Sprintf(`#!/bin/bash
awg-quick down /opt/amnezia/awg/awg0.conf 2>/dev/null || true
if [ -f /opt/amnezia/awg/awg0.conf ]; then awg-quick up /opt/amnezia/awg/awg0.conf; fi
iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -o eth0 -s %s/%s -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s %s/%s -o eth0 -j MASQUERADE
tail -f /dev/null
`, AWGDefaults["subnet_ip"], AWGDefaults["subnet_cidr"], AWGDefaults["subnet_ip"], AWGDefaults["subnet_cidr"])

	if err := client.UploadSudoFile(ctx, "/tmp/_amnz_start.sh", []byte(startScript), 0755); err != nil {
		return err
	}
	_, _, _, _ = client.RunSudoCommand(ctx, "docker cp /tmp/_amnz_start.sh amnezia-awg:/opt/amnezia/start.sh")
	_, _, _, _ = client.RunSudoCommand(ctx, "docker exec amnezia-awg chmod +x /opt/amnezia/start.sh")
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -f /tmp/_amnz_start.sh")
	_, _, _, _ = client.RunSudoCommand(ctx, "docker restart amnezia-awg")

	firewallScript := `
sysctl -w net.ipv4.ip_forward=1
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
`
	_, _, _, _ = client.RunSudoScript(ctx, firewallScript)
	return nil
}

// Install deploys Docker (if missing), builds the AWG container, configures parameters, and starts the service.
func (m *AWGManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	port := AWGDefaults["port"]
	if p, ok := params["port"]; ok && fmt.Sprint(p) != "" {
		port = fmt.Sprint(p)
	}

	profile := "standard"
	if p, ok := params["awg_profile"]; ok && fmt.Sprint(p) != "" {
		profile = fmt.Sprint(p)
	}

	hpOn, _ := parseBoolParam(params["awg_header_protection"])
	awgParams, err := GenerateAWGParams(profile, hpOn)
	if err != nil {
		return fmt.Errorf("failed to generate AWG params: %w", err)
	}
	awgParams.Port = port

	if (profile == "standard" || profile == "pro") && params != nil {
		cpsProto := "quic"
		if cp, ok := params["awg_cps_protocol"]; ok && fmt.Sprint(cp) != "" {
			cpsProto = fmt.Sprint(cp)
		}
		if d, err := cps.SelectMimicryDomain(ctx, client, cpsProto); err == nil && d != "" {
			if cpsPackets, err := cps.GenerateCPSPackets(profile, d); err == nil {
				awgParams.I1 = cpsPackets["i1"]
				awgParams.I2 = cpsPackets["i2"]
				awgParams.I3 = cpsPackets["i3"]
				awgParams.I4 = cpsPackets["i4"]
				awgParams.I5 = cpsPackets["i5"]
			}
		}
	}

	if err := ensureDockerInstalled(ctx, client); err != nil {
		return err
	}
	if err := prepareHostAndContainers(ctx, client); err != nil {
		return err
	}
	if err := buildAndRunAWGContainer(ctx, client, port); err != nil {
		return err
	}
	return initializeServerKeysAndConfig(ctx, client, port, awgParams)
}

// Uninstall stops and removes all AWG containers and clean up directories.
func (m *AWGManager) Uninstall(ctx context.Context, server *models.Server) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.invalidateContainerCache(server)

	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s 2>/dev/null || true", name))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", name))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rmi %s 2>/dev/null || true", name))
	}
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -rf /opt/amnezia/amnezia-awg /opt/amnezia/awg")
	return nil
}

func (m *AWGManager) resolveContainerName(ctx context.Context, client ssh.SSHClient) string {
	if cached, ok := m.getCachedContainerForClient(client); ok {
		return cached
	}

	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Names}}'", name))
		if err == nil && code == 0 {
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == name {
					m.setCachedContainerForClient(client, name)
					return name
				}
			}
		}
	}
	// Fallback to any running container with name starting with amnezia-awg
	out, _, code, err := client.RunSudoCommand(ctx, "docker ps --filter name=amnezia-awg --format '{{.Names}}'")
	if err == nil && code == 0 {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "amnezia-awg") && IsValidContainerName(trimmed) {
				m.setCachedContainerForClient(client, trimmed)
				return trimmed
			}
		}
	}
	safeDefault := m.containerName()
	if !IsValidContainerName(safeDefault) {
		safeDefault = "amnezia-awg"
	}
	return safeDefault
}

func (m *AWGManager) getServerConfig(ctx context.Context, client ssh.SSHClient, containerNames ...string) (string, error) {
	names := containerNames
	if len(names) == 0 || (len(names) == 1 && names[0] == "") {
		resolved := m.resolveContainerName(ctx, client)
		if !IsValidContainerName(resolved) {
			resolved = m.containerName()
		}
		names = []string{resolved}
		for _, name := range AWGContainerNames {
			if name != resolved && IsValidContainerName(name) {
				names = append(names, name)
			}
		}
	}
	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null || docker exec -i %s cat /etc/amnezia/amneziawg/awg0.conf 2>/dev/null", name, m.configPath(), name)
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return out, nil
		}
	}
	return "", fmt.Errorf("failed to get server config from containers: %v", names)
}

func (m *AWGManager) saveServerConfig(ctx context.Context, client ssh.SSHClient, content string) error {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return errors.New("invalid container name")
	}
	tmpPath := "/tmp/_amnz_edit_config.conf"
	if err := client.UploadSudoFile(ctx, tmpPath, []byte(content), 0600); err != nil {
		return err
	}
	defer func() {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("rm -f %s", tmpPath))
	}()

	cpCmd := fmt.Sprintf("docker cp %s %s:%s", tmpPath, cName, m.configPath())
	if _, errOut, code, err := client.RunSudoCommand(ctx, cpCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to copy config into container (code %d): %s, %w", code, errOut, err)
	}

	syncCmd := fmt.Sprintf("docker exec -i %s bash -c '%s syncconf %s <(%s-quick strip %s)'",
		cName, m.wgBinary(), m.interfaceName(), m.wgBinary(), m.configPath())
	_, _, _, _ = client.RunSudoCommand(ctx, syncCmd)
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
	out, _, code, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null", cName, m.clientsTablePath()))
	if code != 0 || strings.TrimSpace(out) == "" {
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

	tmpPath := "/tmp/_amnz_clients.json"
	if err := client.UploadSudoFile(ctx, tmpPath, []byte(jsonData), 0600); err != nil {
		return err
	}
	defer func() {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("rm -f %s", tmpPath))
	}()

	cpCmd := fmt.Sprintf("docker cp %s %s:%s", tmpPath, cName, m.clientsTablePath())
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
	showOut, _, _, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s %s show all 2>/dev/null", m.containerName(), m.wgBinary()))
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
			"speed_limit_down":  ud.SpeedLimitDown,
			"speed_limit_up":    ud.SpeedLimitUp,
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

type wgShowPeerStat struct {
	LatestHandshake   string
	DataReceived      string
	DataSent          string
	DataReceivedBytes int64
	DataSentBytes     int64
	AllowedIPs        string
}

func parseWGShow(out string) map[string]wgShowPeerStat {
	stats := make(map[string]wgShowPeerStat)
	var currentPeer string
	var currentStat wgShowPeerStat

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "peer:") {
			if currentPeer != "" {
				stats[currentPeer] = currentStat
			}
			currentPeer = strings.TrimSpace(strings.TrimPrefix(trimmed, "peer:"))
			currentStat = wgShowPeerStat{}
		} else if currentPeer != "" && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			switch k {
			case "latest handshake":
				currentStat.LatestHandshake = v
			case "transfer":
				tfParts := strings.Split(v, ",")
				if len(tfParts) == 2 {
					rx := strings.TrimSpace(strings.TrimSuffix(tfParts[0], "received"))
					tx := strings.TrimSpace(strings.TrimSuffix(tfParts[1], "sent"))
					currentStat.DataReceived = rx
					currentStat.DataSent = tx
					currentStat.DataReceivedBytes = parseSizeHuman(rx)
					currentStat.DataSentBytes = parseSizeHuman(tx)
				}
			case "allowed ips":
				currentStat.AllowedIPs = v
			}
		}
	}
	if currentPeer != "" {
		stats[currentPeer] = currentStat
	}
	return stats
}

func parseSizeHuman(s string) int64 {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0
	}
	val, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	mult := int64(1)
	switch strings.ToLower(parts[1]) {
	case "kib", "kb":
		mult = 1024
	case "mib", "mb":
		mult = 1024 * 1024
	case "gib", "gb":
		mult = 1024 * 1024 * 1024
	case "tib", "tb":
		mult = 1024 * 1024 * 1024 * 1024
	}
	return int64(val * float64(mult))
}

func resolveClientName(clientParams map[string]any) string {
	if n, ok := clientParams["name"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	if n, ok := clientParams["clientName"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	return "client"
}

func parseSpeedLimits(clientParams map[string]any) (*int, *int) {
	var speedDown, speedUp *int
	if v, ok := clientParams["awg_speed_limit_down"]; ok && v != nil {
		if val, err := strconv.Atoi(fmt.Sprint(v)); err == nil && val > 0 {
			speedDown = &val
		}
	}
	if v, ok := clientParams["awg_speed_limit_up"]; ok && v != nil {
		if val, err := strconv.Atoi(fmt.Sprint(v)); err == nil && val > 0 {
			speedUp = &val
		}
	}
	return speedDown, speedUp
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

// upsertPeerInConfig replaces the [Peer] section whose PublicKey matches
// peerSection's PublicKey, or appends the section when no such peer exists.
// [Peer] blocks whose PublicKey is listed in removePubKeys are dropped (stale
// identity that was re-keyed under the same client name). Duplicate blocks for
// the same PublicKey are collapsed. Non-peer content is preserved as-is.
func upsertPeerInConfig(confText, peerSection string, removePubKeys ...string) (string, error) {
	peerLines := strings.Split(strings.TrimSpace(peerSection), "\n")
	newPub := ""
	for _, line := range peerLines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PublicKey = ") {
			newPub = strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = "))
			break
		}
	}
	if newPub == "" {
		return "", errors.New("peer section is missing a PublicKey line")
	}

	lines := strings.Split(strings.TrimRight(confText, "\n"), "\n")
	var out []string
	replaced := false
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "[Peer]" {
			out = append(out, lines[i])
			continue
		}
		// Collect the whole [Peer] block (up to the next section header).
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
			j++
		}
		block := lines[i:j]
		blockPub := ""
		for _, bl := range block {
			trimmed := strings.TrimSpace(bl)
			if strings.HasPrefix(trimmed, "PublicKey = ") {
				blockPub = strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = "))
				break
			}
		}
		stale := false
		for _, rk := range removePubKeys {
			if rk != "" && rk != newPub && rk == blockPub {
				stale = true
				break
			}
		}
		switch {
		case stale:
			// Drop the stale block entirely.
		case blockPub == newPub:
			if !replaced {
				out = append(out, peerLines...)
				replaced = true
			}
			// Duplicate legacy block for the same key: drop it.
		default:
			out = append(out, block...)
		}
		i = j - 1
	}
	if !replaced {
		// Blank separator line before the appended peer, mirroring the
		// formatting awg-quick conf files get from the portal.
		withSep := append([]string{""}, peerLines...)
		out = append(out, withSep...)
	}
	return strings.Join(out, "\n") + "\n", nil
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

// peerSectionFor renders the [Peer] section to append to the server config.
// Probe peers carry no PresharedKey line: the prober probes with psk="", so
// both sides must derive IKpsk2 keys with a zero PSK.
func peerSectionFor(isProbePeer bool, clientPubKey, psk, clientIP, allowedIPs string) string {
	if isProbePeer {
		if allowedIPs == "" {
			allowedIPs = clientIP + "/32"
		}
		return fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", clientPubKey, allowedIPs)
	}
	return fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientPubKey, psk, clientIP)
}

// upsertClientEntry updates the clientsTable entry at existingIdx in place
// (keeping IP and identity fields), or appends a new entry when idx < 0.
func upsertClientEntry(clients []AWGClient, existingIdx int, clientPubKey, clientName, clientPrivKey, psk, clientIP, mimicry string, speedDown, speedUp *int, contentPadding bool) []AWGClient {
	if existingIdx >= 0 {
		clients[existingIdx].ClientID = clientPubKey
		clients[existingIdx].UserData.ClientName = clientName
		clients[existingIdx].UserData.ClientPrivateKey = clientPrivKey
		clients[existingIdx].UserData.PSK = psk
		clients[existingIdx].UserData.Enabled = true

		if clients[existingIdx].UserData.RekeyAfterTime == nil {
			rat, rt, rej, kt, mha, pk := GenerateClientTimingParams()
			clients[existingIdx].UserData.RekeyAfterTime = rat
			clients[existingIdx].UserData.RekeyTimeout = rt
			clients[existingIdx].UserData.RejectAfterTime = rej
			clients[existingIdx].UserData.KeepaliveTimeout = kt
			clients[existingIdx].UserData.MaxHandshakeAttempts = mha
			clients[existingIdx].UserData.PersistentKeepalive = pk
		}

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
			SpeedLimitDown:         speedDown,
			SpeedLimitUp:           speedUp,
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

// applyClientSpeedLimit applies TC speed limits when any limit is set.
func applyClientSpeedLimit(ctx context.Context, client ssh.SSHClient, containerName, interfaceName, clientIP string, speedDown, speedUp *int) {
	if speedDown == nil && speedUp == nil {
		return
	}
	dVal, uVal := 0, 0
	if speedDown != nil {
		dVal = *speedDown
	}
	if speedUp != nil {
		uVal = *speedUp
	}
	_ = tc.ApplySpeedLimit(ctx, client, containerName, interfaceName, clientIP, dVal, uVal)
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
func (m *AWGManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	clientName := resolveClientName(clientParams)

	// Name-based probe detection (R2): a legacy "Health Probe" entry may exist
	// with a server PSK from the old name-only registration path. Treat the
	// name as probe identity so the upsert drops the PresharedKey line and
	// forces psk="" — keeping the peer on the PSK-less identity both probers use.
	clientNameIsProbe := strings.EqualFold(strings.TrimSpace(clientName), "Health Probe")

	clientPubKey := probePeerPubKey(clientParams)
	isProbePeer := clientPubKey != "" || clientNameIsProbe
	clientPrivKey := ""
	if clientPubKey == "" {
		// No caller-supplied key: generate a keypair. For probe-named clients
		// this keeps the PSK-less probe policy while still yielding a valid
		// peer identity (the name-only legacy fallback has no caller key, and
		// a keyless [Peer] would be rejected by upsertPeerInConfig).
		clientPrivKey, clientPubKey, err = GenerateWGKeypair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate client keypair: %w", err)
		}
	}

	// Read server config
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return nil, err
	}

	usedIPs := GetUsedIPsFromConfig(confText)
	subnetAddr := AWGDefaults["subnet_address"]
	subnetCIDR, _ := strconv.Atoi(AWGDefaults["subnet_cidr"])
	gatewayIP := AWGDefaults["subnet_ip"]

	serverParams, _, _ := ParseServerConfig(confText)
	serverPubKeyOut, _, _, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s cat /opt/amnezia/awg/wireguard_server_public_key.key", m.containerName()))
	serverPubKey := strings.TrimSpace(serverPubKeyOut)

	// Idempotency: reuse the existing entry (and its IP) when this identity is
	// already registered instead of appending a duplicate peer.
	clients, _ := m.getClientsTable(ctx, client)
	existingIdx, existingPubKey := findExistingClient(clients, clientPubKey, clientName)

	var psk, clientIP string
	if existingIdx >= 0 {
		clientIP = clients[existingIdx].UserData.ClientIP
	}
	if clientIP == "" {
		clientIP, err = GetNextIP(usedIPs, subnetAddr, subnetCIDR, gatewayIP)
		if err != nil {
			return nil, err
		}
	}
	// Normal clients get the server's PresharedKey (read fresh each call, as
	// before). Probe peers force psk="": the prober derives IKpsk2 keys with an
	// empty PSK, so the peer must be registered without one (R2).
	if !isProbePeer {
		pskOut, _, _, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s cat /opt/amnezia/awg/wireguard_psk.key", m.containerName()))
		psk = strings.TrimSpace(pskOut)
	}

	allowedIPs := ""
	if aip, ok := clientParams["allowed_ips"]; ok && aip != nil {
		allowedIPs = fmt.Sprint(aip)
	}
	peerSection := peerSectionFor(isProbePeer, clientPubKey, psk, clientIP, allowedIPs)
	var removePubKeys []string
	if existingPubKey != "" && existingPubKey != clientPubKey {
		removePubKeys = []string{existingPubKey}
	}
	newConfig, err := upsertPeerInConfig(confText, peerSection, removePubKeys...)
	if err != nil {
		return nil, err
	}
	if err := m.saveServerConfig(ctx, client, newConfig); err != nil {
		return nil, err
	}

	// Parse speed limits if provided
	speedDown, speedUp := parseSpeedLimits(clientParams)

	mimicry := "auto"
	if v, ok := clientParams["awg_mimicry"]; ok && fmt.Sprint(v) != "" {
		mimicry = fmt.Sprint(v)
	}

	cpOn, _ := parseBoolParam(clientParams["awg_content_padding"])

	// Save to clientsTable (update in place when the identity already exists)
	clients = upsertClientEntry(clients, existingIdx, clientPubKey, clientName, clientPrivKey, psk, clientIP, mimicry, speedDown, speedUp, cpOn)
	_ = m.saveClientsTable(ctx, client, clients)

	if isProbePeer {
		// Probe peers need no client config, connection kit, or TC limits:
		// nothing consumes a private key that does not exist.
		return map[string]any{
			"client_id":   clientPubKey,
			"client_name": clientName,
			"client_ip":   clientIP,
		}, nil
	}

	// Apply speed limit via TC
	applyClientSpeedLimit(ctx, client, m.containerName(), m.interfaceName(), clientIP, speedDown, speedUp)

	// Render client config
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
	connectionKit, _ := cps.GenerateConnectionKit(ctx, clientConfig, "", client)

	return map[string]any{
		"client_id":      clientPubKey,
		"client_name":    clientName,
		"client_ip":      clientIP,
		"config":         clientConfig,
		"connection_kit": connectionKit,
		"awg_mimicry":    mimicry,
	}, nil
}

func convertStringMapToAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// RemoveClient removes a client from the server WireGuard configuration and clientsTable.
func (m *AWGManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Remove TC speed limit for peer IP
	clients, _ := m.getClientsTable(ctx, client)
	for _, c := range clients {
		if c.ClientID == clientID && c.UserData.ClientIP != "" {
			_ = tc.RemoveSpeedLimit(ctx, client, m.containerName(), m.interfaceName(), c.UserData.ClientIP)
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
			continue
		}
		newSections = append(newSections, sec)
	}

	newConfig := "[" + strings.Join(newSections, "[")
	if err := m.saveServerConfig(ctx, client, newConfig); err != nil {
		return err
	}

	// 3. Update clientsTable
	var updatedClients []AWGClient
	for _, c := range clients {
		if c.ClientID != clientID {
			updatedClients = append(updatedClients, c)
		}
	}
	return m.saveClientsTable(ctx, client, updatedClients)
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

	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return "", err
	}

	serverParams, _, _ := ParseServerConfig(confText)
	serverPubKeyOut, _, _, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s cat /opt/amnezia/awg/wireguard_server_public_key.key", m.containerName()))
	serverPubKey := strings.TrimSpace(serverPubKeyOut)

	psk := ud.PSK
	if psk == "" {
		pskOut, _, _, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s cat /opt/amnezia/awg/wireguard_psk.key", m.containerName()))
		psk = strings.TrimSpace(pskOut)
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

	m.mu.Lock()
	defer m.mu.Unlock()

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

	if err := m.saveServerConfig(ctx, client, newConfig); err != nil {
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
		outAll, errOutAll, codeAll, errAll := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps -a --filter name=^%s$ --format '{{.Names}}'", name))
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

		outRun, errOutRun, codeRun, errRun := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Status}}'", foundName))
		if errRun != nil || codeRun != 0 {
			return nil, fmt.Errorf("docker ps failed checking %s (code %d): %s, %w", foundName, codeRun, errOutRun, errRun)
		}
		running = strings.Contains(outRun, "Up")
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
	out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker port %s 2>/dev/null", containerName))
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

	inspectCmd := fmt.Sprintf("docker inspect --format '{{range $p, $conf := .HostConfig.PortBindings}}{{(index $conf 0).HostPort}} {{end}}' %s 2>/dev/null", containerName)
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

// GetServerPublicKey returns the public key for AmneziaWG server.
func (m *AWGManager) GetServerPublicKey(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	resolved := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(resolved) {
		resolved = m.containerName()
	}
	names := []string{resolved}
	for _, name := range AWGContainerNames {
		if name != resolved && IsValidContainerName(name) {
			names = append(names, name)
		}
	}

	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat /opt/amnezia/awg/wireguard_server_public_key.key 2>/dev/null || docker exec -i %s %s show awg0 public-key 2>/dev/null || docker exec -i %s wg show awg0 public-key 2>/dev/null", name, name, m.wgBinary(), name)
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out), nil
		}
	}

	// Also check if public key can be derived from PrivateKey in awg0.conf
	if conf, err := m.getServerConfig(ctx, client, names...); err == nil && conf != "" {
		for _, line := range strings.Split(conf, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(trimmed), "privatekey") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					privKeyBase64 := strings.TrimSpace(parts[1])
					if privBytes, err := base64.StdEncoding.DecodeString(privKeyBase64); err == nil && len(privBytes) == 32 {
						if pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint); err == nil {
							return base64.StdEncoding.EncodeToString(pubBytes), nil
						}
					}
				}
			}
		}
	}

	return "", errors.New("failed to get AmneziaWG server public key")
}

// GetServerPSK returns the preshared key for AmneziaWG server.
func (m *AWGManager) GetServerPSK(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	resolved := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(resolved) {
		resolved = m.containerName()
	}
	names := []string{resolved}
	for _, name := range AWGContainerNames {
		if name != resolved && IsValidContainerName(name) {
			names = append(names, name)
		}
	}

	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat /opt/amnezia/awg/wireguard_psk.key 2>/dev/null || docker exec -i %s cat /etc/amnezia/amneziawg/wireguard_psk.key 2>/dev/null", name, name)
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

func parseSpeedLimit(params map[string]any, keys ...string) (*int, bool) {
	for _, k := range keys {
		if v, ok := params[k]; ok {
			if v == nil {
				return nil, true
			}
			if val, err := strconv.Atoi(fmt.Sprint(v)); err == nil && val > 0 {
				return &val, true
			}
			return nil, true
		}
	}
	return nil, false
}

// EditClient modifies client metadata, enabling/disabling, and bandwidth limits with TC sync.
func (m *AWGManager) EditClient(ctx context.Context, server *models.Server, clientID string, params map[string]any) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

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
		target.UserData.Enabled = newEnabled
		_ = m.updateServerConfigPeer(ctx, client, clientID, target.UserData.ClientIP, target.UserData.PSK, newEnabled)
	}

	down, downOk := parseSpeedLimit(params, "speed_limit_down", "awg_speed_limit_down", "speedDown")
	up, upOk := parseSpeedLimit(params, "speed_limit_up", "awg_speed_limit_up", "speedUp")
	if downOk || upOk {
		if downOk {
			target.UserData.SpeedLimitDown = down
		}
		if upOk {
			target.UserData.SpeedLimitUp = up
		}
		m.syncClientTC(ctx, client, target.UserData.ClientIP, target.UserData.SpeedLimitDown, target.UserData.SpeedLimitUp)
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
	return m.saveServerConfig(ctx, client, newConfig)
}

func (m *AWGManager) syncClientTC(ctx context.Context, client ssh.SSHClient, clientIP string, curDown, curUp *int) {
	if (curDown != nil && *curDown > 0) || (curUp != nil && *curUp > 0) {
		dVal, uVal := 0, 0
		if curDown != nil {
			dVal = *curDown
		}
		if curUp != nil {
			uVal = *curUp
		}
		_ = tc.ApplySpeedLimit(ctx, client, m.containerName(), m.interfaceName(), clientIP, dVal, uVal)
	} else {
		_ = tc.RemoveSpeedLimit(ctx, client, m.containerName(), m.interfaceName(), clientIP)
	}
}

// RotateMimicry rotates a client's mimicry profile through the sequence:
// auto -> tls -> quic -> dns -> sip -> tls, regenerates I1-I5 packet headers, and updates clientsTable.
func (m *AWGManager) RotateMimicry(ctx context.Context, server *models.Server, clientID string) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

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
		nextProfile = "tls"
	case "tls":
		nextProfile = "quic"
	case "quic":
		nextProfile = "dns"
	case "dns":
		nextProfile = "sip"
	case "sip":
		nextProfile = "tls"
	default:
		nextProfile = "tls"
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
